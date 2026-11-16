"""Authentication: login, logout, password change and admin user management.

Passwords are stored as salted hashes (Werkzeug PBKDF2). Sessions are signed
Flask cookies; login attempts are rate-limited per IP.
"""
from functools import wraps

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)

from ..audit import audit
from ..extensions import db
from ..models import User
from ..security import (clear_failed_logins, login_rate_limited,
                        record_failed_login)

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                audit("access_denied", request.path, "DENIED",
                      f"Role '{session.get('role')}' tried to access an administrator page")
                flash("Administrator access required.", "error")
                return redirect(url_for("dashboard.dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if login_rate_limited(ip):
            audit("login", request.form.get("username", ""), "DENIED",
                  "Rate limited after repeated failures", username="anonymous", role="anonymous")
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            clear_failed_logins(ip)
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session.permanent = True
            audit("login", username, "SUCCESS", "User logged in")
            return redirect(url_for("dashboard.dashboard"))
        record_failed_login(ip)
        audit("login", username, "FAILED", "Invalid username or password",
              username="anonymous", role="anonymous")
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    audit("logout", session.get("username", ""), "SUCCESS", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        user = db.session.get(User, session["user_id"])
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        if not user.check_password(current):
            audit("password_change", user.username, "FAILED", "Wrong current password")
            flash("Current password is incorrect.", "error")
        elif len(new) < 10:
            audit("password_change", user.username, "FAILED", "New password too short")
            flash("New password must be at least 10 characters.", "error")
        else:
            user.password_hash = __import__("werkzeug.security", fromlist=["generate_password_hash"]).generate_password_hash(new)
            db.session.commit()
            audit("password_change", user.username, "SUCCESS", "Password changed")
            flash("Password updated.", "success")
            return redirect(url_for("dashboard.dashboard"))
    return render_template("change_password.html")


@auth_bp.route("/users", methods=["GET", "POST"])
@role_required("Administrator")
def manage_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "Analyst")
        if role not in ("Administrator", "Analyst"):
            role = "Analyst"
        if not username or len(password) < 10:
            flash("Username is required and the password must be at least 10 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        else:
            User.create(username=username, password=password, role=role)
            audit("user_created", username, "SUCCESS", f"Account created with role {role}")
            flash(f"User '{username}' created.", "success")
        return redirect(url_for("auth.manage_users"))
    users = User.query.order_by(User.username).all()
    return render_template("users.html", users=users)
