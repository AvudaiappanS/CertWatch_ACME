from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from ..models import User
auth_bp = Blueprint("auth", __name__)
@auth_bp.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u=User.query.filter_by(username=request.form["username"]).first()
        if u and u.check_password(request.form["password"]):
            session.update(user_id=u.id, username=u.username, role=u.role)
            return redirect(url_for("dashboard.index"))
        flash("Invalid username or password")
    return render_template("login.html")
@auth_bp.route("/logout")
def logout():
    session.clear(); return redirect(url_for("auth.login"))
