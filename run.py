"""Development entry point:  python run.py"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Port 8000 so Docker can map host 80 -> 8000 without root inside the container.
    app.run(host="0.0.0.0", port=8000, debug=False)
