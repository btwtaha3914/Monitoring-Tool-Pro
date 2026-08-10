"""
Monitor Suite -- unified entry point
======================================
Combines three previously-standalone tools into one Flask app behind a
single sign-in gate:

  * Web Monitor      -- /web-monitor      (domain & subdomain uptime/SSL checks)
  * Signal Monitor    -- /signal-monitor    (Wi-Fi signal + local network devices)
  * Server Monitor    -- /server-monitor    (public/private server IP intelligence)

Run:
    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000
"""

import os
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash

import auth
from modules.web_monitor import web_monitor_bp
from modules.signal_monitor import signal_monitor_bp
from modules.server_monitor import server_monitor_bp

app = Flask(__name__)
app.secret_key = os.environ.get("MONITOR_SUITE_SECRET_KEY", "dev-secret-key-change-me")

app.register_blueprint(web_monitor_bp)
app.register_blueprint(signal_monitor_bp)
app.register_blueprint(server_monitor_bp)


# ----------------------------------------------------------------------
# Auth helpers
# ----------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_helpers():
    # Makes `session` usable inside templates that weren't rendered with
    # it explicitly (e.g. the shared navbar partial).
    return {"session": session}


# ----------------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "guest":
            session.clear()
            session["logged_in"] = True
            session["guest"] = True
            session["user"] = "Guest"
            return redirect(url_for("dashboard"))

        if action == "signup":
            username = request.form.get("username", "")
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            user, err = auth.create_user(username, email, password)
            if err:
                flash(err, "error")
                return render_template("login.html", mode="signup")
            session.clear()
            session["logged_in"] = True
            session["guest"] = False
            session["user"] = user["username"]
            session["email"] = user["email"]
            flash("Account created — welcome!", "success")
            return redirect(url_for("dashboard"))

        if action == "signin":
            email = request.form.get("email", "")
            password = request.form.get("password", "")
            user, err = auth.verify_user(email, password)
            if err:
                flash(err, "error")
                return render_template("login.html", mode="signin")
            session.clear()
            session["logged_in"] = True
            session["guest"] = False
            session["user"] = user["username"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

    return render_template("login.html", mode="signin")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


# ----------------------------------------------------------------------
# Gate every module page/API behind login (guest included) except the
# login page itself and static assets.
# ----------------------------------------------------------------------

_OPEN_ENDPOINTS = {"login", "static"}


@app.before_request
def require_login():
    if request.endpoint in _OPEN_ENDPOINTS or request.endpoint is None:
        return None
    if not session.get("logged_in"):
        return redirect(url_for("login", next=request.path))
    return None


if __name__ == "__main__":
    # Cloud hosts (Render, Railway, Fly.io, etc.) inject the port to bind
    # via the PORT env var and expect 0.0.0.0. Debug mode is auto-disabled
    # outside local dev.
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)