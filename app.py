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
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash

# Central logging must be configured FIRST, before any module below
# creates its own logger. This ensures every module's logger uses
# our formatting and rotation instead of Python's defaults.
from shared.logging_setup import setup_logging
setup_logging()

import auth
from modules.web_monitor import web_monitor_bp
from modules.signal_monitor import signal_monitor_bp
from modules.server_monitor import server_monitor_bp

app = Flask(__name__)

# Initialize database and migrate legacy users.json if present.
# Safe to call every startup — both operations are idempotent.
auth.ensure_ready()
app.secret_key = os.environ.get("MONITOR_SUITE_SECRET_KEY", "dev-secret-key-change-me")

# ----------------------------------------------------------------------
# Session hardening
# ----------------------------------------------------------------------
# Without an explicit lifetime/SameSite policy, Flask's session cookie
# can behave inconsistently across browsers -- most commonly showing up
# as a guest (or signed-in) session that silently doesn't "stick": the
# user gets bounced back to the login screen (looking like a Sign In
# button appeared) on the very next page. Being explicit here fixes that:
#   - PERMANENT_SESSION_LIFETIME + session.permanent=True (set on login)
#     means the cookie has a real, predictable expiry instead of relying
#     on ambiguous "session cookie" browser defaults.
#   - SAMESITE="Lax" is the correct choice for a same-site app navigated
#     via normal links/redirects (works over plain HTTP too, which
#     matters since this app is commonly reached via a local IP like
#     http://192.168.x.x:5000 rather than HTTPS).
#   - SESSION_COOKIE_SECURE is left off (False) on purpose: turning it on
#     would silently break login entirely over plain HTTP (LAN/localhost
#     use), which is this app's normal deployment mode. Turn it on only
#     if you put this behind HTTPS.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

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
            # Guests share a single is_guest=1 user record in the DB.
            # Ensures every server row has a valid user_id foreign key.
            guest_user = auth.get_or_create_guest_user()
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["guest"] = True
            session["user"] = "Guest"
            session["user_id"] = guest_user["id"]
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
            session.permanent = True
            session["logged_in"] = True
            session["guest"] = False
            session["user"] = user["username"]
            session["email"] = user["email"]
            session["user_id"] = user["id"]
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
            session.permanent = True
            session["logged_in"] = True
            session["guest"] = False
            session["user"] = user["username"]
            session["email"] = user["email"]
            session["user_id"] = user["id"]
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