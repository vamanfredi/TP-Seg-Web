"""The lab mailbox runs on its own origin and uses separate credentials."""
import hmac
import os
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Flask, abort, current_app, redirect, render_template, request, session, url_for

from . import security_headers
from .auth import reset_link
from .config import configure
from .db import close_databases, core
from .lab import mailbox_messages

RESET_DETAILS = re.compile(r"^Token: ([\w-]+)\nCuenta: ([\w-]+)$", re.MULTILINE)


def mailbox_key():
    with core() as db:
        db.execute("CREATE TABLE IF NOT EXISTS mailbox_key (id INTEGER PRIMARY KEY CHECK (id = 1), secret BLOB NOT NULL)")
        key = db.execute("SELECT secret FROM mailbox_key WHERE id = 1").fetchone()
        if key is None:
            db.execute("INSERT OR IGNORE INTO mailbox_key VALUES (1, ?)", (secrets.token_bytes(32),))
            key = db.execute("SELECT secret FROM mailbox_key WHERE id = 1").fetchone()
    return key["secret"]


def mailbox_password(key, user):
    configured = current_app.config["LAB_DEFAULT_MAILBOX_PASSWORD"]
    if configured and user and user["username"] == "cliente.a" and user["role"] == "client":
        return configured
    user_id = user["id"] if user else ""
    return hmac.new(key, user_id.encode(), "sha256").hexdigest()[:32]


def create_mailbox_app(config=None):
    app = Flask(__name__)
    configure(app, config)
    app.config.update(
        SECRET_KEY=secrets.token_bytes(32),
        SESSION_COOKIE_NAME="mailbox_session",
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=app.config["SESSION_TTL_SECONDS"],
        TRUSTED_HOSTS=["localhost", "127.0.0.1", urlsplit(app.config["MAILBOX_URL"]).hostname],
    )
    app.teardown_appcontext(close_databases)
    app.after_request(security_headers)

    def show_mailbox(username=None, messages=(), error=None):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return render_template("mailbox.html", username=username, messages=messages,
                               csrf_token=session["csrf_token"], error=error)

    def check_csrf():
        supplied = request.form.get("csrf_token", "").encode()
        expected = session.get("csrf_token", "").encode()
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400)

    @app.get("/")
    def inbox():
        user_id = session.get("user_id")
        if user_id is None:
            return show_mailbox()
        user = core().execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            session.clear()
            return show_mailbox()
        messages = []
        for message in mailbox_messages(user_id):
            details = RESET_DETAILS.search(message["body"])
            messages.append({
                "body": message["body"],
                "created_at": datetime.fromtimestamp(message["created_at"], timezone.utc).strftime("%d/%m/%Y · %H:%M UTC"),
                "reset_url": reset_link(*details.groups()) if details else None,
            })
        return show_mailbox(user["username"], messages)

    @app.post("/login")
    def login():
        check_csrf()
        username = request.form.get("username", "")
        supplied = request.form.get("password", "")
        user = core().execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
        expected = mailbox_password(mailbox_key(), user)
        if not hmac.compare_digest(supplied.encode(), expected.encode()) or user is None:
            return show_mailbox(error="Usuario o contraseña del buzón incorrectos."), 401
        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("inbox"), code=303)

    @app.post("/logout")
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("inbox"), code=303)

    return app


if __name__ == "__main__":
    from waitress import serve

    serve(create_mailbox_app(), host=os.environ.get("APP_HOST", "127.0.0.1"), port=8025, threads=4)
