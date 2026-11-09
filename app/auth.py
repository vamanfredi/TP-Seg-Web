import hashlib
import hmac
import secrets
import time
from functools import wraps
from urllib.parse import urlencode

from flask import Blueprint, abort, current_app, g, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

from .db import core

bp = Blueprint("auth", __name__)
COOKIE = "portal_session"
RESET_PATH = "/restablecer-contrasena"


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def load_session():
    g.user, g.session = None, None
    raw = request.cookies.get(COOKIE, "")
    if raw:
        g.session = core().execute(
            "SELECT * FROM sessions WHERE id = ? AND revoked = 0 AND expires_at > ?",
            (token_hash(raw), int(time.time()))).fetchone()
        if g.session and g.session["user_id"]:
            g.user = core().execute(
                "SELECT id, organization_id, username, role FROM users WHERE id = ?",
                (g.session["user_id"],)).fetchone()


def new_session(user_id=None):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with core() as db:
        if g.session:
            db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.session["id"],))
        db.execute("INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)", (
            token_hash(raw), user_id, csrf, int(time.time()) + current_app.config["SESSION_TTL_SECONDS"]))
    return raw, csrf


def session_cookie(response, raw):
    response.set_cookie(COOKIE, raw, httponly=True, samesite="Lax",
                        secure=current_app.config["SESSION_COOKIE_SECURE"], path="/")
    return response


def require_user(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                abort(401, description="Iniciá sesión para continuar.")
            if roles and g.user["role"] not in roles:
                abort(403, description="Tu cuenta no tiene acceso a esta función.")
            return view(*args, **kwargs)
        return wrapped
    return decorator


def csrf_required():
    supplied = request.headers.get("X-CSRF-Token", "")
    if not g.session or not hmac.compare_digest(supplied.encode(), g.session["csrf_token"].encode()):
        abort(400, description="La protección CSRF requiere una sesión y un token válidos.")


def json_object():
    if not request.is_json:
        abort(400, description="Se requiere un objeto JSON.")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        abort(400, description="Se requiere un objeto JSON válido.")
    return body


def text_field(body, key, minimum=1, maximum=256):
    value = body.get(key)
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        abort(400, description=f"Campo inválido: {key}.")
    return value


@bp.get("/api/session")
def session_info():
    response = jsonify(user=dict(g.user) if g.user else None,
                       csrf_token=g.session["csrf_token"] if g.session else None)
    if not g.session:
        raw, csrf = new_session()
        response = session_cookie(jsonify(user=None, csrf_token=csrf), raw)
    return response


@bp.post("/api/auth/login")
def login():
    csrf_required()
    body = json_object()
    username, password = text_field(body, "username"), text_field(body, "password")
    user = core().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    password_hash = user["password_hash"] if user else current_app.config["DUMMY_PASSWORD_HASH"]
    if not check_password_hash(password_hash, password) or not user:
        abort(401, description="Usuario o contraseña incorrectos.")
    raw, csrf = new_session(user["id"])
    return session_cookie(jsonify(user={key: user[key] for key in ("id", "organization_id", "username", "role")},
                                  csrf_token=csrf), raw)


@bp.post("/api/auth/logout")
@require_user()
def logout():
    csrf_required()
    with core() as db:
        db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (g.session["id"],))
    response = jsonify(message="Sesión cerrada.")
    response.delete_cookie(COOKIE, path="/")
    return response


@bp.post("/api/auth/recovery")
def recovery():
    csrf_required()
    username = text_field(json_object(), "username")
    user = core().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        message = (f"Recuperación de cuenta\nEnlace: {reset_link(token, user['id'])}\n"
                   f"Token: {token}\nCuenta: {user['id']}")
        with core() as db:
            db.execute("INSERT INTO password_reset_tokens VALUES (?, ?, ?, NULL)", (
                token_hash(token), user["id"], now + current_app.config["RESET_TOKEN_TTL_SECONDS"]))
            db.execute("INSERT INTO lab_messages (recipient_user_id, body, created_at) VALUES (?, ?, ?)",
                       (user["id"], message, now))
    return jsonify(message="Si la cuenta existe, enviamos las instrucciones a su buzón."), 202


def reset_link(token, user_id):
    fragment = urlencode({"token": token, "user_id": user_id})
    return f"{current_app.config['PORTAL_URL']}{RESET_PATH}#{fragment}"


@bp.get(RESET_PATH)
def reset_form():
    return render_template("reset_password.html")


@bp.post("/api/auth/reset-password")
def reset_password():
    csrf_required()
    body = json_object()
    token = text_field(body, "token")
    user_id = text_field(body, "user_id")
    password = text_field(body, "new_password", minimum=12)
    now = int(time.time())
    db = core()
    # Serialize validation + consumption to prevent concurrent reuse of a token.
    with db:
        db.execute("BEGIN IMMEDIATE")
        issued = db.execute(
            "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND expires_at > ? AND consumed_at IS NULL",
            (token_hash(token), now)).fetchone()
        # T2 / A07: token validity is always checked; account binding is the flaw.
        if not issued or (not current_app.config["VULN_A07"] and issued["user_id"] != user_id):
            abort(400, description="El token no es válido para esta cuenta.")
        target = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            abort(400, description="El token no es válido para esta cuenta.")
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), user_id))
        db.execute("UPDATE password_reset_tokens SET consumed_at = ? WHERE token_hash = ?", (now, token_hash(token)))
        db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))
    return jsonify(message="Contraseña actualizada. Iniciá sesión nuevamente.")
