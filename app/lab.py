"""Local seed/reset commands and the user's simulated mailbox."""
import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import UUID, uuid4

import click
from flask import Blueprint, current_app, g, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

from .db import core, close_databases
from .auth import require_user

bp = Blueprint("lab", __name__)
OWNER = "tp-seg-web-exportaciones-v1\n"
MARKER = "DEMO_EXPORT_B_CONFIDENTIAL"

CORE_SCHEMA = """
CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE users (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
 username TEXT NOT NULL UNIQUE, email TEXT NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('client','operator','supervisor')));
CREATE TABLE sessions (
 id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), csrf_token TEXT NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE password_reset_tokens (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 expires_at INTEGER NOT NULL, consumed_at INTEGER);
CREATE TABLE tickets (
 id INTEGER PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
 owner_user_id TEXT NOT NULL REFERENCES users(id), assigned_operator_id TEXT REFERENCES users(id),
 subject TEXT NOT NULL, description TEXT NOT NULL);
CREATE TABLE lab_messages (
 id INTEGER PRIMARY KEY, recipient_user_id TEXT NOT NULL REFERENCES users(id),
 body TEXT NOT NULL, created_at INTEGER NOT NULL);
"""
CATALOG_SCHEMA = """CREATE TABLE exports (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, title TEXT NOT NULL,
 is_confidential INTEGER NOT NULL CHECK(is_confidential IN (0,1)))"""


def owned_path(root, relative):
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise RuntimeError("Ruta de datos fuera del directorio del laboratorio.")
    return path


def initialize(reset=False):
    root = current_app.config["APP_DATA_DIR"]
    root.mkdir(parents=True, exist_ok=True)
    marker = owned_path(root, ".lab-owner")
    files = [owned_path(root, name) for name in ("core.sqlite", "catalog.sqlite", "developer-credentials.json")]
    export_dir = owned_path(root, "exports")
    if not marker.exists():
        if any(p.exists() for p in files) or export_dir.exists():
            raise RuntimeError("El directorio contiene datos sin marca de propiedad; no se sobrescribieron.")
        marker.write_text(OWNER, encoding="utf-8")
    elif marker.read_text(encoding="utf-8") != OWNER:
        raise RuntimeError("Marca de propiedad del laboratorio inválida.")
    if files[0].exists() and files[1].exists() and not reset:
        return
    if any(p.exists() for p in files) and not reset:
        raise RuntimeError("Semilla incompleta. Revisar los datos y ejecutar lab reset explícitamente.")
    close_databases()
    # Only delete generated CSVs explicitly listed in this lab's old catalog.
    if files[1].exists():
        with closing(sqlite3.connect(files[1])) as old:
            ids = [str(UUID(row[0])) for row in old.execute("SELECT id FROM exports")]
        for export_id in ids:
            owned_path(root, f"exports/{export_id}.csv").unlink(missing_ok=True)
    for path in files:
        path.unlink(missing_ok=True)
    export_dir.mkdir(exist_ok=True)
    credentials = {}
    user_ids = {role: str(uuid4()) for role in ("client", "operator", "supervisor")}
    org_a, org_b = str(uuid4()), str(uuid4())
    with closing(sqlite3.connect(files[0])) as db, db:
        db.executescript(CORE_SCHEMA)
        db.executemany("INSERT INTO organizations VALUES (?, ?)", [(org_a, "Empresa A"), (org_b, "Empresa B")])
        for role, user_id in user_ids.items():
            username = "cliente.a" if role == "client" else f"{role}.{secrets.token_hex(3)}"
            password = secrets.token_urlsafe(18)
            if role == "client" and current_app.config["LAB_DEFAULT_CLIENT_PASSWORD"]:
                password = current_app.config["LAB_DEFAULT_CLIENT_PASSWORD"]
            credentials[role] = {"username": username, "password": password}
            db.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (
                user_id, org_a if role == "client" else org_b, username,
                username + "@example.test", generate_password_hash(password), role))
        db.executemany("INSERT INTO tickets VALUES (?, ?, ?, ?, ?, ?)", [
            (1001, org_a, user_ids["client"], None, "Acceso al portal", "Necesito consultar el estado de mi solicitud."),
            (1002, org_b, user_ids["supervisor"], user_ids["operator"], "Revisión de exportaciones", "Validar el cierre mensual de Empresa B."),
        ])
    with closing(sqlite3.connect(files[1])) as db, db:
        db.execute(CATALOG_SCHEMA)
        for organization, title, confidential in [
            (org_b, "Resumen operativo de B", 0), (org_b, "Nómina reservada de B", 1),
            (org_a, "Resumen operativo de A", 0),
        ]:
            export_id = str(uuid4())
            db.execute("INSERT INTO exports VALUES (?, ?, ?, ?)", (export_id, organization, title, confidential))
            content = f"referencia,concepto,importe\n{MARKER if confidential else 'DEMO_GENERAL'},Datos ficticios,12500\n"
            owned_path(root, f"exports/{export_id}.csv").write_text(content, encoding="utf-8")
    files[2].write_text(json.dumps(credentials, indent=2) + "\n", encoding="utf-8")
    files[2].chmod(0o600)
    files[0].chmod(0o600)


def restore_client_password():
    """Restore the configured demo password only when the server starts."""
    password = current_app.config["LAB_DEFAULT_CLIENT_PASSWORD"]
    if not password:
        return
    root = current_app.config["APP_DATA_DIR"]
    path = owned_path(root, "developer-credentials.json")
    credentials = json.loads(path.read_text(encoding="utf-8"))
    with core() as db:
        user = db.execute("SELECT id, password_hash FROM users WHERE username = ? AND role = ?",
                          ("cliente.a", "client")).fetchone()
        if user is None:
            raise RuntimeError("No se encontró el cliente del laboratorio.")
        if not check_password_hash(user["password_hash"], password):
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(password), user["id"]))
            db.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user["id"],))
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
    credentials["client"] = {"username": "cliente.a", "password": password}
    path.write_text(json.dumps(credentials, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


@bp.get("/lab/inbox")
@require_user("client")
def inbox():
    return jsonify(messages=[dict(row) for row in mailbox_messages(g.user["id"])])


def mailbox_messages(user_id):
    return core().execute(
        "SELECT id, body, created_at FROM lab_messages WHERE recipient_user_id = ? ORDER BY id DESC",
        (user_id,)).fetchall()


def register(app):
    app.register_blueprint(bp)

    @app.cli.group("lab")
    def lab_cli():
        """Utilidades locales de la demo."""

    @lab_cli.command("reset")
    def reset_command():
        """Recrear solo los datos generados; ejecutar sin solicitudes activas."""
        initialize(reset=True)
        click.echo("Semilla reiniciada. Consultá lab credentials; las sesiones anteriores quedaron invalidadas.")

    @lab_cli.command("credentials")
    @click.option("--developer", is_flag=True, help="Incluye operador y supervisor, solo para preparación local.")
    def credentials_command(developer):
        credentials = json.loads((current_app.config["APP_DATA_DIR"] / "developer-credentials.json").read_text())
        click.echo(json.dumps(credentials if developer else credentials["client"], indent=2))

    @lab_cli.command("mailbox-credentials")
    @click.option("--developer", is_flag=True, help="Incluye operador y supervisor, solo para preparación local.")
    def mailbox_credentials_command(developer):
        """Consultar las credenciales independientes del buzón."""
        from .mailbox import mailbox_key, mailbox_password

        path = current_app.config["APP_DATA_DIR"] / "developer-credentials.json"
        accounts = json.loads(path.read_text(encoding="utf-8"))
        roles = accounts if developer else ("client",)
        key = mailbox_key()
        credentials = {}
        for role in roles:
            username = accounts[role]["username"]
            user = core().execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
            credentials[role] = {"username": username, "password": mailbox_password(key, user)}
        click.echo(json.dumps(credentials if developer else credentials["client"], indent=2))
