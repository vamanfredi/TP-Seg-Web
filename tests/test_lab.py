import json
import time

import pytest

from app import create_app
from app.auth import token_hash
from app.config import FLAGS
from app.db import core, catalog
from conftest import Actor


def test_secure_defaults_and_explicit_flags(tmp_path, monkeypatch):
    for key in (*FLAGS, "LAB_MODE", "APP_DATA_DIR"):
        monkeypatch.delenv(key, raising=False)
    app = create_app({"APP_DATA_DIR": tmp_path / "default"})
    assert not any(app.config[flag] for flag in FLAGS)
    assert not app.debug
    for flag in FLAGS:
        with pytest.raises(ValueError, match="LAB_MODE"):
            create_app({"APP_DATA_DIR": tmp_path / flag, flag: "1", "LAB_MODE": "0"})
    app = create_app({"APP_DATA_DIR": tmp_path / "zeros", **{flag: "0" for flag in FLAGS}})
    assert not any(app.config[flag] for flag in FLAGS)
    with pytest.raises(ValueError):
        create_app({"VULN_A01": "false"})


def test_reset_preserves_unrelated_files_and_changes_ids(app):
    actor = Actor(app, "client")
    actor.recovery_token()
    root = app.config["APP_DATA_DIR"]
    unrelated = root / "exports" / "mis-apuntes.txt"
    unrelated.write_text("conservar")
    with app.app_context():
        old_ids = {row["id"] for row in catalog().execute("SELECT id FROM exports")}
    credentials_before = (root / "developer-credentials.json").read_text()
    runner = app.test_cli_runner()
    assert runner.invoke(args=["lab", "reset"]).exit_code == 0
    assert unrelated.read_text() == "conservar"
    assert (root / "developer-credentials.json").read_text() != credentials_before
    assert actor.get("/api/tickets").status_code == 401
    with app.app_context():
        assert core().execute("SELECT count(*) FROM password_reset_tokens").fetchone()[0] == 0
        assert core().execute("SELECT count(*) FROM lab_messages").fetchone()[0] == 0
        new_ids = {row["id"] for row in catalog().execute("SELECT id FROM exports")}
    assert not old_ids.intersection(new_ids)
    assert all(not (root / "exports" / f"{uid}.csv").exists() for uid in old_ids)
    default_output = json.loads(runner.invoke(args=["lab", "credentials"]).output)
    assert set(default_output) == {"username", "password"}


def test_startup_preserves_existing_seed(app):
    actor = Actor(app, "client")
    token = actor.recovery_token()
    credentials = (app.config["APP_DATA_DIR"] / "developer-credentials.json").read_text()
    second = create_app(dict(app.config))
    assert credentials == (second.config["APP_DATA_DIR"] / "developer-credentials.json").read_text()
    with second.app_context():
        assert core().execute("SELECT 1 FROM password_reset_tokens WHERE token_hash = ?", (token_hash(token),)).fetchone()


def test_server_restart_restores_client_password_and_preserves_lab(factory):
    password = "ClienteA-2026!"
    app = factory(LAB_DEFAULT_CLIENT_PASSWORD=password)
    assert app.credentials["client"]["password"] == password
    client = Actor(app, "client")
    changed_password = "Otra-Clave-2026!"
    assert client.post("/api/auth/reset-password", {
        "token": client.recovery_token(), "user_id": client.user["id"],
        "new_password": changed_password,
    }).status_code == 200
    client.refresh()
    assert client.login("cliente.a", changed_password).status_code == 200
    pending_token = client.recovery_token()
    operator = Actor(app, "operator")
    with app.app_context():
        exports_before = [dict(row) for row in catalog().execute("SELECT * FROM exports")]
        tickets_before = [dict(row) for row in core().execute("SELECT * FROM tickets")]

    # Loading the app for a CLI command must not change the password.
    cli_app = create_app(dict(app.config))
    output = cli_app.test_cli_runner().invoke(args=["lab", "credentials"])
    assert output.exit_code == 0
    assert Actor(cli_app).login("cliente.a", changed_password).status_code == 200

    restarted = create_app(dict(app.config), restore_client_password=True)
    assert Actor(restarted).login("cliente.a", changed_password).status_code == 401
    assert Actor(restarted).login("cliente.a", password).status_code == 200
    assert client.get("/api/tickets").status_code == 401
    assert operator.refresh().json["user"]["id"] == operator.user["id"]
    credentials = json.loads((restarted.config["APP_DATA_DIR"] / "developer-credentials.json").read_text())
    assert credentials["client"]["password"] == password
    assert credentials["operator"] == app.credentials["operator"]
    assert credentials["supervisor"] == app.credentials["supervisor"]
    with restarted.app_context():
        assert not core().execute("SELECT 1 FROM password_reset_tokens WHERE token_hash = ?", (token_hash(pending_token),)).fetchone()
        assert [dict(row) for row in catalog().execute("SELECT * FROM exports")] == exports_before
        assert [dict(row) for row in core().execute("SELECT * FROM tickets")] == tickets_before


@pytest.mark.parametrize("password", ["", "ClienteA-2026!"])
def test_server_restart_preserves_sessions_when_password_unchanged(factory, password):
    app = factory(LAB_DEFAULT_CLIENT_PASSWORD=password)
    client = Actor(app, "client")
    token = client.recovery_token()
    create_app(dict(app.config), restore_client_password=True)
    assert client.get("/api/tickets").status_code == 200
    with app.app_context():
        assert core().execute("SELECT 1 FROM password_reset_tokens WHERE token_hash = ?", (token_hash(token),)).fetchone()


def test_seed_refuses_to_overwrite_unowned_data(tmp_path):
    original = tmp_path / "core.sqlite"
    original.write_bytes(b"archivo ajeno")
    with pytest.raises(RuntimeError, match="sin marca"):
        create_app({"APP_DATA_DIR": tmp_path})
    assert original.read_bytes() == b"archivo ajeno"


@pytest.mark.parametrize("vulnerable", [False, True])
def test_tokens_rejected_and_session_revoked_in_both_modes(factory, vulnerable):
    app = factory(**{flag: vulnerable for flag in FLAGS})
    client = Actor(app, "client")
    other_session = Actor(app, "client")
    token = client.recovery_token()
    body = {"token": "invalid", "user_id": client.user["id"], "new_password": "Nueva-Clave-Propia-2026"}
    assert client.post("/api/auth/reset-password", body).status_code == 400
    body["token"] = token
    with app.app_context():
        with core() as db:
            db.execute("UPDATE password_reset_tokens SET expires_at = ?", (int(time.time()) - 1,))
    assert client.post("/api/auth/reset-password", body).status_code == 400
    body["token"] = client.recovery_token()
    assert client.post("/api/auth/reset-password", body).status_code == 200
    assert other_session.get("/api/tickets").status_code == 401
    client.refresh()
    assert client.post("/api/auth/reset-password", body).status_code == 400
    assert client.login(app.credentials["client"]["username"], body["new_password"]).status_code == 200


def test_pages_do_not_publish_setup_or_payloads(app):
    actor = Actor(app)
    for url in ("/", "/?view=recovery", "/static/portal.js"):
        response = actor.get(url)
        assert response.status_code == 200
        for credential in app.credentials.values():
            assert credential["password"] not in response.text
        assert app.credentials["operator"]["username"] not in response.text
        assert "VULN_A" not in response.text
    for url in ("/developer-credentials.json", "/core.sqlite", "/catalog.sqlite"):
        assert actor.get(url).status_code == 404
