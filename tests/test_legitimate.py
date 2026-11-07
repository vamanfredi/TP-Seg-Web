import time
from uuid import uuid4

from app.auth import COOKIE, token_hash
from app.db import core
from conftest import Actor


def test_roles_and_downloads(app):
    guest = Actor(app)
    assert guest.get("/api/tickets").status_code == 401
    client = Actor(app, "client")
    assert [row["id"] for row in client.get("/api/tickets").json["tickets"]] == [1001]
    assert client.get("/api/tickets/1001").json["assigned_operator"] is None
    assert client.get("/api/tickets/1002").status_code == 403
    assert client.get("/api/tickets/9999").status_code == 404
    assert client.get("/api/exports/search").status_code == 403
    operator = Actor(app, "operator")
    supervisor = Actor(app, "supervisor")
    general = operator.get("/api/exports/search").json["exports"]
    assert len(general) == 1 and not general[0]["is_confidential"]
    exports = supervisor.get("/api/exports/search").json["exports"]
    assert len(exports) == 2
    confidential = next(row for row in exports if row["is_confidential"])
    url = f"/api/exports/{confidential['id']}/download"
    assert client.post(url, {"context": None}).status_code == 403
    assert guest.post(url, {"context": None}).status_code == 401
    assert operator.post(url, {"context": {"purpose": "download"}}).status_code == 403
    assert operator.post(url, {"context": None}).status_code == 400
    response = supervisor.post(url, {"context": {"purpose": "download"}})
    assert response.status_code == 200 and b"DEMO_EXPORT_B_CONFIDENTIAL" in response.data
    assert response.mimetype == "text/csv"
    assert operator.post(f"/api/exports/{general[0]['id']}/download", {"context": {}}).status_code == 200
    assert operator.post(f"/api/exports/{uuid4()}/download", {"context": None}).status_code == 404


def test_recovery_revokes_sessions_and_consumes_token(app):
    actor = Actor(app, "client")
    other_session = Actor(app, "client")
    token = actor.recovery_token()
    body = {"token": token, "user_id": actor.user["id"], "new_password": "Una-Clave-Nueva-2026"}
    assert actor.post("/api/auth/reset-password", body).status_code == 200
    assert other_session.get("/api/tickets").status_code == 401
    assert actor.get("/api/tickets").status_code == 401
    actor.refresh()
    assert actor.post("/api/auth/reset-password", body).status_code == 400
    assert actor.login(**app.credentials["client"]).status_code == 401
    assert actor.login(app.credentials["client"]["username"], body["new_password"]).status_code == 200


def test_invalid_expired_foreign_tokens_and_mailbox(app):
    actor = Actor(app, "client")
    operator = Actor(app, "operator")
    token = actor.recovery_token()
    body = {"token": token, "user_id": operator.user["id"], "new_password": "Otra-Clave-Nueva-2026"}
    assert actor.post("/api/auth/reset-password", body).status_code == 400
    assert Actor(app).login(**app.credentials["operator"]).status_code == 200
    with app.app_context():
        db = core()
        with db:
            db.execute("UPDATE password_reset_tokens SET expires_at = ? WHERE token_hash = ?", (int(time.time()) - 1, token_hash(token)))
            db.execute("INSERT INTO lab_messages (recipient_user_id, body, created_at) VALUES (?, ?, ?)",
                       (operator.user["id"], "NO_DEBE_FILTRARSE", int(time.time())))
    body["user_id"] = actor.user["id"]
    assert actor.post("/api/auth/reset-password", body).status_code == 400
    body["token"] = "no-existe"
    assert actor.post("/api/auth/reset-password", body).status_code == 400
    assert "NO_DEBE_FILTRARSE" not in actor.get("/lab/inbox", query_string={"user_id": operator.user["id"]}).text
    assert operator.get("/lab/inbox").status_code == 403


def test_csrf_and_logout_replay(app):
    actor = Actor(app)
    old_cookie = actor.client.get_cookie(COOKIE).value
    response = actor.client.post("/api/auth/login", json=app.credentials["client"])
    assert response.status_code == 400
    assert actor.login(**app.credentials["client"]).status_code == 200
    cookie = actor.client.get_cookie(COOKIE)
    assert cookie.value != old_cookie and cookie.http_only and cookie.same_site == "Lax"
    assert actor.client.post("/api/auth/logout").status_code == 400
    assert actor.post("/api/auth/logout").status_code == 200
    actor.client.set_cookie(COOKIE, cookie.value)
    assert actor.get("/api/tickets").status_code == 401


def test_recovery_response_does_not_enumerate(app):
    actor = Actor(app)
    known = actor.post("/api/auth/recovery", {"username": app.credentials["client"]["username"]})
    unknown = actor.post("/api/auth/recovery", {"username": "nadie"})
    assert known.status_code == unknown.status_code == 202
    assert known.json == unknown.json
    assert "token" not in known.text.lower()
