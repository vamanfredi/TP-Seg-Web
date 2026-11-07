from concurrent.futures import ThreadPoolExecutor
import time
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from app.auth import COOKIE, token_hash
from app.config import FLAGS
from app.db import catalog, core
from conftest import Actor


@pytest.mark.parametrize("vulnerable", [False, True])
def test_cross_company_downloads_and_operator_access(factory, vulnerable):
    app = factory(**{flag: vulnerable for flag in FLAGS})
    operator, supervisor = Actor(app, "operator"), Actor(app, "supervisor")
    with app.app_context():
        other_export = catalog().execute("SELECT id FROM exports WHERE organization_id != ?",
                                         (operator.user["organization_id"],)).fetchone()[0]
    url = f"/api/exports/{other_export}/download"
    assert operator.post(url, {"context": {}}).status_code == 403
    assert supervisor.post(url, {"context": {}}).status_code == 403
    exports = operator.get("/api/exports/search").json["exports"]
    assert len(exports) == 1
    assert exports[0]["organization_id"] == operator.user["organization_id"]
    assert operator.post(f"/api/exports/{exports[0]['id']}/download", {"context": {}}).status_code == 200


def test_owner_and_company_are_both_checked(app):
    actor = Actor(app, "client")
    with app.app_context():
        with core() as db:
            other = str(uuid4())
            db.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
                       (other, actor.user["organization_id"], "otro.cliente", "otro@example.test", generate_password_hash("Otra-clave-segura"), "client"))
            db.execute("INSERT INTO tickets VALUES (?, ?, ?, NULL, ?, ?)",
                       (1003, actor.user["organization_id"], other, "Ajeno en A", "Privado"))
    assert actor.get("/api/tickets/1003").status_code == 403
    assert [row["id"] for row in actor.get("/api/tickets").json["tickets"]] == [1001]


def test_a07_revokes_only_target_sessions(factory):
    app = factory(VULN_A07=True)
    client, operator = Actor(app, "client"), Actor(app, "operator")
    token = client.recovery_token()
    response = client.post("/api/auth/reset-password", {"token": token, "user_id": operator.user["id"], "new_password": "Cambio-operador-2026"})
    assert response.status_code == 200
    assert operator.get("/api/exports/search").status_code == 401
    assert client.get("/api/tickets").status_code == 200
    assert client.refresh().json["user"]["role"] == "client"


def test_reset_token_is_consumed_atomically(app):
    owner = Actor(app, "client")
    token = owner.recovery_token()
    first, second = Actor(app), Actor(app)
    body = {"token": token, "user_id": owner.user["id"], "new_password": "Cambio-simultaneo-2026"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda actor: actor.post("/api/auth/reset-password", body).status_code, (first, second)))
    assert sorted(outcomes) == [200, 400]


def test_expired_session_and_login_rotation(app):
    actor = Actor(app)
    old_cookie = actor.client.get_cookie(COOKIE).value
    actor.login(**app.credentials["client"])
    new_cookie = actor.client.get_cookie(COOKIE).value
    actor.client.set_cookie(COOKIE, old_cookie)
    assert actor.get("/api/tickets").status_code == 401
    actor.client.set_cookie(COOKIE, new_cookie)
    with app.app_context():
        with core() as db:
            db.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (int(time.time()) - 1, token_hash(new_cookie)))
    assert actor.get("/api/tickets").status_code == 401
