import json
import sqlite3
from uuid import uuid4

import pytest

from app import authorization
from app.config import FLAGS
from app.db import catalog, core
from app.lab import MARKER
from conftest import Actor
from scripts.demo_chain import PAYLOAD, local_url


@pytest.mark.parametrize("fixed", [None, *FLAGS, "all"])
def test_chain_and_independent_fixes(factory, fixed):
    app = factory(**{flag: fixed not in (flag, "all") for flag in FLAGS})
    client = Actor(app, "client")
    assert client.get("/api/tickets/1001").json["assigned_operator"] is None
    response = client.get("/api/tickets/1002")
    if fixed in ("VULN_A01", "all"):
        assert response.status_code == 403
        assert "assigned_operator" not in response.text
        return
    target = response.json["assigned_operator"]
    organization = response.json["ticket"]["organization_id"]
    assert target["id"] not in client.get("/api/tickets").text
    token = client.recovery_token()
    password = "Nueva-Clave-Para-Demo-2026"
    response = client.post("/api/auth/reset-password", {"token": token, "user_id": target["id"], "new_password": password})
    if fixed == "VULN_A07":
        assert response.status_code == 400
        # Developer verification only after the attacker has stopped.
        assert Actor(app).login(**app.credentials["operator"]).status_code == 200
        assert Actor(app).login(target["username"], password).status_code == 401
        return
    assert response.status_code == 200
    operator = Actor(app)
    assert operator.login(target["username"], password).status_code == 200
    normal = operator.get("/api/exports/search").json["exports"]
    assert len(normal) == 1 and not normal[0]["is_confidential"]
    response = operator.get("/api/exports/search", query_string={"q": PAYLOAD})
    assert response.status_code == 200 and MARKER not in response.text
    if fixed == "VULN_A05":
        assert response.json["exports"] == []
        return
    protected = next(row for row in response.json["exports"] if row["is_confidential"] and row["organization_id"] == organization)
    assert protected["id"] not in [row["id"] for row in normal]
    url = f"/api/exports/{protected['id']}/download"
    assert operator.post(url, {"context": {"purpose": "download"}}).status_code == 403
    response = operator.post(url, {"context": None})
    if fixed == "VULN_A10":
        assert response.status_code == 400 and MARKER not in response.text
    else:
        assert response.status_code == 200 and MARKER.encode() in response.data
        assert response.mimetype == "text/csv"


@pytest.mark.parametrize("vulnerable", [False, True])
def test_adapter_boundaries(factory, monkeypatch, vulnerable):
    app = factory(**{flag: vulnerable for flag in FLAGS})
    operator, supervisor, client = Actor(app, "operator"), Actor(app, "supervisor"), Actor(app, "client")
    protected = next(row for row in supervisor.get("/api/exports/search").json["exports"] if row["is_confidential"])
    url = f"/api/exports/{protected['id']}/download"
    assert client.post(url, {"context": None, "role": "supervisor"}).status_code == 403
    assert Actor(app).post(url, {"context": None}).status_code == 401
    assert operator.client.post(url, json={"context": None}).status_code == 400
    assert operator.post("/api/exports/not-a-uuid/download", {"context": None}).status_code == 400
    assert operator.post(f"/api/exports/{uuid4()}/download", {"context": None}).status_code == 404
    for body in ({}, [], "bad"):
        assert operator.post(url, body).status_code == 400
    malformed = operator.client.post(url, data='{"context":', content_type="application/json", headers={"X-CSRF-Token": operator.csrf})
    assert malformed.status_code == 400
    for context in ({"purpose": "admin", "allowed": True}, {"role": "supervisor"}, {}):
        assert operator.post(url, {"context": context}).status_code == 403
    assert supervisor.post(url, {"context": {}}).status_code == 200
    for context in (None, [], 0, "download"):
        response = operator.post(url, {"context": context})
        assert response.status_code == (200 if vulnerable else 400)

    def unavailable(*args):
        raise RuntimeError("ERROR_INTERNO_NO_PUBLICAR")

    monkeypatch.setattr(authorization, "evaluate", unavailable)
    response = operator.post(url, {"context": {}})
    assert response.status_code == (200 if vulnerable else 503)
    assert "ERROR_INTERNO_NO_PUBLICAR" not in response.text
    if not vulnerable:
        assert MARKER not in response.text
    path = app.config["APP_DATA_DIR"] / "exports" / f"{protected['id']}.csv"
    path.unlink()
    assert operator.post(url, {"context": {}}).status_code == 503


def test_catalog_cannot_escape_its_metadata(app):
    with app.app_context():
        db = catalog()
        assert len(db.execute("SELECT * FROM exports").fetchall()) == 3
        for sql in (
            "DELETE FROM exports", "UPDATE exports SET title = 'changed'",
            "ATTACH DATABASE 'core.sqlite' AS core", "PRAGMA database_list",
            "SELECT * FROM sqlite_master", "SELECT * FROM users",
            "SELECT readfile('core.sqlite')", "SELECT load_extension('missing')",
        ):
            with pytest.raises(sqlite3.Error):
                db.execute(sql)
        assert len(db.execute("SELECT * FROM exports").fetchall()) == 3
        assert MARKER not in json.dumps([dict(row) for row in db.execute("SELECT * FROM exports")])


@pytest.mark.parametrize("url", ["https://example.com", "http://192.168.1.10:8000", "http://127.0.0.1.evil.test", "http://user@127.0.0.1", "http://127.0.0.1/path", "file:///tmp"])
def test_demo_refuses_external_destinations(url):
    with pytest.raises(ValueError):
        local_url(url)


def test_demo_normalizes_localhost():
    assert local_url("http://localhost:8000/") == "http://127.0.0.1:8000"
    assert local_url("http://[::1]:8000") == "http://[::1]:8000"
