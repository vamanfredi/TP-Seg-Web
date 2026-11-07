import json
import re
import pytest

from app import create_app
from app.config import FLAGS


@pytest.fixture
def factory(tmp_path):
    counter = 0

    def make(**options):
        nonlocal counter
        counter += 1
        config = {"TESTING": True, "LAB_MODE": True, **{flag: False for flag in FLAGS},
                  "APP_DATA_DIR": tmp_path / str(counter)}
        config.update(options)
        app = create_app(config)
        app.credentials = json.loads((app.config["APP_DATA_DIR"] / "developer-credentials.json").read_text())
        return app
    return make


@pytest.fixture
def app(factory):
    return factory()


class Actor:
    def __init__(self, app, role=None):
        self.client = app.test_client()
        self.refresh()
        if role:
            self.login(**app.credentials[role])

    def refresh(self):
        response = self.client.get("/api/session")
        self.csrf = response.json["csrf_token"]
        self.user = response.json["user"]
        return response

    def post(self, path, body=None, **kwargs):
        return self.client.post(path, json=body, headers={"X-CSRF-Token": self.csrf}, buffered=True, **kwargs)

    def login(self, username, password):
        response = self.post("/api/auth/login", {"username": username, "password": password})
        if response.status_code == 200:
            self.csrf = response.json["csrf_token"]
            self.user = response.json["user"]
        return response

    def get(self, path, **kwargs):
        return self.client.get(path, **kwargs)

    def recovery_token(self):
        response = self.post("/api/auth/recovery", {"username": self.user["username"]})
        assert response.status_code == 202
        message = self.get("/lab/inbox").json["messages"][0]["body"]
        return re.search(r"Token: ([\w-]+)", message).group(1)
