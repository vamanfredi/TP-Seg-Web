import html
import json
import re
from urllib.parse import parse_qs, urlsplit

from app.mailbox import create_mailbox_app
from conftest import Actor


def mailbox_csrf(page):
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def reset_urls(page):
    return [html.unescape(url) for url in re.findall(r'href="([^"]*/restablecer-contrasena#[^"]+)"', page.text)]


def mailbox_credentials(app, *options):
    result = app.test_cli_runner().invoke(args=["lab", "mailbox-credentials", *options])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_guest_recovers_password_via_independent_mailbox(app):
    mailbox = create_mailbox_app({"APP_DATA_DIR": app.config["APP_DATA_DIR"]})
    guest = Actor(app)
    owner = Actor(app, "client")
    recovery = guest.post("/api/auth/recovery", {"username": owner.user["username"]})
    assert recovery.status_code == 202
    assert "token" not in recovery.text.lower()

    with mailbox.test_client() as browser:
        credentials = mailbox_credentials(app)
        login = browser.get("/")
        inbox = browser.post("/login", data={**credentials, "csrf_token": mailbox_csrf(login)},
                             follow_redirects=True)
        assert inbox.status_code == 200
        link, = reset_urls(inbox)

    url = urlsplit(link)
    assert f"{url.scheme}://{url.netloc}" == app.config["PORTAL_URL"]
    assert not url.query
    fragment = parse_qs(url.fragment)
    assert fragment["user_id"] == [owner.user["id"]]
    form = guest.get(url.path)
    assert form.status_code == 200
    assert 'name="new_password"' in form.text
    assert 'name="user_id"' not in form.text and 'name="token"' not in form.text

    password = "Clave-Nueva-Segura-2026"
    body = {"token": fragment["token"][0], "user_id": fragment["user_id"][0], "new_password": password}
    assert guest.post("/api/auth/reset-password", body).status_code == 200
    assert guest.post("/api/auth/reset-password", body).status_code == 400
    assert guest.login(**app.credentials["client"]).status_code == 401
    assert guest.login(owner.user["username"], password).status_code == 200


def test_mailbox_sessions_and_messages_are_isolated(factory):
    configured_password = "Buzon-Alternativo-2026!"
    app = factory(LAB_DEFAULT_MAILBOX_PASSWORD=configured_password)
    mailbox = create_mailbox_app({
        "APP_DATA_DIR": app.config["APP_DATA_DIR"],
        "LAB_DEFAULT_MAILBOX_PASSWORD": configured_password,
    })
    owner = Actor(app, "client")
    operator = Actor(app, "operator")
    credentials = mailbox_credentials(app, "--developer")
    assert credentials["client"]["password"] == configured_password
    assert credentials["operator"]["password"] != configured_password
    assert credentials["supervisor"]["password"] != configured_password
    for actor in (owner, operator):
        assert owner.post("/api/auth/recovery", {"username": actor.user["username"]}).status_code == 202

    with mailbox.test_client() as browser:
        browser.set_cookie("portal_session", owner.client.get_cookie("portal_session").value)
        login = browser.get("/")
        assert not reset_urls(login)
        assert browser.post("/login", data=credentials["client"]).status_code == 400
        assert browser.post("/login", data={**app.credentials["client"], "csrf_token": mailbox_csrf(login)}).status_code == 401

        for role, actor in (("client", owner), ("operator", operator)):
            login = browser.get("/")
            inbox = browser.post("/login", data={**credentials[role], "csrf_token": mailbox_csrf(login)},
                                 follow_redirects=True)
            assert inbox.status_code == 200
            link, = reset_urls(inbox)
            assert parse_qs(urlsplit(link).fragment)["user_id"] == [actor.user["id"]]
            logged_out = browser.post("/logout", data={"csrf_token": mailbox_csrf(inbox)}, follow_redirects=True)
            assert not reset_urls(logged_out)
