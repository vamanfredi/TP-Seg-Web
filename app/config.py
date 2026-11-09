"""Configuration is read once at startup; secure behavior is the default."""
import os
from pathlib import Path
from urllib.parse import urlsplit

FLAGS = ("VULN_A01", "VULN_A07", "VULN_A05", "VULN_A10")


def boolean(value):
    if value is True or value == "1" or type(value) is int and value == 1:
        return True
    if value is False or value == "0" or type(value) is int and value == 0:
        return False
    raise ValueError("Las opciones booleanas deben ser 0 o 1.")


def configure(app, overrides=None):
    defaults = {
        "LAB_MODE": "0", **{flag: "0" for flag in FLAGS},
        "APP_DATA_DIR": str(Path(app.root_path).parent / "data"),
        "RESET_TOKEN_TTL_SECONDS": "600", "SESSION_TTL_SECONDS": "3600",
        "SESSION_COOKIE_SECURE": "0",
        "LAB_DEFAULT_CLIENT_PASSWORD": "",
        "LAB_DEFAULT_MAILBOX_PASSWORD": "",
        "PORTAL_URL": "http://127.0.0.1:8000",
        "MAILBOX_URL": "http://127.0.0.1:8025",
    }
    app.config.update({key: os.environ.get(key, value) for key, value in defaults.items()})
    app.config.update(overrides or {})
    for key in ("LAB_DEFAULT_CLIENT_PASSWORD", "LAB_DEFAULT_MAILBOX_PASSWORD"):
        password = app.config[key]
        if password and len(password) < 12:
            raise ValueError(f"{key} debe tener al menos 12 caracteres.")
    for key in (*FLAGS, "LAB_MODE", "SESSION_COOKIE_SECURE"):
        app.config[key] = boolean(app.config[key])
    if any(app.config[key] for key in FLAGS) and not app.config["LAB_MODE"]:
        raise ValueError("Las fallas intencionales requieren LAB_MODE=1.")
    for key in ("RESET_TOKEN_TTL_SECONDS", "SESSION_TTL_SECONDS"):
        app.config[key] = int(app.config[key])
        if app.config[key] <= 0:
            raise ValueError(f"{key} debe ser positivo.")
    for key in ("PORTAL_URL", "MAILBOX_URL"):
        url = urlsplit(app.config[key])
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
                or url.path not in {"", "/"} or url.query or url.fragment):
            raise ValueError(f"{key} debe ser un origen HTTP o HTTPS.")
        app.config[key] = f"{url.scheme}://{url.netloc}"
    app.config.update(DEBUG=False, MAX_CONTENT_LENGTH=16384)
    app.config["APP_DATA_DIR"] = Path(app.config["APP_DATA_DIR"]).resolve()
