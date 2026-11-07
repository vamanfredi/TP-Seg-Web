"""Configuration is read once at startup; secure behavior is the default."""
import os
from pathlib import Path

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
    }
    app.config.update({key: os.environ.get(key, value) for key, value in defaults.items()})
    app.config.update(overrides or {})
    password = app.config["LAB_DEFAULT_CLIENT_PASSWORD"]
    if password and len(password) < 12:
        raise ValueError("LAB_DEFAULT_CLIENT_PASSWORD debe tener al menos 12 caracteres.")
    for key in (*FLAGS, "LAB_MODE", "SESSION_COOKIE_SECURE"):
        app.config[key] = boolean(app.config[key])
    if any(app.config[key] for key in FLAGS) and not app.config["LAB_MODE"]:
        raise ValueError("Las fallas intencionales requieren LAB_MODE=1.")
    for key in ("RESET_TOKEN_TTL_SECONDS", "SESSION_TTL_SECONDS"):
        app.config[key] = int(app.config[key])
        if app.config[key] <= 0:
            raise ValueError(f"{key} debe ser positivo.")
    app.config.update(DEBUG=False, MAX_CONTENT_LENGTH=16384)
    app.config["APP_DATA_DIR"] = Path(app.config["APP_DATA_DIR"]).resolve()
