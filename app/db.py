"""Independent connections: the search engine can only read catalog metadata."""
import sqlite3
from flask import current_app, g


def core():
    if "core_db" not in g:
        db = sqlite3.connect(current_app.config["APP_DATA_DIR"] / "core.sqlite")
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.core_db = db
    return g.core_db


def catalog_authorizer(action, arg1, arg2, database, source):
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and database == "main" and arg1 == "exports":
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in {"like", "lower", "upper"}:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def catalog():
    if "catalog_db" not in g:
        path = current_app.config["APP_DATA_DIR"] / "catalog.sqlite"
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        # No extensions or user-defined file-reading functions are registered.
        db.set_authorizer(catalog_authorizer)
        db.set_progress_handler(lambda: 1, 100000)
        g.catalog_db = db
    return g.catalog_db


def close_databases(error=None):
    for key in ("core_db", "catalog_db"):
        db = g.pop(key, None)
        if db is not None:
            db.close()
