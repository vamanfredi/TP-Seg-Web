import secrets

from flask import Flask, jsonify, render_template
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from .config import configure


def create_app(config=None, *, restore_client_password=False):
    app = Flask(__name__)
    configure(app, config)
    app.config["DUMMY_PASSWORD_HASH"] = generate_password_hash(secrets.token_urlsafe(18))
    from . import auth, db, exports, lab, tickets
    app.teardown_appcontext(db.close_databases)
    app.before_request(auth.load_session)
    app.register_blueprint(auth.bp)
    app.register_blueprint(tickets.bp)
    app.register_blueprint(exports.bp)
    lab.register(app)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def portal():
        return render_template("portal.html")

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    @app.errorhandler(Exception)
    def unexpected_error(error):
        app.logger.error("Error interno: %s", type(error).__name__)
        return jsonify(error="Error interno del servidor."), 500

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        return response

    with app.app_context():
        lab.initialize()
        if restore_client_password:
            lab.restore_client_password()
    return app
