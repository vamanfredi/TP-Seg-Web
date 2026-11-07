import sqlite3
from uuid import UUID

from flask import Blueprint, abort, current_app, g, jsonify, request, send_file

from . import authorization
from .auth import csrf_required, json_object, require_user
from .db import catalog

bp = Blueprint("exports", __name__)


@bp.get("/api/exports/search")
@require_user("operator", "supervisor")
def search():
    query = request.args.get("q", "")
    if len(query) > 300:
        abort(400, description="La búsqueda admite hasta 300 caracteres.")
    sql = "SELECT id, organization_id, title, is_confidential FROM exports WHERE organization_id = ? AND (is_confidential = 0 OR ? = 1) AND title LIKE ?"
    parameters = (g.user["organization_id"], int(g.user["role"] == "supervisor"), f"%{query}%")
    if current_app.config["VULN_A05"]:
        # T3 / A05: intentionally unsafe, real SQL over the isolated catalog.
        sql = "SELECT id, organization_id, title, is_confidential FROM exports WHERE organization_id = ? AND (is_confidential = 0 OR ? = 1) AND title LIKE '%" + query + "%'"
        parameters = parameters[:2]
    try:
        rows = catalog().execute(sql, parameters).fetchall()
    except sqlite3.Error:
        abort(400, description="No se pudo procesar la búsqueda.")
    return jsonify(exports=[dict(row) for row in rows])


@bp.post("/api/exports/<export_id>/download")
@require_user("operator", "supervisor")
def download(export_id):
    csrf_required()
    try:
        canonical_id = str(UUID(export_id))
    except ValueError:
        abort(400, description="Identificador de exportación inválido.")
    export = catalog().execute("SELECT * FROM exports WHERE id = ?", (canonical_id,)).fetchone()
    if export is None:
        abort(404, description="Exportación inexistente.")
    body = json_object()
    if "context" not in body:
        abort(400, description="Falta el campo context.")
    context = body["context"]
    if not current_app.config["VULN_A10"] and not isinstance(context, dict):
        abort(400, description="context debe ser un objeto.")
    try:
        allowed = authorization.evaluate(g.user, export, context)
    except Exception:
        current_app.logger.warning("Falló el adaptador de autorización.")
        # T4 / A10: only an exception inside the adapter triggers fail-open.
        if current_app.config["VULN_A10"]:
            allowed = True
        else:
            abort(503, description="No se pudo evaluar el permiso. Intentá más tarde.")
    if not allowed:
        abort(403, description="No tenés permiso para descargar esta exportación.")
    path = current_app.config["APP_DATA_DIR"] / "exports" / f"{canonical_id}.csv"
    if not path.is_file():
        abort(503, description="El archivo no está disponible.")
    return send_file(path, mimetype="text/csv", as_attachment=True, download_name=f"exportacion-{canonical_id}.csv")
