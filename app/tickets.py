from flask import Blueprint, abort, current_app, g, jsonify

from .auth import require_user
from .db import core

bp = Blueprint("tickets", __name__)


@bp.get("/api/tickets")
@require_user("client")
def list_tickets():
    rows = core().execute(
        "SELECT id, subject FROM tickets WHERE owner_user_id = ? AND organization_id = ? ORDER BY id",
        (g.user["id"], g.user["organization_id"])).fetchall()
    return jsonify(tickets=[dict(row) for row in rows])


@bp.get("/api/tickets/<int:ticket_id>")
@require_user("client")
def ticket_detail(ticket_id):
    ticket = core().execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404, description="Ticket inexistente.")
    # T1 / A01: the vulnerable variant omits the ownership check only here.
    if not current_app.config["VULN_A01"] and (
        ticket["owner_user_id"] != g.user["id"] or ticket["organization_id"] != g.user["organization_id"]
    ):
        abort(403, description="Este ticket pertenece a otra cuenta.")
    assigned = None
    if ticket["assigned_operator_id"]:
        row = core().execute("SELECT id, username FROM users WHERE id = ?", (ticket["assigned_operator_id"],)).fetchone()
        assigned = dict(row)
    return jsonify(ticket={key: ticket[key] for key in ("id", "organization_id", "subject", "description")},
                   assigned_operator=assigned)
