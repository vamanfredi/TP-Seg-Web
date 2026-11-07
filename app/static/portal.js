"use strict";
let csrf = "";
const $ = (selector) => document.querySelector(selector);

function notice(message, error = false) {
  const box = $("#notice");
  box.textContent = message;
  box.className = error ? "error" : "";
  box.hidden = false;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : {"Content-Type": "application/json", "X-CSRF-Token": csrf},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const result = await response.json();
    throw new Error(`${result.error || "No se pudo completar la operación."} (${response.status})`);
  }
  if (response.headers.get("Content-Type").startsWith("text/csv")) return response.blob();
  return response.json();
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function form(selector, action) {
  const element = $(selector);
  if (!element) return;
  element.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = element.querySelector("button[type=submit]");
    button.disabled = true;
    try { await action(Object.fromEntries(new FormData(element))); }
    catch (error) { notice(error.message, true); }
    finally { button.disabled = false; }
  });
}

async function tickets() {
  const data = await api("/api/tickets");
  const list = $("#ticket-list");
  list.replaceChildren();
  for (const ticket of data.tickets) {
    const row = node("div", undefined, "list-row");
    row.append(node("span", "↗", "file-icon"));
    const main = node("div", undefined, "row-main");
    main.append(node("strong", ticket.subject), node("small", `Solicitud #${ticket.id}`));
    const link = node("a", "Ver detalle →");
    link.href = `/?view=tickets&id=${encodeURIComponent(ticket.id)}`;
    row.append(main, link);
    list.append(row);
  }
  if (!data.tickets.length) list.append(node("p", "Todavía no tenés solicitudes.", "empty"));
  const id = new URLSearchParams(location.search).get("id");
  if (id) {
    const data = await api(`/api/tickets/${encodeURIComponent(id)}`);
    const detail = $("#ticket-detail");
    detail.hidden = false;
    detail.replaceChildren(node("p", `SOLICITUD #${data.ticket.id}`, "eyebrow"), node("h2", data.ticket.subject), node("p", data.ticket.description));
    if (data.assigned_operator) {
      detail.append(node("p", `Operador asignado: ${data.assigned_operator.username}`), node("p", `Identificador: ${data.assigned_operator.id}`));
    } else detail.append(node("p", "Tu solicitud está pendiente de asignación."));
  }
}

async function inbox() {
  const data = await api("/lab/inbox");
  const list = $("#inbox-list");
  list.replaceChildren();
  for (const message of data.messages) {
    const article = node("article", undefined, "message");
    article.append(node("h2", "Recuperación de cuenta"), node("small", new Date(message.created_at * 1000).toLocaleString("es-AR")), node("pre", message.body));
    list.append(article);
  }
  if (!data.messages.length) list.append(node("p", "No tenés mensajes. Las instrucciones de recuperación aparecerán aquí.", "empty"));
}

async function exportsList(query = "") {
  const data = await api(`/api/exports/search?q=${encodeURIComponent(query)}`);
  const list = $("#export-list");
  list.replaceChildren();
  for (const report of data.exports) {
    const row = node("div", undefined, "list-row");
    const main = node("div", undefined, "row-main");
    main.append(node("strong", report.title), node("small", report.is_confidential ? "Confidencial · Acceso restringido" : "General · Disponible para tu equipo"));
    const button = node("button", "Descargar ↓", "secondary");
    button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const blob = await api(`/api/exports/${encodeURIComponent(report.id)}/download`, {context: {purpose: "download"}});
        const url = URL.createObjectURL(blob);
        const link = node("a");
        link.href = url;
        link.download = `exportacion-${report.id}.csv`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        notice("La descarga está lista.");
      } catch (error) { notice(error.message, true); }
      finally { button.disabled = false; }
    });
    row.append(node("span", "CSV", "file-icon"), main, button);
    list.append(row);
  }
  if (!data.exports.length) list.append(node("p", "No encontramos archivos para esa búsqueda.", "empty"));
}

async function start() {
  const session = await api("/api/session");
  csrf = session.csrf_token;
  form("#login-form", async (body) => { await api("/api/auth/login", body); location.assign("/"); });
  form("#recovery-form", async (body) => notice((await api("/api/auth/recovery", body)).message));
  form("#reset-form", async (body) => {
    notice((await api("/api/auth/reset-password", body)).message);
    $("#reset-form").reset();
    csrf = (await api("/api/session")).csrf_token;
  });
  form("#search-form", async (body) => exportsList(body.q));
  $("#logout")?.addEventListener("click", async () => {
    try { await api("/api/auth/logout", {}); location.assign("/"); }
    catch (error) { notice(error.message, true); }
  });
  $("#refresh-inbox")?.addEventListener("click", () => inbox().catch(error => notice(error.message, true)));
  if ($("#ticket-list")) await tickets();
  if ($("#inbox-list")) await inbox();
  if ($("#export-list")) await exportsList();
}
start().catch(error => notice(error.message, true));
