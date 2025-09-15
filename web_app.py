#!/usr/bin/env python3
import os
import sqlite3
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, Response, jsonify
from prometheus_client import CollectorRegistry, Gauge, generate_latest, CONTENT_TYPE_LATEST

# ---------------- Configuración ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "scanner.db")

app = Flask(__name__)
SCAN_STATUS = {}  # {domain: {"status": "in_progress"/"done", "rows": []}}

# ---------------- HTML Templates ----------------
INDEX_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>FOCA Scanner - Buscar dominio</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
label { font-weight: bold; }
input { padding: 5px; margin-right: 10px; }
button { padding: 5px 10px; }
</style>
</head>
<body>
<h1>FOCA Scanner</h1>
<form action="/scan" method="POST">
  <label>Dominio a escanear:</label>
  <input type="text" name="domain" placeholder="example.com" required>
  <button type="submit">Escanear</button>
</form>
<p>Las métricas de Prometheus están disponibles en <code>/metrics</code></p>
</body>
</html>
"""

RESULTS_TEMPLATE = """
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>FOCA Scanner - Resultados {{ domain }}</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }
th { background-color: #eee; }
</style>
</head>
<body>
<h1>Resultados del dominio: {{ domain }}</h1>
<p id="status">Escaneo en progreso...</p>
<table id="resultsTable">
<tr>
<th>Archivo</th><th>URL</th><th>Tamaño (bytes)</th>
<th>Autor</th><th>Título</th><th>Creación</th><th>Modificación</th>
<th>Software</th><th>Comentarios</th><th>Plantilla/Ruta</th>
</tr>
</table>
<p><a href="/">Volver a buscar otro dominio</a></p>

<script>
async function updateTable() {
    const response = await fetch("/status/{{ domain }}");
    const data = await response.json();
    const table = document.getElementById("resultsTable");
    table.innerHTML = `<tr>
<th>Archivo</th><th>URL</th><th>Tamaño (bytes)</th>
<th>Autor</th><th>Título</th><th>Creación</th><th>Modificación</th>
<th>Software</th><th>Comentarios</th><th>Plantilla/Ruta</th>
</tr>`;
    for (const row of data.rows) {
        const meta = row[3] || {};
        table.insertAdjacentHTML("beforeend", `
<tr>
<td>${row[0]}</td>
<td><a href="${row[1]}" target="_blank">Abrir</a></td>
<td>${row[2]}</td>
<td>${meta.author || ""}</td>
<td>${meta.title || ""}</td>
<td>${meta.createdate || meta.created || ""}</td>
<td>${meta.modifydate || meta.modified || ""}</td>
<td>${meta.creatortool || ""}</td>
<td>${meta.comments || ""}</td>
<td>${meta.template || meta.sourcefile || ""}</td>
</tr>
`);
    }
    document.getElementById("status").textContent = data.status === "done" ? "Escaneo completado ✅" : "Escaneo en progreso...";
}
setInterval(updateTable, 2000);
</script>
</body>
</html>
"""

# ---------------- Funciones auxiliares ----------------
def get_files(domain=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if domain:
        c.execute("SELECT filename, url, filesize, metadata_json FROM files WHERE domain=? ORDER BY scanned_at DESC", (domain,))
    else:
        c.execute("SELECT domain, filename, url, filesize, metadata_json FROM files ORDER BY scanned_at DESC")
    raw_rows = c.fetchall()
    conn.close()

    rows = []
    for r in raw_rows:
        if domain:
            filename, url, filesize, metadata_json = r
        else:
            _, filename, url, filesize, metadata_json = r

        # ✅ Normalizar metadatos
        try:
            meta = json.loads(metadata_json) if metadata_json else {}
            if isinstance(meta, dict):
                meta = {k.lower(): v for k, v in meta.items()}  # 🔧 Forzamos claves minúsculas
            else:
                meta = {}
        except json.JSONDecodeError:
            meta = {}

        rows.append((filename, url, filesize, meta))
    return rows

def crawl_domain(domain):
    from scanner import scan_domain
    SCAN_STATUS[domain] = {"status": "in_progress", "rows": []}
    scan_domain(domain)
    rows = get_files(domain)
    SCAN_STATUS[domain] = {"status": "done", "rows": rows}

# ---------------- Rutas Flask ----------------
@app.route("/")
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form["domain"]
    threading.Thread(target=crawl_domain, args=(domain,), daemon=True).start()
    return redirect(url_for("results", domain=domain))

@app.route("/results/<domain>")
def results(domain):
    return render_template_string(RESULTS_TEMPLATE, domain=domain)

@app.route("/status/<domain>")
def status(domain):
    data = SCAN_STATUS.get(domain, {"status": "pending", "rows": []})
    return jsonify(data)

@app.route("/metrics")
def metrics():
    rows = get_files()
    total_files = len(rows)
    total_bytes = sum(r[2] for r in rows)

    registry = CollectorRegistry()
    g_files = Gauge("foca_total_files", "Total files scanned", registry=registry)
    g_bytes = Gauge("foca_total_bytes", "Total bytes downloaded", registry=registry)
    g_files.set(total_files)
    g_bytes.set(total_bytes)

    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

# ---------------- Main ----------------
if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000)

