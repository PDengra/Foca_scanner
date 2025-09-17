#!/usr/bin/env python3
import sqlite3
import json
import os
from flask import Flask, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "scanner.db")

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>FOCA Scanner - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .metadata-cell {
            max-height: 120px;
            overflow-y: auto;
            font-size: 0.85rem;
        }
        /* Botones de scroll */
        .scroll-btn {
            position: fixed;
            right: 20px;
            width: 40px;
            height: 40px;
            background-color: #0d6efd;
            color: white;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
        }
        .scroll-btn:hover {
            background-color: #0b5ed7;
        }
        #scroll-up { top: 80px; }
        #scroll-down { top: 130px; }
    </style>
</head>
<body class="bg-light">
<div class="container mt-4 mb-5">
    <h1 class="text-center mb-4">📊 FOCA Scanner Dashboard</h1>

    <form class="d-flex justify-content-center mb-3" method="GET">
        <input class="form-control w-50 me-2" type="text" name="q" value="{{ query }}" placeholder="Buscar dominio o archivo...">
        <button class="btn btn-primary me-2" type="submit">Buscar</button>
        <a href="/?clear=1" class="btn btn-secondary">Limpiar</a>
    </form>

    {% if show_results %}
        {% if total_results == 0 %}
            <div class="alert alert-warning text-center">
                <b>⚠ No se encontraron resultados para tu búsqueda.</b>
            </div>
        {% else %}
            <p class="text-muted text-center">
                Mostrando <b>{{ start+1 }}</b> - <b>{{ end_display }}</b> de <b>{{ total_results }}</b> resultados
            </p>

            <div class="table-responsive">
                <table class="table table-striped table-hover table-sm">
                    <thead class="table-dark">
                        <tr>
                            <th>Dominio</th>
                            <th>Archivo</th>
                            <th>Metadatos</th>
                            <th>Hallazgos Sensibles</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for row in page_files %}
                        <tr>
                            <td>{{ row['domain'] }}</td>
                            <td>
                                <a href="{{ row['url'] }}" target="_blank">{{ row['filename'] }}</a><br>
                                <small class="text-muted">{{ row['extension'] }} | {{ row['filesize'] }} bytes</small>
                            </td>
                            <td class="metadata-cell">
                                {% if row['metadata'] %}
                                    {% for k, v in row['metadata'].items() %}
                                        {% if k not in ["SensitiveFindings", "ExtractedText"] and v %}
                                            <b>{{ k }}:</b> {{ v }}<br>
                                        {% endif %}
                                    {% endfor %}
                                {% else %}
                                    <i class="text-muted">Sin metadatos</i>
                                {% endif %}
                            </td>
                            <td>
                                {% if row['metadata'] and row['metadata'].get("SensitiveFindings") %}
                                    {% for finding in row['metadata']["SensitiveFindings"] %}
                                        <div class="alert alert-danger p-1 m-1">
                                            <b>{{ finding["type"] }}</b>: {{ ", ".join(finding["values"]) }}
                                        </div>
                                    {% endfor %}
                                {% else %}
                                    <span class="text-muted">Sin hallazgos</span>
                                {% endif %}
                            </td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>

            {% if total_pages > 1 %}
            <nav>
                <ul class="pagination justify-content-center">
                    {% if page > 1 %}
                    <li class="page-item">
                        <a class="page-link" href="{{ pagination_url(page-1) }}">«</a>
                    </li>
                    {% endif %}

                    {% for p in pages_to_show %}
                    <li class="page-item {% if p == page %}active{% endif %}">
                        <a class="page-link" href="{{ pagination_url(p) }}">{{ p }}</a>
                    </li>
                    {% endfor %}

                    {% if page < total_pages %}
                    <li class="page-item">
                        <a class="page-link" href="{{ pagination_url(page+1) }}">»</a>
                    </li>
                    {% endif %}
                </ul>
            </nav>
            {% endif %}
        {% endif %}
    {% endif %}
</div>

<!-- Botones de scroll -->
<button class="scroll-btn" id="scroll-up" title="Subir">&#9650;</button>
<button class="scroll-btn" id="scroll-down" title="Bajar">&#9660;</button>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.getElementById("scroll-up").addEventListener("click", () => {
    window.scrollBy({ top: -300, behavior: 'smooth' });
});
document.getElementById("scroll-down").addEventListener("click", () => {
    window.scrollBy({ top: 300, behavior: 'smooth' });
});
</script>
</body>
</html>
"""

def get_files(query=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if query:
        query_like = f"%{query}%"
        c.execute(
            "SELECT domain, url, filename, extension, filesize, metadata_json FROM files "
            "WHERE domain LIKE ? OR filename LIKE ? ORDER BY scanned_at DESC",
            (query_like, query_like)
        )
    else:
        c.execute("SELECT domain, url, filename, extension, filesize, metadata_json FROM files ORDER BY scanned_at DESC")
    rows = c.fetchall()
    conn.close()

    files = []
    for r in rows:
        try:
            metadata = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
        except json.JSONDecodeError:
            metadata = {}
        files.append({
            "domain": r["domain"],
            "url": r["url"],
            "filename": r["filename"],
            "extension": r["extension"],
            "filesize": r["filesize"],
            "metadata": metadata
        })
    return files

@app.route("/")
def dashboard():
    if request.args.get("clear") == "1":
        return render_template_string(TEMPLATE, show_results=False, query="", page_files=[])

    page = request.args.get("page", 1, type=int)
    query = request.args.get("q", "")

    files = get_files(query)
    per_page = 8
    total_results = len(files)
    total_pages = max(1, (total_results + per_page - 1) // per_page)

    start = (page - 1) * per_page
    end = start + per_page
    end_display = min(end, total_results)

    page_files = files[start:end]

    window_size = 5
    half = window_size // 2
    start_page = max(1, page - half)
    end_page = min(total_pages, start_page + window_size - 1)
    start_page = max(1, end_page - window_size + 1)
    pages_to_show = list(range(start_page, end_page + 1))

    def pagination_url(p):
        if query:
            return f"/?page={p}&q={query}"
        return f"/?page={p}"

    return render_template_string(
        TEMPLATE,
        show_results=True,
        page_files=page_files,
        page=page,
        total_pages=total_pages,
        pages_to_show=pages_to_show,
        query=query,
        pagination_url=pagination_url,
        total_results=total_results,
        start=start,
        end=end,
        end_display=end_display
    )

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"[ERROR] No se encontró la base de datos en {DB_PATH}. Ejecuta scanner.py primero.")
    else:
        print("[INFO] FOCA Scanner Dashboard corriendo en http://0.0.0.0:5000 ...")
        app.run(host="0.0.0.0", port=5000, debug=True)

