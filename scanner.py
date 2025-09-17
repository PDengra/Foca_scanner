#!/usr/bin/env python3
import os
import re
import json
import sqlite3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from io import BytesIO
from PyPDF2 import PdfReader
import docx
from PIL import Image
from PIL.ExifTags import TAGS
from flask import Flask, render_template_string, request, redirect, url_for, flash

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")
DB_PATH = os.path.join(DATA_DIR, "scanner.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; FOCA-Scanner/3.0)"}
ALLOWED_EXTENSIONS = (
    ".pdf", ".doc", ".docx", ".dot", ".dotx",
    ".ppt", ".pptx", ".pps", ".ppsx",
    ".xls", ".xlsx", ".xlsm", ".csv", ".ods", ".odt", ".odp",
    ".rtf", ".txt", ".xml", ".json", ".yaml", ".yml",
    ".html", ".htm",
    ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".gif", ".svg", ".webp",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2",
    ".conf", ".ini", ".log", ".py", ".js", ".php", ".sh", ".bat", ".ps1"
)

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
WINDOWS_PATH_REGEX = r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
SENSITIVE_KEYWORDS = ["password", "contraseña", "usuario", "internal", "confidencial", "secret", "key", "token"]

# Opcional para Word antiguos / Excel / LibreOffice
try:
    import fitz
except ImportError:
    fitz = None
try:
    import olefile
except ImportError:
    olefile = None
try:
    import openpyxl
except ImportError:
    openpyxl = None
try:
    from odf.opendocument import load as odf_load
except ImportError:
    odf_load = None

# ---------------- BASE DE DATOS ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            url TEXT,
            local_path TEXT,
            filename TEXT,
            extension TEXT,
            filesize INTEGER,
            scanned_at TEXT,
            metadata_json TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_domain ON files(domain)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            last_scanned TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_file_record(domain, url, local_path, filename, ext, filesize, metadata):
    selected_meta = {
        "Author": metadata.get("Author"),
        "Title": metadata.get("Title"),
        "CreateDate": metadata.get("CreateDate"),
        "ModifyDate": metadata.get("ModifyDate"),
        "CreatorTool": metadata.get("CreatorTool"),
        "Comments": metadata.get("Comments"),
        "Template": metadata.get("Template"),
        "SourceFile": metadata.get("SourceFile"),
        "ExtractedText": metadata.get("ExtractedText"),
        "SensitiveFindings": metadata.get("SensitiveFindings")
    }
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO files (domain,url,local_path,filename,extension,filesize,scanned_at,metadata_json)
        VALUES (?,?,?,?,?,?,?,?)
    """, (domain, url, local_path, filename, ext, filesize,
          datetime.utcnow().isoformat(), json.dumps(selected_meta, ensure_ascii=False)))
    conn.commit()
    conn.close()

# ---------------- METADATOS ----------------
def extract_metadata(local_path, content):
    meta = {}
    text = ""
    ext = os.path.splitext(local_path)[1].lower()
    try:
        if ext == ".pdf" and fitz:
            try:
                doc = fitz.open(stream=content, filetype="pdf")
                meta.update(doc.metadata or {})
                for page in doc:
                    text += page.get_text() or ""
            except Exception:
                pass
        if ext == ".pdf":
            try:
                reader = PdfReader(BytesIO(content))
                if reader.metadata:
                    for k, v in reader.metadata.items():
                        meta[k.replace("/", "")] = str(v)
                for page in reader.pages:
                    text += page.extract_text() or ""
            except Exception:
                pass
        elif ext == ".docx":
            try:
                doc = docx.Document(BytesIO(content))
                core_props = doc.core_properties
                meta["Author"] = core_props.author
                meta["Title"] = core_props.title
                meta["CreateDate"] = str(core_props.created) if core_props.created else None
                meta["ModifyDate"] = str(core_props.modified) if core_props.modified else None
                text = "\n".join([p.text for p in doc.paragraphs])
            except Exception:
                pass
    except Exception:
        pass
    if text:
        meta["ExtractedText"] = text
    return meta

# ---------------- INFO SENSIBLE ----------------
def detect_sensitive_info(text, url):
    findings = []
    emails = re.findall(EMAIL_REGEX, text)
    if emails:
        findings.append({"type": "email", "values": list(set(emails))})
    paths = re.findall(WINDOWS_PATH_REGEX, text)
    if paths:
        findings.append({"type": "path", "values": list(set(paths))})
    for kw in SENSITIVE_KEYWORDS:
        if re.search(kw, text, re.IGNORECASE):
            findings.append({"type": "keyword", "values": [kw]})
    if findings:
        print(f"[ALERTA] Posible info sensible en {url}: {findings}")
    return findings

# ---------------- GUARDADO ----------------
def save_file(domain, url, content, metadata):
    filename = os.path.basename(urlparse(url).path)
    ext = os.path.splitext(filename)[1].lower()
    local_path = os.path.join(DOWNLOAD_DIR, filename)
    with open(local_path, "wb") as f:
        f.write(content)
    metadata["SensitiveFindings"] = []
    if "ExtractedText" in metadata:
        metadata["SensitiveFindings"] = detect_sensitive_info(metadata["ExtractedText"], url)
    insert_file_record(domain, url, local_path, filename, ext, len(content), metadata)

# ---------------- CRAWLER ----------------
def already_scanned(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM files WHERE url=?", (url,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def crawl(domain, base_url, max_depth=2):
    visited = set()
    to_visit = [(base_url.rstrip("/"), 0)]
    while to_visit:
        url, depth = to_visit.pop()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link["href"])
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != urlparse(base_url).netloc:
                    continue
                if any(href.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                    if not already_scanned(href):
                        try:
                            file_resp = requests.get(href, headers=HEADERS, timeout=15)
                            if file_resp.status_code == 200:
                                print(f"[DL] {href}")
                                metadata = extract_metadata(
                                    os.path.join(DOWNLOAD_DIR, os.path.basename(parsed.path)),
                                    file_resp.content
                                )
                                save_file(domain, href, file_resp.content, metadata)
                        except Exception as e:
                            print(f"[ERR] {href}: {e}")
                else:
                    if depth < max_depth:
                        to_visit.append((href, depth + 1))
        except Exception as e:
            print(f"[ERR] {url}: {e}")

def scan_domain(domain):
    base_url = f"http://{domain}"
    crawl(domain, base_url)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO domains (domain, last_scanned) VALUES (?,?)", (domain, datetime.utcnow().isoformat()))
    c.execute("UPDATE domains SET last_scanned=? WHERE domain=?", (datetime.utcnow().isoformat(), domain))
    conn.commit()
    conn.close()

# ---------------- FLASK WEB ----------------
app = Flask(__name__)
app.secret_key = "foca_secret"

TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>FOCA Scanner</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-4">
<h1 class="text-center">📊 FOCA Scanner</h1>

<form class="d-flex mb-3" method="POST" action="/">
<input class="form-control me-2" type="text" name="new_domain" placeholder="Añadir dominio" required>
<button class="btn btn-success" type="submit">Añadir</button>
</form>

{% with messages = get_flashed_messages() %}
{% if messages %}
  <div class="alert alert-info">{{ messages[0] }}</div>
{% endif %}
{% endwith %}

<h3>Dominios escaneados:</h3>
<table class="table table-striped table-sm">
<thead class="table-dark"><tr><th>Dominio</th><th>Último Escaneo</th><th>Acciones</th></tr></thead>
<tbody>
{% for d in domains %}
<tr>
<td>{{ d['domain'] }}</td>
<td>{{ d['last_scanned'] or '-' }}</td>
<td>
<form style="display:inline" method="POST" action="/scan/{{ d['domain'] }}">
<button class="btn btn-primary btn-sm">Escanear</button>
</form>
<form style="display:inline" method="POST" action="/clear/{{ d['domain'] }}">
<button class="btn btn-danger btn-sm">Limpiar descargas</button>
</form>
</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET","POST"])
def index():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == "POST":
        new_domain = request.form.get("new_domain")
        if new_domain:
            c.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?)", (new_domain,))
            conn.commit()
            flash(f"Dominio {new_domain} añadido")
        return redirect(url_for("index"))
    c.execute("SELECT * FROM domains ORDER BY id DESC")
    domains = [dict(row) for row in map(dict, c.fetchall())]
    conn.close()
    return render_template_string(TEMPLATE, domains=domains)

@app.route("/scan/<domain>", methods=["POST"])
def scan(domain):
    scan_domain(domain)
    flash(f"Dominio {domain} escaneado")
    return redirect(url_for("index"))

@app.route("/clear/<domain>", methods=["POST"])
def clear(domain):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT local_path FROM files WHERE domain=?", (domain,))
    paths = c.fetchall()
    for p in paths:
        path = p[0]
        if os.path.exists(path):
            os.remove(path)
    c.execute("DELETE FROM files WHERE domain=?", (domain,))
    conn.commit()
    conn.close()
    flash(f"Archivos y registros del dominio {domain} eliminados")
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
