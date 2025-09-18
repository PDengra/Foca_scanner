#!/usr/bin/env python3
import os
import re
import json
import sqlite3
import threading
import requests
from flask import Flask, render_template_string, request, jsonify, send_from_directory
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from io import BytesIO
from PyPDF2 import PdfReader
import docx
from PIL import Image
from PIL.ExifTags import TAGS

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
    ".ppt", ".pptx", ".xls", ".xlsx", ".txt", ".csv", ".json",
    ".html", ".htm", ".jpg", ".jpeg", ".png", ".gif"
)

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
WINDOWS_PATH_REGEX = r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
SENSITIVE_KEYWORDS = ["password", "contraseña", "usuario", "internal", "confidencial", "secret", "key", "token"]

# Control del escaneo
scanning_threads = []
stop_scan_flag = threading.Event()

app = Flask(__name__)

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
    conn.commit()
    conn.close()

def insert_file_record(domain, url, local_path, filename, ext, filesize, metadata):
    selected_meta = {
        "Author": metadata.get("Author"),
        "LastModifiedBy": metadata.get("LastModifiedBy"),
        "Title": metadata.get("Title"),
        "Subject": metadata.get("Subject"),
        "CreateDate": metadata.get("CreateDate"),
        "ModifyDate": metadata.get("ModifyDate"),
        "Producer": metadata.get("Producer"),
        "Company": metadata.get("Company"),
        "Make": metadata.get("Make"),
        "Model": metadata.get("Model"),
        "DateTimeOriginal": metadata.get("DateTimeOriginal"),
        "GPSLatitude": metadata.get("GPSLatitude"),
        "GPSLongitude": metadata.get("GPSLongitude"),
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

def clear_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM files")
    conn.commit()
    conn.close()
    for f in os.listdir(DOWNLOAD_DIR):
        try:
            os.remove(os.path.join(DOWNLOAD_DIR, f))
        except:
            pass

# ---------------- EXTRACCIÓN DE METADATOS ----------------
def extract_metadata(local_path, content):
    meta = {}
    text = ""
    ext = os.path.splitext(local_path)[1].lower()
    try:
        if ext == ".pdf":
            try:
                reader = PdfReader(BytesIO(content))
                if reader.metadata:
                    for k, v in reader.metadata.items():
                        meta[k.replace("/", "")] = str(v)
                for page in reader.pages:
                    text += page.extract_text() or ""
            except:
                pass
        elif ext == ".docx":
            try:
                doc = docx.Document(BytesIO(content))
                core_props = doc.core_properties
                meta["Author"] = core_props.author
                meta["LastModifiedBy"] = core_props.last_modified_by
                meta["Title"] = core_props.title
                meta["Subject"] = core_props.subject
                meta["CreateDate"] = str(core_props.created) if core_props.created else None
                meta["ModifyDate"] = str(core_props.modified) if core_props.modified else None
                text = "\n".join([p.text for p in doc.paragraphs])
            except:
                pass
        elif ext in [".jpg", ".jpeg", ".tiff", ".tif", ".png"]:
            try:
                img = Image.open(BytesIO(content))
                exif = img._getexif()
                if exif:
                    for tag, value in exif.items():
                        decoded = TAGS.get(tag, tag)
                        meta[decoded] = str(value)
                        if decoded == "GPSInfo":
                            gps = value
                            meta["GPSLatitude"] = str(gps.get(2)) if gps.get(2) else None
                            meta["GPSLongitude"] = str(gps.get(4)) if gps.get(4) else None
            except:
                pass
    except:
        pass
    if text:
        meta["ExtractedText"] = text
    return meta

# ---------------- DETECCIÓN DE INFO SENSIBLE ----------------
def detect_sensitive_info(text):
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
    return findings

# ---------------- GUARDADO ----------------
def save_file(domain, url, content, metadata):
    filename = os.path.basename(urlparse(url).path)
    if not filename:
        filename = "index.html"
    ext = os.path.splitext(filename)[1].lower()
    local_path = os.path.join(DOWNLOAD_DIR, filename)
    with open(local_path, "wb") as f:
        f.write(content)
    metadata["SensitiveFindings"] = []
    if "ExtractedText" in metadata:
        metadata["SensitiveFindings"] = detect_sensitive_info(metadata["ExtractedText"])
    if any(metadata.get(k) for k in ["Author","LastModifiedBy","Title","Subject","CreateDate","ModifyDate","Producer","Company","Make","Model","DateTimeOriginal"]):
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
    while to_visit and not stop_scan_flag.is_set():
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
                                metadata = extract_metadata(
                                    os.path.join(DOWNLOAD_DIR, os.path.basename(parsed.path)),
                                    file_resp.content
                                )
                                save_file(domain, href, file_resp.content, metadata)
                        except:
                            pass
                else:
                    if depth < max_depth:
                        to_visit.append((href, depth + 1))
        except:
            pass

def scan_domain(domain):
    base_url = f"http://{domain}"
    stop_scan_flag.clear()
    crawl(domain, base_url)

# ---------------- FLASK ----------------
TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>FOCA Scanner</title>
<style>
table, th, td { border: 1px solid black; border-collapse: collapse; padding: 5px; vertical-align: top;}
th { background-color: #f0f0f0; }
pre { margin:0; }
</style>
</head>
<body>
<h1>FOCA Scanner</h1>

<h3>Escanear dominio</h3>
<form method="POST" action="/scan">
    <input type="text" name="domain" placeholder="example.com" required>
    <button type="submit">Escanear</button>
    <button type="button" onclick="stopScan()">Detener escaneo</button>
</form>

<h3>Subir archivo para analizar</h3>
<form method="POST" action="/upload_file" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <button type="submit">Subir y analizar</button>
</form>

<form method="POST" action="/clear" style="margin-top:10px;">
    <button type="submit">Limpiar</button>
</form>

<h3>Archivos con metadatos o info sensible</h3>
<div id="scan-status"></div>
<table>
<thead>
<tr><th>Archivo</th><th>Metadatos</th><th>Información sensible</th></tr>
</thead>
<tbody id="file-list"></tbody>
</table>

<div>
<button onclick="prevPage()">Anterior</button>
<span id="page-info"></span>
<button onclick="nextPage()">Siguiente</button>
</div>

<script>
let currentPage = 1;
let totalPages = 1;
let perPage = 5;

async function fetchFiles() {
    const res = await fetch(`/files_filtered?page=${currentPage}&per_page=${perPage}`);
    const data = await res.json();
    const tbody = document.getElementById("file-list");
    tbody.innerHTML = "";
    totalPages = data.total_pages;
    document.getElementById("page-info").textContent = `Página ${currentPage} de ${totalPages}`;
    document.getElementById("scan-status").textContent = data.scanning ? "Escaneo en curso..." : "Escaneo completado";
    data.files.forEach(f => {
        const tr = document.createElement("tr");
        const tdFile = document.createElement("td");
        const link = document.createElement("a");
        link.href = `/download/${f.filename}`;
        link.textContent = f.filename;
        link.target="_blank";
        tdFile.appendChild(link);
        tr.appendChild(tdFile);

        const tdMeta = document.createElement("td");
        const metaPre = document.createElement("pre");
        metaPre.textContent = Object.entries(f.metadata).filter(([k,v])=>v).map(([k,v])=>`${k}: ${v}`).join("\\n");
        tdMeta.appendChild(metaPre);
        tr.appendChild(tdMeta);

       const tdSens = document.createElement("td");
       const sensList = f.sensitive || [];
       if (sensList.length === 0) {
          tdSens.textContent = "—";
       } else {
          tdSens.innerHTML = sensList.map(s => {
               return s.values.map(v => `<div>${s.type}: ${v}</div>`).join("");
          }).join("");
       }
       tr.appendChild(tdSens);

        tbody.appendChild(tr);
    });
}

function nextPage(){
    if(currentPage<totalPages){ currentPage++; fetchFiles(); }
}
function prevPage(){
    if(currentPage>1){ currentPage--; fetchFiles(); }
}

function stopScan(){
    fetch("/stop_scan", {method:"POST"});
}

setInterval(fetchFiles, 3000);
fetchFiles();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE)

@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form.get("domain")
    if domain:
        t = threading.Thread(target=scan_domain, args=(domain,), daemon=True)
        scanning_threads.append(t)
        t.start()
    return ("", 204)

@app.route("/stop_scan", methods=["POST"])
def stop_scan():
    stop_scan_flag.set()
    return ("",204)

@app.route("/clear", methods=["POST"])
def clear():
    stop_scan_flag.set()
    clear_data()
    return ("", 204)

@app.route("/files_filtered")
def files_filtered():
    page = int(request.args.get("page",1))
    per_page = int(request.args.get("per_page",5))
    offset = (page-1)*per_page
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT filename, metadata_json FROM files ORDER BY scanned_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    result = []
    for row in c.fetchall():
        filename, metadata_json = row
        metadata = json.loads(metadata_json)
        sensitive = metadata.get("SensitiveFindings", [])
        meta_keys = ["Author","LastModifiedBy","Title","Subject","CreateDate","ModifyDate","Producer","Company","Make","Model","DateTimeOriginal","GPSLatitude","GPSLongitude"]
        has_meta = any(metadata.get(k) for k in meta_keys)
        if has_meta or sensitive:
            result.append({"filename": filename, "metadata": metadata, "sensitive": sensitive})
    # total count
    c.execute("SELECT COUNT(*) FROM files")
    total_count = c.fetchone()[0]
    conn.close()
    total_pages = max(1,(total_count+per_page-1)//per_page)
    scanning = any(t.is_alive() for t in scanning_threads)
    return jsonify({"files": result,"total_pages":total_pages,"scanning":scanning})

@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)

@app.route("/upload_file", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if file:
        filename = file.filename
        local_path = os.path.join(DOWNLOAD_DIR, filename)
        content = file.read()
        with open(local_path,"wb") as f:
            f.write(content)
        metadata = extract_metadata(local_path, content)
        save_file("LOCAL_UPLOAD", f"file://{filename}", content, metadata)
    return ("",204)

if __name__ == "__main__":
    init_db()
    print("[INFO] FOCA Scanner corriendo en http://0.0.0.0:5000 ...")
    app.run(host="0.0.0.0", port=5000, debug=True)
