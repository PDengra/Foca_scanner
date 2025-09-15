#!/usr/bin/env python3
import os
import requests
import sqlite3
import json
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin, urlparse

# ---------------- Configuración ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "scanner.db")
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# ---------------- Funciones ----------------
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

def download_file(url, domain):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        filename = os.path.basename(urlparse(url).path)
        local_path = os.path.join(DOWNLOADS_DIR, f"{domain}_{filename}")
        with open(local_path, "wb") as f:
            f.write(r.content)
        filesize = os.path.getsize(local_path)
        return local_path, filename, filesize
    except:
        return None, None, 0

def extract_metadata(local_path):
    """
    Extrae metadatos básicos usando python-magic o metadata de PDFs, DOCX, etc.
    Aquí se simula un ejemplo de metadatos.
    """
    return {
        "Author": "Desconocido",
        "Title": os.path.basename(local_path),
        "CreateDate": datetime.utcnow().isoformat(),
        "ModifyDate": datetime.utcnow().isoformat(),
        "CreatorTool": "FOCA Scanner Simulado",
        "Comments": "",
        "Template": "",
        "SourceFile": local_path
    }

def insert_file_record(domain, url, local_path, filename, ext, filesize, metadata_json, scan_status=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO files (domain, url, local_path, filename, extension, filesize, scanned_at, metadata_json)
        VALUES (?,?,?,?,?,?,?,?)
    """, (domain, url, local_path, filename, ext, filesize, datetime.utcnow().isoformat(), json.dumps(metadata_json, ensure_ascii=False)))
    conn.commit()
    conn.close()
    if scan_status is not None:
        # Actualiza el estado en tiempo real para el dashboard
        scan_status["rows"].append((filename, url, filesize, metadata_json))

def scan_domain(domain, scan_status=None):
    """
    Escanea un solo dominio: descarga enlaces de archivos y guarda metadatos.
    """
    if scan_status is not None:
        scan_status["status"] = "in_progress"
        scan_status["rows"] = []

    print(f"=== Escaneando dominio: {domain} ===")
    try:
        r = requests.get(f"http://{domain}", timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"[ERROR] No se pudo acceder a {domain}: {e}")
        if scan_status is not None:
            scan_status["status"] = "done"
        return

    soup = BeautifulSoup(r.text, "html.parser")
    links = [urljoin(f"http://{domain}", a.get("href")) for a in soup.find_all("a", href=True)]
    file_links = [l for l in links if any(l.lower().endswith(ext) for ext in [".pdf", ".docx", ".xlsx", ".pptx"])]

    for url in file_links:
        local_path, filename, filesize = download_file(url, domain)
        if not local_path:
            continue
        ext = os.path.splitext(filename)[1].lower()
        metadata = extract_metadata(local_path)
        insert_file_record(domain, url, local_path, filename, ext, filesize, metadata, scan_status)

    print(f"=== Escaneo completado: {domain} ===")
    if scan_status is not None:
        scan_status["status"] = "done"

# ---------------- Main ----------------
if __name__ == "__main__":
    init_db()
    import sys
    if len(sys.argv) > 1:
        for d in sys.argv[1:]:
            scan_domain(d)
