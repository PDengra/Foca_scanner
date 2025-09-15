#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import sqlite3
import requests
import mimetypes
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin, urlparse

DB_PATH = os.path.expanduser("~/foca_scanner/data/scanner.db")
DOWNLOAD_DIR = os.path.expanduser("~/foca_scanner/downloads")

# Extensiones soportadas
ALLOWED_EXTENSIONS = [
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".txt", ".rtf"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0 Safari/537.36"
}

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


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


def already_scanned(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM files WHERE url = ?", (url,))
    count = c.fetchone()[0]
    conn.close()
    return count > 0


def save_file(domain, url, content, metadata_json):
    filename = url.split("/")[-1]
    ext = os.path.splitext(filename)[1].lower()
    local_path = os.path.join(DOWNLOAD_DIR, f"{domain}_{filename}")
    with open(local_path, "wb") as f:
        f.write(content)

    filesize = os.path.getsize(local_path)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO files (domain,url,local_path,filename,extension,filesize,scanned_at,metadata_json)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        domain,
        url,
        local_path,
        filename,
        ext,
        filesize,
        datetime.utcnow().isoformat(),
        json.dumps(metadata_json, ensure_ascii=False)
    ))
    conn.commit()
    conn.close()


def extract_metadata(local_path):
    metadata = {}
    ext = os.path.splitext(local_path)[1].lower()

    try:
        if ext == ".pdf":
            import fitz  # pymupdf
            doc = fitz.open(local_path)
            metadata = doc.metadata or {}
            doc.close()

        elif ext in [".docx"]:
            from docx import Document
            doc = Document(local_path)
            core = doc.core_properties
            metadata = {
                "Author": core.author,
                "Title": core.title,
                "Comments": core.comments,
                "Created": str(core.created),
                "Modified": str(core.modified)
            }

        elif ext in [".xlsx", ".xlsm", ".xltx"]:
            from openpyxl import load_workbook
            wb = load_workbook(local_path, read_only=True)
            props = wb.properties
            metadata = {
                "Author": props.creator,
                "Title": props.title,
                "Created": str(props.created),
                "Modified": str(props.modified)
            }

        # Si no hay librería específica, al menos guarda tamaño y nombre
        else:
            metadata = {"info": "No se pudieron extraer metadatos para este tipo de archivo"}
    except Exception as e:
        metadata = {"error": f"No se pudo extraer metadatos: {e}"}

    return metadata


def crawl(domain, base_url, max_depth=2):
    visited = set()
    to_visit = [(base_url, 0)]

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
                    continue  # Ignora dominios externos

                if any(href.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                    if not already_scanned(href):
                        try:
                            file_resp = requests.get(href, headers=HEADERS, timeout=15)
                            if file_resp.status_code == 200:
                                print(f"[DL] {href}")
                                local_metadata = extract_metadata(local_path := os.path.join(DOWNLOAD_DIR, os.path.basename(href)))
                                save_file(domain, href, file_resp.content, local_metadata)
                            else:
                                print(f"[WARN] {href} -> status {file_resp.status_code}")
                        except Exception as e:
                            print(f"[ERR] No se pudo descargar {href}: {e}")
                else:
                    if depth < max_depth:
                        to_visit.append((href, depth + 1))

        except Exception as e:
            print(f"[ERR] {url}: {e}")


def scan_domain(domain):
    print(f"\n=== Escaneando dominio: {domain} ===")
    base_url = f"https://{domain}"
    crawl(domain, base_url)


if __name__ == "__main__":
    init_db()
    if len(sys.argv) < 2:
        print("Uso: ./scanner.py domains.txt")
        sys.exit(1)

    domains_file = sys.argv[1]
    if not os.path.exists(domains_file):
        print(f"No se encontró {domains_file}")
        sys.exit(1)

    with open(domains_file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        scan_domain(domain)

    print("Escaneo completado.")
