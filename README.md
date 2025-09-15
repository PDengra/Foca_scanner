🚀 Proyecto FOCA Scanner – Escaneo automático de dominios y metadatos

Me complace compartir un proyecto personal/profesional en el que he estado trabajando: FOCA Scanner, una herramienta de monitorización y análisis de documentos públicos disponibles en sitios web.

💡 Qué hace FOCA Scanner:

Escanea automáticamente dominios y detecta archivos PDF, DOCX, XLSX, PPTX.

Extrae metadatos críticos de cada archivo: Autor, Título, Fecha de creación/modificación, Software usado, Comentarios internos y rutas/plantillas.

Guarda toda la información en una base de datos SQLite para análisis posterior.

Interfaz web en tiempo real con Flask, mostrando los resultados a medida que se van escaneando los archivos.

Métricas integradas con Prometheus para seguimiento de volumen de datos y archivos procesados.

🛠 Tecnologías utilizadas:

Python: requests, BeautifulSoup, sqlite3, Flask, prometheus_client

Raspberry Pi como plataforma de ejecución

SQLite para almacenamiento de resultados

Hilos en Python para escaneo en segundo plano y dashboard interactivo

🛠 Estructura del proyecto foca_scanner

foca_scanner/

├─ scanner.py # Script principal para escaneo de dominios

├─ web_app.py # Interfaz web con dashboard en tiempo real

├─ requirements.txt # Dependencias Python

├─ README.md # Descripción del proyecto

├─ domains.txt # Lista de dominios de ejemplo

├─ .gitignore # Archivos/carpetas a ignorar

├─ data/ # Carpeta vacía para la base de datos

└─ downloads/ # Carpeta vacía para archivos descargados

🔍 Valor añadido:

Permite identificar documentos sensibles o información pública que podría ser relevante para auditorías de seguridad o análisis de datos.

Interfaz web en tiempo real, lo que facilita la visualización de resultados mientras el escaneo está en curso.

💻 Este proyecto combina mis conocimientos en desarrollo en Python, automatización de procesos y análisis de información digital, aplicables tanto en seguridad de la información como en gestión documental.

#Python #Flask #Prometheus #Seguridad #DocumentaciónDigital #RaspberryPi #Automatización #DesarrolloDeSoftware
