from urllib.parse import urljoin
from utils.http import get

COMMON_PATHS = [
    "/backup/", "/backups/", "/admin/", "/administrator/",
    "/uploads/", "/files/", "/logs/", "/log/", "/tmp/",
    "/config/", "/conf/", "/.git/", "/.env",
    "/wp-content/uploads/", "/assets/", "/static/",
    "/db/", "/database/", "/sql/", "/dump/",
]

DIR_LISTING_SIGNATURES = ["index of /", "directory listing for", "parent directory"]


def check(session, url, reporter):
    reporter.section("Directory Listing / Rutas Sensibles")

    base = url.rstrip("/")
    found = False

    for path in COMMON_PATHS:
        target = urljoin(base + "/", path.lstrip("/"))
        response = get(session, target)
        if not response:
            continue

        text_lower = response.text.lower()

        if response.status_code == 200 and any(sig in text_lower for sig in DIR_LISTING_SIGNATURES):
            reporter.add(
                "dirlisting",
                "HIGH",
                f"Directory Listing activo: {path}",
                "El servidor lista el contenido del directorio",
                target,
            )
            found = True
        elif response.status_code == 200 and path in ("/.git/", "/.env"):
            reporter.add(
                "dirlisting",
                "HIGH",
                f"Archivo/directorio sensible expuesto: {path}",
                "Puede contener credenciales o código fuente",
                target,
            )
            found = True
        elif response.status_code == 200 and path in ("/admin/", "/administrator/"):
            reporter.add(
                "dirlisting",
                "MEDIUM",
                f"Panel de administración accesible: {path}",
                "Verificar si requiere autenticación",
                target,
            )
            found = True

    if not found:
        reporter.add("dirlisting", "INFO", "No se encontraron rutas sensibles expuestas", "", url)
