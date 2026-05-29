SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HIGH",
        "HSTS ausente — sin protección contra downgrade a HTTP",
    ),
    "Content-Security-Policy": (
        "HIGH",
        "CSP ausente — mayor riesgo de XSS",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "X-Frame-Options ausente — vulnerable a Clickjacking",
    ),
    "X-Content-Type-Options": (
        "LOW",
        "X-Content-Type-Options ausente — riesgo de MIME sniffing",
    ),
    "Referrer-Policy": (
        "LOW",
        "Referrer-Policy ausente — puede filtrar URLs internas",
    ),
    "Permissions-Policy": (
        "LOW",
        "Permissions-Policy ausente — sin restricción de APIs del navegador",
    ),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def check(session, url, reporter):
    reporter.section("Cabeceras de Seguridad")
    from utils.http import get

    response = get(session, url)
    if not response:
        reporter.add("headers", "INFO", "No se pudo conectar al servidor", "", url)
        return

    found_any = False
    for header, (severity, detail) in SECURITY_HEADERS.items():
        if header not in response.headers:
            reporter.add("headers", severity, f"Falta: {header}", detail, url)
            found_any = True

    for header in LEAKY_HEADERS:
        if header in response.headers:
            value = response.headers[header]
            reporter.add(
                "headers",
                "LOW",
                f"Header informativo expuesto: {header}",
                f"Valor: {value} — revela tecnología del servidor",
                url,
            )
            found_any = True

    if not found_any:
        reporter.add("headers", "INFO", "Cabeceras de seguridad correctamente configuradas", "", url)
