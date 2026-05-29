from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.http import get, extract_forms

PAYLOADS = ["'", "''", "`", "1' OR '1'='1", "1 OR 1=1--", "' OR 1=1#"]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "ora-",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlite_error",
    "syntax error",
]


def _has_sql_error(text):
    lower = text.lower()
    return any(sig in lower for sig in ERROR_SIGNATURES)


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check(session, url, reporter):
    reporter.section("SQL Injection")

    base_response = get(session, url)
    if not base_response:
        reporter.add("sqli", "INFO", "No se pudo conectar", "", url)
        return

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    found = False

    for param in params:
        for payload in PAYLOADS:
            test_url = _inject_param(url, param, payload)
            response = get(session, test_url)
            if response and _has_sql_error(response.text):
                reporter.add(
                    "sqli",
                    "HIGH",
                    f"SQL Injection (error-based) en parámetro: {param}",
                    f"Payload: {payload} — error SQL visible en respuesta",
                    test_url,
                )
                found = True
                break

    forms = extract_forms(base_response.text, url)
    for form in forms:
        for inp in form["inputs"]:
            for payload in PAYLOADS:
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "post":
                        response = session.post(form["action"], data=data, timeout=10, verify=False)
                    else:
                        response = get(session, form["action"], params=data)
                    if response and _has_sql_error(response.text):
                        reporter.add(
                            "sqli",
                            "HIGH",
                            f"SQL Injection en formulario — campo: {inp['name']}",
                            f"Action: {form['action']} | Payload: {payload}",
                            form["action"],
                        )
                        found = True
                        break
                except Exception:
                    continue

    if not found:
        reporter.add("sqli", "INFO", "No se detectaron errores SQL en los puntos probados", "", url)
