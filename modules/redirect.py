from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.http import get

REDIRECT_PARAMS = ["url", "redirect", "next", "return", "goto", "redir", "target", "dest", "destination", "link"]
TEST_URL = "https://example.com"


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check(session, url, reporter):
    reporter.section("Open Redirect")

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())
    params_to_test = list(set(existing_params + REDIRECT_PARAMS))

    found = False
    for param in params_to_test:
        test_url = _inject_param(url, param, TEST_URL)
        response = get(session, test_url, allow_redirects=False)
        if response and response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if TEST_URL in location or "example.com" in location:
                reporter.add(
                    "redirect",
                    "MEDIUM",
                    f"Open Redirect en parámetro: {param}",
                    f"Redirige a: {location}",
                    test_url,
                )
                found = True

    if not found:
        reporter.add("redirect", "INFO", "No se detectaron redirecciones abiertas", "", url)
