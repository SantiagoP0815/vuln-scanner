import requests
from urllib.parse import urlparse, urljoin

TIMEOUT = 10
HEADERS = {
    "User-Agent": "VulnScanner/1.0 (Authorized Security Testing)",
}


def create_session():
    session = requests.Session()
    session.headers.update(HEADERS)
    session.max_redirects = 3
    return session


def get(session, url, params=None, allow_redirects=True):
    try:
        return session.get(
            url,
            params=params,
            timeout=TIMEOUT,
            allow_redirects=allow_redirects,
            verify=False,
        )
    except requests.RequestException:
        return None


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.geturl()


def extract_forms(html, base_url):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(base_url, action) if action else base_url
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            value = tag.get("value", "test")
            if name:
                inputs.append({"name": name, "value": value})
        forms.append({"action": action_url, "method": method, "inputs": inputs})
    return forms
