import requests
from .checks import ALL_CHECKS

TIMEOUT = 15
UA = "MoneyScan/0.1 (+passive; authorized testing only)"

def fetch(url):
    return requests.get(url, headers={"User-Agent": UA},
                        timeout=TIMEOUT, allow_redirects=True)

def scan(url):
    resp = fetch(url)
    html = resp.text or ""

    findings = []
    for module in ALL_CHECKS:
        try:
            findings.extend(module.run(url, resp, html))
        except Exception as e:
            findings.append({
                "id": f"check-error-{module.NAME}",
                "title": f"Check failed: {module.NAME}",
                "severity": "info",
                "category": "internal",
                "evidence": str(e),
                "why_money": "N/A",
                "fix": "N/A",
            })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    return {
        "url": url,
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", ""),
        "findings": findings,
    }
