NAME = "Security headers"

REQUIRED = {
    "strict-transport-security": "high",
    "content-security-policy": "high",
    "x-frame-options": "medium",
    "x-content-type-options": "low",
    "referrer-policy": "low",
}

def run(url, response, html):
    findings = []
    h = {k.lower(): v for k, v in response.headers.items()}

    for header, severity in REQUIRED.items():
        if header not in h:
            findings.append({
                "id": f"missing-header-{header}",
                "title": f"Missing security header: {header}",
                "severity": severity,
                "category": "headers",
                "evidence": f"Header '{header}' not present.",
                "why_money": (
                    "Weak headers make session hijacking and script injection "
                    "on payment pages easier — a common route to stealing card "
                    "data or redirecting payouts."
                ),
                "fix": f"Add the '{header}' header at your server/CDN.",
            })

    server = h.get("server")
    if server:
        findings.append({
            "id": "server-banner",
            "title": f"Server banner exposed: {server}",
            "severity": "low",
            "category": "headers",
            "evidence": f"Server: {server}",
            "why_money": (
                "Revealing exact server version helps attackers pick a known "
                "exploit — often the first step toward checkout or admin."
            ),
            "fix": "Strip or genericize the Server header at the edge.",
        })

    return findings
