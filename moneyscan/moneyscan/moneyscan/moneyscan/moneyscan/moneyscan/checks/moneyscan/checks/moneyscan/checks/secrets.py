import re

NAME = "Exposed secrets"

PATTERNS = [
    ("Stripe secret key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{20,}")),
    ("AWS access key",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key",    re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub token",      re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("Slack token",       re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("Private key",       re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

def _redact(s, keep=8):
    return s[:keep] + "*" * max(0, len(s) - keep)

def run(url, response, html):
    findings = []
    text = html or ""

    for label, pattern in PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0)
            findings.append({
                "id": f"secret-{label.lower().replace(' ', '-')}",
                "title": f"Possible {label} exposed in page source",
                "severity": "critical",
                "category": "secrets",
                "evidence": f"Found: {_redact(raw)}",
                "why_money": (
                    f"A {label} in frontend code is readable by anyone. An "
                    "attacker can use it to move money, issue refunds, read "
                    "transactions, or take over the payment provider account."
                ),
                "fix": (
                    "Move secrets to the backend, rotate immediately, and "
                    "restrict keys by IP/domain in the provider dashboard."
                ),
            })

    return findings
