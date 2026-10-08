import re

NAME = "Payment & money-flow surface"

PROVIDERS = {
    "Stripe":      [r"js\.stripe\.com", r"stripe\.com/v3", r"pk_(live|test)_"],
    "PayPal":      [r"paypal\.com/sdk", r"paypalobjects\.com"],
    "M-Pesa":      [r"safaricom\.co\.ke", r"mpesa", r"daraja"],
    "Flutterwave": [r"flutterwave\.com", r"rave\.min\.js"],
    "Paystack":    [r"paystack\.com", r"paystack\.co"],
    "Square":      [r"squareup\.com", r"square\.com/v2"],
    "Braintree":   [r"braintreegateway\.com"],
}

IDOR_PATTERNS = [
    r"/invoice[s]?/\d+",
    r"/order[s]?/\d+",
    r"/user[s]?/\d+",
    r"/account[s]?/\d+",
    r"/payment[s]?/\d+",
    r"/transaction[s]?/\d+",
]

def run(url, response, html):
    findings = []
    text = (html or "") + "\n" + " ".join(f"{k}:{v}" for k, v in response.headers.items())

    detected = []
    for name, patterns in PROVIDERS.items():
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                detected.append(name)
                break

    if detected:
        findings.append({
            "id": "payment-providers",
            "title": f"Payment providers in use: {', '.join(sorted(set(detected)))}",
            "severity": "info",
            "category": "payments",
            "evidence": ", ".join(sorted(set(detected))),
            "why_money": (
                "These are the rails money moves on. Every other finding "
                "should be read as a route to abuse THESE rails."
            ),
            "fix": "Informational — use to scope further manual review.",
        })

    hits = set()
    for p in IDOR_PATTERNS:
        for m in re.finditer(p, text, re.IGNORECASE):
            hits.add(m.group(0))

    if hits:
        findings.append({
            "id": "idor-patterns",
            "title": f"IDOR-prone URL patterns found ({len(hits)})",
            "severity": "medium",
            "category": "payments",
            "evidence": "; ".join(sorted(hits)[:10]),
            "why_money": (
                "URLs like /invoice/123 often expose other users' data if the "
                "backend doesn't check ownership. Classic path to reading "
                "someone's card last-4, refunds, or redirecting a payout. "
                "We did NOT test these — verify manually on YOUR account."
            ),
            "fix": (
                "Enforce server-side ownership checks on every ID route; "
                "use UUIDs; log and alert on cross-tenant access."
            ),
        })

    return findings
