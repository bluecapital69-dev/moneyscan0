# MoneyScan

Passive security scanner that finds money-leak weaknesses on websites
you OWN or have WRITTEN PERMISSION to test.

## ⚠️ Legal
Only scan sites you own or are authorized to test. Unauthorized scanning
is illegal (CFAA, UK CMA, Kenya Computer Misuse & Cybercrimes Act 2018).

## Setup
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

## Run
python -m moneyscan https://your-site.com

Outputs: `report.html` and `report.json`
