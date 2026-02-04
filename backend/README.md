# Ebounce Checker (Local)

Local web tool to validate emails from a CSV file.

## Features
- Syntax validation
- MX record checks (domain mail setup)
- Optional SMTP handshake check (no email sent)
- CSV output for all results + per-category CSVs
- Progress bar and live status
- Preview table with filters
- Supports CSVs with or without headers

## Run
```bash
cd "/Users/shashank/Desktop/Ebounce chekcer"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000

## Notes
- SMTP checks are slow and often blocked by servers or ISPs, so results are best-effort.
- For the most accurate deliverability/bounce checking, a paid verification API is recommended.
