# Jaanch: scam check for campus (v5.1)

Explainable scam and impersonation checker for college communities. It shows evidence, confidence and safe next steps. It never proves an account is fake.

## What works
- Message, link, UPI ID and profile checks (English and Hinglish rules, editable in `backend/app/rules.json`)
- SQLite database for the registry, payees and repeat-identifier history
- Faculty payee flow: college-email OTP, then admin approval
- Admin sign-in (password from `.env`)
- Screenshot reading with Tesseract OCR; you review the text before checking
- Web and mobile layout, light and dark theme, printable report, evaluation screen
- Without the backend, `frontend/index.html` runs on its own with local data (no OCR, no OTP)

## Run (Python 3.10+)
```
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then set ADMIN_PASSWORD
python -m pytest
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 (app) and /docs (API tester). On a phone: add `--host 0.0.0.0` and open `http://<computer-ip>:8000` on the same Wi-Fi.

## Install Tesseract (for screenshots)
Ubuntu: `sudo apt install tesseract-ocr`. macOS: `brew install tesseract`. Windows: install from the Tesseract project page and add it to PATH.

## Email codes
With no `SMTP_*` settings, codes print in the server console. `DEV_OTP=1` also shows the code in the app for demos; remove it before real use. Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` and `SMTP_FROM` to send real email.

## Before real use
Change `ADMIN_PASSWORD`, turn off `DEV_OTP`, serve over HTTPS, and get the college’s approval and a privacy review. Login tokens are kept in server memory and reset on restart. Scores are starting heuristics, not probabilities; the built-in test set is small and team-written.

## Open-source parts
FastAPI, Uvicorn, Pydantic, RapidFuzz, python-multipart, python-dotenv, pytesseract, Pillow, Tesseract OCR, SQLite, Pytest, httpx; Plus Jakarta Sans font (SIL OFL). The interface is plain HTML, CSS and JavaScript. Check each project’s own licence before redistributing.
