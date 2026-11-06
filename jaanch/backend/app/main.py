import hashlib, io, json, os, re, secrets, smtplib, sqlite3, time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass
from .engine import analyze

ROOT = Path(__file__).resolve().parents[1]
DB = os.getenv("JAANCH_DB", str(ROOT / "data" / "jaanch.db"))
app = FastAPI(title="Jaanch", version="5.1")
tokens, last_otp = {}, {}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

with db() as c:
    c.executescript("""create table if not exists kv(k text primary key, v text);
    create table if not exists payees(id integer primary key autoincrement, name text, upi text, purpose text, email text, st text);
    create table if not exists ids(k text);
    create table if not exists otp(email text primary key, h text, exp real);""")
    if not c.execute("select 1 from kv where k='org'").fetchone():
        seed = json.loads((ROOT / "data" / "registry.json").read_text(encoding="utf-8"))
        c.execute("insert into kv values('org',?)", (json.dumps(seed["org"]),))
        c.executemany("insert into payees(name,upi,purpose,email,st) values(?,?,?,'',?)",
                      [(p["name"], p["upi"], p["purpose"], p["st"]) for p in seed["payees"]])

def org():
    with db() as c:
        return json.loads(c.execute("select v from kv where k='org'").fetchone()[0])

def payees():
    with db() as c:
        return [dict(r) for r in c.execute("select id,name,upi,purpose,st from payees order by id")]

def need(role, tok):
    t = tokens.get(tok or "")
    if not t or t["exp"] < time.time() or t["role"] != role:
        raise HTTPException(401, f"Please sign in first ({role}).")
    return t

class Org(BaseModel):
    name: str
    domains: list[str]
    handles: list[str]
    contacts: list[str] = []

class PayeeIn(BaseModel):
    name: str
    upi: str
    purpose: str = "Not stated"

class Check(BaseModel):
    text: Optional[str] = ""
    link: Optional[str] = ""
    upi: Optional[str] = ""
    handle: Optional[str] = ""
    name: Optional[str] = ""
    website: Optional[str] = ""

class AdminIn(BaseModel):
    password: str

class OtpReq(BaseModel):
    email: str

class OtpVerify(BaseModel):
    email: str
    code: str

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": "5.1"}

@app.get("/api/v1/registry")
def registry():
    return {"org": org(), "payees": payees()}

@app.put("/api/v1/org")
def put_org(o: Org, x_token: Optional[str] = Header(None)):
    need("admin", x_token)
    with db() as c:
        c.execute("update kv set v=? where k='org'", (json.dumps(o.model_dump()),))
    return org()

@app.post("/api/v1/auth/admin")
def admin_login(a: AdminIn):
    if not secrets.compare_digest(a.password, os.getenv("ADMIN_PASSWORD", "admin123")):
        raise HTTPException(401, "Wrong password.")
    t = secrets.token_urlsafe(24); tokens[t] = {"role": "admin", "exp": time.time() + 3600}
    return {"token": t}

def send_mail(to, code):
    host = os.getenv("SMTP_HOST")
    if not host:
        print(f"[DEV OTP] {to}: {code}"); return False
    m = EmailMessage(); m["Subject"] = "Your Jaanch verification code"; m["To"] = to
    m["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "")); m.set_content(f"Your Jaanch code is {code}. It expires in 10 minutes.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587"))) as s:
        s.starttls()
        if os.getenv("SMTP_USER"):
            s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS", ""))
        s.send_message(m)
    return True

@app.post("/api/v1/otp/request")
def otp_request(r: OtpReq):
    email = r.email.strip().lower(); dom = email.split("@")[-1]
    if "@" not in email or not any(dom == d or dom.endswith("." + d) for d in org()["domains"]):
        raise HTTPException(400, "Use your college email address.")
    if time.time() - last_otp.get(email, 0) < 30:
        raise HTTPException(429, "Please wait 30 seconds before asking for another code.")
    last_otp[email] = time.time(); code = f"{secrets.randbelow(10**6):06d}"
    with db() as c:
        c.execute("insert or replace into otp values(?,?,?)", (email, hashlib.sha256((code + email).encode()).hexdigest(), time.time() + 600))
    sent = send_mail(email, code)
    out = {"message": "Code sent to your email." if sent else "No email server is set up; the code was printed in the server console."}
    if os.getenv("DEV_OTP") == "1":
        out["dev_code"] = code
    return out

@app.post("/api/v1/otp/verify")
def otp_verify(r: OtpVerify):
    email = r.email.strip().lower()
    with db() as c:
        row = c.execute("select h,exp from otp where email=?", (email,)).fetchone()
        if not row or row["exp"] < time.time() or row["h"] != hashlib.sha256((r.code.strip() + email).encode()).hexdigest():
            raise HTTPException(400, "Wrong or expired code.")
        c.execute("delete from otp where email=?", (email,))
    t = secrets.token_urlsafe(24); tokens[t] = {"role": "faculty", "email": email, "exp": time.time() + 3600}
    return {"token": t}

@app.post("/api/v1/payees")
def add_payee(p: PayeeIn, x_token: Optional[str] = Header(None)):
    t = need("faculty", x_token)
    if not re.fullmatch(r"[\w.-]{2,}@[a-z]{2,}", p.upi, re.I):
        raise HTTPException(422, "Enter a valid UPI ID such as name@bank.")
    with db() as c:
        c.execute("insert into payees(name,upi,purpose,email,st) values(?,?,?,?,'pending')", (p.name, p.upi, p.purpose, t["email"]))
    return {"status": "pending"}

@app.patch("/api/v1/payees/{pid}/approve")
def toggle(pid: int, x_token: Optional[str] = Header(None)):
    need("admin", x_token)
    with db() as c:
        r = c.execute("select st from payees where id=?", (pid,)).fetchone()
        if not r:
            raise HTTPException(404, "Payee not found")
        new = "pending" if r["st"] == "approved" else "approved"
        c.execute("update payees set st=? where id=?", (new, pid))
    return {"id": pid, "st": new}

@app.delete("/api/v1/payees/{pid}")
def remove(pid: int, x_token: Optional[str] = Header(None)):
    need("admin", x_token)
    with db() as c:
        c.execute("delete from payees where id=?", (pid,))
    return {"deleted": pid}

@app.post("/api/v1/analyze")
def check(c: Check):
    with db() as con:
        hist = [r[0] for r in con.execute("select k from ids")]
    n = len(hist); res = analyze(c.model_dump(), org(), payees(), hist, keep=True)
    with db() as con:
        con.executemany("insert into ids values(?)", [(k,) for k in hist[n:]])
    return res

@app.post("/api/v1/ocr")
async def ocr(file: UploadFile = File(...)):
    if file.content_type not in ("image/png", "image/jpeg", "image/webp"):
        raise HTTPException(415, "Upload a PNG, JPEG or WebP image.")
    data = await file.read()
    if len(data) > 5_000_000:
        raise HTTPException(413, "Image is larger than 5 MB.")
    try:
        import pytesseract
        from PIL import Image
        text = pytesseract.image_to_string(Image.open(io.BytesIO(data)))
    except Exception:
        raise HTTPException(501, "Screenshot reading needs the Tesseract program installed on the server.")
    return {"text": text.strip()}

@app.get("/api/v1/samples")
def samples():
    return json.loads((ROOT / "data" / "test_set.json").read_text(encoding="utf-8"))

@app.post("/api/v1/evaluation/run")
def evaluate():
    rows = []
    for it in samples():
        r = analyze(it, org(), payees())
        worst = max((["Low", "Medium", "High"].index(g["band"]) for g in r["groups"].values()), default=0)
        rows.append({"label": it["label"], "band": ["Low", "Medium", "High"][worst], "text": it["text"][:70]})
    g = [r for r in rows if r["label"] == "genuine"]; s = [r for r in rows if r["label"] == "scam"]
    return {"false_alarms": sum(r["band"] != "Low" for r in g), "genuine_total": len(g),
            "missed": sum(r["band"] == "Low" for r in s), "scam_total": len(s), "rows": rows,
            "note": "Small team-written set; shows sensible behaviour, not real-world accuracy."}

app.mount("/", StaticFiles(directory=ROOT.parent / "frontend", html=True), name="web")
