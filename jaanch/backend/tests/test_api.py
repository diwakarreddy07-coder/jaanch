import os, sys, tempfile
os.environ.update(JAANCH_DB=os.path.join(tempfile.mkdtemp(), "t.db"), DEV_OTP="1", ADMIN_PASSWORD="pw")
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)

def test_registry_seeded():
    assert c.get("/api/v1/registry").json()["payees"][0]["upi"] == "rao.sunrise@upi"

def test_non_college_email_rejected():
    assert c.post("/api/v1/otp/request", json={"email": "a@gmail.com"}).status_code == 400

def test_wrong_admin_password():
    assert c.post("/api/v1/auth/admin", json={"password": "no"}).status_code == 401

def test_payee_needs_email_code_and_admin_approval():
    e = "dr.x@sunrise.edu.in"
    assert c.post("/api/v1/payees", json={"name": "Dr X", "upi": "dr.x@upi"}).status_code == 401
    j = c.post("/api/v1/otp/request", json={"email": e}).json()
    assert c.post("/api/v1/otp/verify", json={"email": e, "code": "000000"}).status_code == 400
    ft = c.post("/api/v1/otp/verify", json={"email": e, "code": j["dev_code"]}).json()["token"]
    assert c.post("/api/v1/payees", json={"name": "Dr X", "upi": "dr.x@upi", "purpose": "Workshop"}, headers={"X-Token": ft}).status_code == 200
    pid = [x for x in c.get("/api/v1/registry").json()["payees"] if x["upi"] == "dr.x@upi"][0]["id"]
    text = {"text": "Workshop fee payable to dr.x@upi at sunrise.edu.in"}
    assert c.post("/api/v1/analyze", json=text).json()["outcome"] == "Unverified"
    assert c.patch(f"/api/v1/payees/{pid}/approve").status_code == 401
    at = c.post("/api/v1/auth/admin", json={"password": "pw"}).json()["token"]
    assert c.patch(f"/api/v1/payees/{pid}/approve", headers={"X-Token": at}).json()["st"] == "approved"
    assert c.post("/api/v1/analyze", json=text).json()["outcome"] == "Matches registered payee"

def test_repeat_identifier_is_linked():
    t = {"text": "Pay Rs 99 fee to scam.one@upi now"}
    c.post("/api/v1/analyze", json=t)
    assert "linked" in c.post("/api/v1/analyze", json=t).json()["categories"]

def test_ocr_rejects_non_image():
    assert c.post("/api/v1/ocr", files={"file": ("a.txt", b"hi", "text/plain")}).status_code == 415
