import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.engine import analyze
D = json.loads((Path(__file__).resolve().parents[1] / "data/registry.json").read_text(encoding="utf-8"))
run = lambda i: analyze(i, D["org"], D["payees"])

def test_verified_payee_not_flagged():
    r = run({"text": "Workshop fee Rs 500 payable to rao.sunrise@upi at sunrise.edu.in/ws"})
    assert r["outcome"] == "Matches registered payee" and r["groups"]["m"]["band"] == "Low"

def test_forwarded_scam_is_high():
    r = run({"text": "Internship guaranteed. Only 50 seats left, register TODAY: bit.ly/x. Pay Rs 199 deposit. Forward to all groups!"})
    assert r["groups"]["m"]["band"] == "High" and r["outcome"] == "Risk indicators found"

def test_single_signal_cannot_be_high():
    assert run({"text": "Share the OTP sent to you to confirm"})["groups"]["m"]["band"] != "High"

def test_lookalike_domain():
    assert "lookalike" in run({"text": "Pay at sunrise-edu.in/pay now please"})["categories"]

def test_insufficient():
    assert run({"text": "hi"})["insufficient"]

def test_upi_id_followed_by_full_stop():
    r = run({"text": "Fee payable to rao.sunrise@upi. Details at sunrise.edu.in/ws"})
    assert r["outcome"] == "Matches registered payee"
