"""Rule-based analysis engine. Heuristic points, not probabilities."""
import json, re
from pathlib import Path
from rapidfuzz import fuzz

RULES = json.loads((Path(__file__).parent / "rules.json").read_text(encoding="utf-8"))
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd"}
UPI = re.compile(r"[\w.-]{2,}@[a-z]{2,}\b(?!\.[a-z])", re.I)
URL = re.compile(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.I)

def norm(s):
    s = re.sub(r"[^a-z0-9]", "", (s or "").lower())
    return s.replace("rn", "m").replace("0", "o").replace("1", "l")

def sim(a, b):
    return fuzz.ratio(norm(a), norm(b)) / 100

def host(u):
    return re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split("?")[0].split("#")[0].lower()

def band(s):
    return "High" if s >= 60 else "Medium" if s >= 25 else "Low"

def analyze(i, org, payees, history=None, keep=False):
    ev = []
    def add(g, c, p, t, d, s):
        ev.append(dict(g=g, c=c, p=p, t=t, d=d, s=s))
    text = i.get("text") or ""
    for r in RULES:
        m = re.search(r["pattern"], text, re.I)
        if m:
            add("m", r["cat"], r["pts"], r["title"], f"Matched “{m.group(0)}”. {r['why']}", "message text")
    mu = UPI.search(text)
    upi = (i.get("upi") or (mu.group(0) if mu else "")).strip()
    clean = re.sub(r"[\w.-]+@[\w.-]+", "", text + " " + (i.get("link") or ""))
    hosts = list(dict.fromkeys(host(u) for u in URL.findall(clean)))
    reg = lambda h: next((d for d in org["domains"] if h == d or h.endswith("." + d)), None)
    for h in hosts:
        if h in SHORT:
            add("m", "short", 10, "Shortened link", f"“{h}” hides the real destination. Not opened.", "message text")
        elif reg(h):
            add("m", "ok", 0, "Domain matches registry", f"“{h}” is a registered domain.", "registry")
        elif any(sim(h, d) >= .8 for d in org["domains"]):
            add("m", "lookalike", 30, "Lookalike domain", f"“{h}” resembles a registered domain but is not one.", "registry comparison")
        else:
            add("m", "link", 5, "Other link", f"“{h}” is not in the registry. Not opened.", "message text")
    if upi:
        p = next((x for x in payees if x["upi"].lower() == upi.lower()), None)
        if p and p["st"] == "approved":
            add("m", "verified", -30, "Verified payee", f"{upi} is registered to {p['name']} for: {p['purpose']}.", "registry")
        elif p:
            add("m", "pending", 10, "Payee awaiting approval", f"{upi} was submitted but not approved yet.", "registry")
        else:
            add("m", "unreg", 10, "UPI ID not in registry", f"{upi} is not a registered payee. Unverified, not proof of a scam.", "registry")
    ph = re.search(r"(?:\+91[- ]?)?[6-9]\d{9}", text)
    ids = [x for x in ([upi and "upi:" + upi.lower(), ph and "ph:" + ph.group(0)] + ["d:" + h for h in hosts if not reg(h)]) if x]
    if keep and history is not None:
        for k in ids:
            c = sum(k in h for h in history)
            if c:
                add("m", "linked", 0, "Seen before", f"“{k.split(':', 1)[1]}” appeared in {c} earlier check(s).", "case history")
    handle = (i.get("handle") or "").lstrip("@")
    exact = any(h.lower() == handle.lower() for h in org["handles"])
    if handle:
        best = max([sim(h, handle) for h in org["handles"]] or [0])
        if exact:
            add("f", "hx", 0, "Handle matches registry", "Same as a registered handle.", "registry")
        elif best >= .8:
            add("f", "hn", 20, "Handle resembles an official one", f"“{handle}” is close to a registered handle but not the same.", "registry comparison")
        else:
            add("f", "hu", 0, "Handle: no close match", "Unknown relationship to registered handles.", "registry comparison")
    name = i.get("name") or ""
    if name and not exact and sim(name, re.sub(r" \(.*", "", org["name"])) >= .75:
        add("f", "dn", 15, "Display name resembles the college", f"“{name}” looks like the registered name.", "registry comparison")
    if i.get("website"):
        h = host(i["website"])
        if reg(h):
            add("f", "wk", 0, "Website matches registry", f"“{h}” is registered.", "registry")
        else:
            add("f", "wd", 30, "Website differs from registry", f"“{h}” is not a registered domain.", "registry comparison")
    groups = {}
    for g in "mf":
        it = [e for e in ev if e["g"] == g]
        if not it:
            continue
        sc = max(0, min(100, sum(e["p"] for e in it)))
        cats = {e["c"] for e in it if e["p"] > 0}
        b = band(sc)
        if b == "High" and len(cats) < 2:
            b = "Medium"
        groups[g] = dict(score=sc, band=b, evidence=it)
    has_profile = bool(handle or name or i.get("website"))
    insuf = len(text.strip()) < 15 and not upi and not has_profile and not hosts
    cf = sum(bool(x) for x in [len(text.strip()) >= 20, upi or hosts, org["domains"] and org["handles"]])
    outcome = ("Insufficient information" if insuf else
               "Risk indicators found" if any(x["band"] == "High" for x in groups.values()) else
               "Matches registered payee" if any(e["c"] == "verified" for e in ev) else "Unverified")
    if keep and history is not None and not insuf:
        history.extend(ids)
    return dict(outcome=outcome, confidence=["Low", "Low", "Medium", "High"][cf], insufficient=insuf,
                groups=groups, categories=sorted({e["c"] for e in ev}))
