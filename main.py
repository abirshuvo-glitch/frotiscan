from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket, ssl, httpx, datetime, idna
from dateutil import tz
import dns.resolver

# --------- FastAPI app + CORS ----------
app = FastAPI(title="FortiScan Backend", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # dev-friendly; tighten for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------- Models ----------
class ScanRequest(BaseModel):
    target: str

# --------- Helpers ----------
def normalize_host(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.split(":", 1)[0]
    try:
        return idna.encode(raw).decode("ascii")
    except Exception:
        return raw

def resolve_ip(host: str) -> str | None:
    try:
        ans = dns.resolver.resolve(host, "A", lifetime=3.0)
        for r in ans:
            return r.to_text()
    except Exception:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

async def check_https_redirect(host: str) -> bool:
    url = f"http://{host}"
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            r = await client.get(url, headers={"User-Agent": "FortiScan/0.1"})
            return r.url.scheme.lower() == "https"
    except Exception:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"https://{host}", headers={"User-Agent": "FortiScan/0.1"})
                return r.status_code < 500
        except Exception:
            return False

def check_tls_certificate(host: str) -> tuple[bool, int | None, str | None]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(tz=tz.tzutc())
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=tz.tzutc())
                    days_left = int((expires - now).total_seconds() // 86400)
                else:
                    days_left = None
                return True, days_left, None
    except ssl.SSLCertVerificationError as e:
        return False, None, f"TLS verification error: {e.verify_message or str(e)}"
    except Exception as e:
        return False, None, f"TLS error: {str(e)}"

def quick_open_ports(host: str) -> list[int]:
    ports = [80, 443]
    open_list = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=1.2):
                open_list.append(p)
        except Exception:
            pass
    return open_list

def score_and_grade(https_ok: bool, ssl_valid: bool, days_left: int | None) -> tuple[int, str, list[str]]:
    score = 100
    notes: list[str] = []

    if not https_ok:
        score -= 10
        notes.append("Enable HTTP→HTTPS redirect site-wide (301) to protect users from downgrade/MITM.")

    if not ssl_valid:
        score -= 15
        notes.append("Fix TLS certificate issues (hostname mismatch/expired/untrusted). Use a valid cert and chain.")
    else:
        if days_left is None:
            score -= 3
            notes.append("Could not read TLS expiry; ensure standard certificate chain is presented.")
        elif days_left < 30:
            score -= 5
            notes.append("Rotate TLS certificate within 30 days to avoid outages.")
        elif days_left < 90:
            score -= 2
            notes.append("Plan TLS certificate rotation (expires in <90 days).")

    score = max(0, min(100, score))
    if   score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 40: grade = "D"
    else:             grade = "F"

    return score, grade, notes

# --------- Routes ----------
@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/scan")
async def scan(req: ScanRequest):
    host = normalize_host(req.target)
    if not host:
        return {"error": "invalid_target"}

    ip = resolve_ip(host)
    https_ok = await check_https_redirect(host)
    ssl_valid, days_left, ssl_err = check_tls_certificate(host)
    open_ports = quick_open_ports(host)
    score, grade, notes = score_and_grade(https_ok, ssl_valid, days_left)

    if 80 in open_ports and not https_ok:
        notes.append("Port 80 is reachable and not enforcing redirect; add forced HTTPS redirect.")
    if 443 not in open_ports:
        notes.append("Port 443 is not reachable; ensure your firewall/host allows HTTPS for public sites.")
    if ssl_err:
        notes.append(f"TLS note: {ssl_err}")

    return {
        "host": host,
        "ip": ip,
        "https_redirect": bool(https_ok),
        "ssl_valid": bool(ssl_valid),
        "ssl_expires_in_days": days_left,
        "open_ports": open_ports,
        "score": score,
        "grade": grade,
        "notes": notes,
    }
