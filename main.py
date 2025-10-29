# main.py — FortiScan Commercial Backend (v4.0)
# Secure, monetizable, production-grade FastAPI backend
#
# Endpoints:
#   POST /api/scan  -> run security audit
#   GET  /healthz   -> health probe
#   GET  /version   -> version info
#
# Env (all optional):
#   ALLOWED_ORIGINS       : comma-separated list (default: *)
#   FORTISCAN_API_KEY     : if set, requests must send X-API-Key
#   RATE_LIMIT_WINDOW_SEC : default 30
#   RATE_LIMIT_MAX_REQ    : default 12
#   REQ_TIMEOUT_SEC       : default 8
#
# Requirements (requirements.txt):
#   fastapi==0.115.0
#   uvicorn==0.30.0
#   httpx==0.27.0
#   dnspython==2.6.1

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import os, re, ssl, socket, ipaddress, asyncio
import httpx
import dns.resolver
from typing import Dict, Any, List, Optional, Tuple
from collections import deque
from time import time

VERSION = "4.0"

# ------------------------- Config -------------------------
ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",")
] or ["*"]

API_KEY = os.getenv("FORTISCAN_API_KEY", "").strip() or None
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "30"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX_REQ", "12"))
REQ_TIMEOUT = float(os.getenv("REQ_TIMEOUT_SEC", "8.0"))

# ------------------------- App ----------------------------
app = FastAPI(title="FortiScan Commercial API", version=VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# Security headers on all responses
@app.middleware("http")
async def secure_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # The API serves JSON only; lock CSP down.
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    return resp

# Optional API key enforcement
@app.middleware("http")
async def api_key_mw(request: Request, call_next):
    if API_KEY:
        if request.url.path.startswith("/api/"):
            if request.headers.get("x-api-key") != API_KEY:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return await call_next(request)

# Simple in-memory rate limiter (per instance)
_req_log: Dict[str, deque] = {}

@app.middleware("http")
async def rate_limit_mw(request: Request, call_next):
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    ip = request.client.host
    now = time()
    dq = _req_log.setdefault(ip, deque())
    # purge old entries
    while dq and now - dq[0] > RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
    dq.append(now)
    return await call_next(request)

# ------------------------- Models -------------------------
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)

class ScanIn(BaseModel):
    target: str

# ------------------------- Utils --------------------------
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in n for n in PRIVATE_NETS)
    except ValueError:
        return False

def sanitize_domain(raw: str) -> str:
    d = raw.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    d = d.split(":", 1)[0]
    return d

def calc_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

# --------------------- Network Helpers --------------------
async def resolve_dns(domain: str) -> List[str]:
    try:
        res = dns.resolver.Resolver()
        res.lifetime = REQ_TIMEOUT
        answers = res.resolve(domain, "A", lifetime=REQ_TIMEOUT)
        return [a.to_text() for a in answers]
    except Exception:
        return []

async def ssl_info(domain: str) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Returns: (valid_ssl, days_left, issuer_common_name)
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443), timeout=REQ_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                issuer = cert.get("issuer")
                issuer_cn = None
                if issuer:
                    # issuer is a tuple of tuples ((('commonName','X'),), ...)
                    for rdn in issuer:
                        for (k, v) in rdn:
                            if k.lower() in ("commonname", "cn"):
                                issuer_cn = v
                                break
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days = (exp.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                else:
                    days = None
                return True, days, issuer_cn
    except Exception:
        return False, None, None

async def fetch_headers(domain: str) -> Tuple[Dict[str, str], Optional[str], Optional[int]]:
    """
    Returns (headers_lc, final_scheme, status_code)
    Tries HTTPS first, then HTTP. Follows redirects.
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=REQ_TIMEOUT) as client:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{domain}")
                headers = {k.lower(): v for k, v in r.headers.items()}
                final_scheme = httpx.URL(str(r.url)).scheme
                return headers, final_scheme, r.status_code
            except Exception:
                continue
    return {}, None, None

async def probe_port(host: str, port: int) -> bool:
    try:
        fut = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=REQ_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

# --------------------- AI Reasoning -----------------------
def ai_reasoning(signals: Dict[str, Any]) -> str:
    m = []
    if not signals["dns_ok"]:
        m.append("Domain does not resolve; site may be offline or misconfigured.")
    if not signals["ssl"]["valid"]:
        m.append("TLS handshake failed or certificate invalid; HTTPS cannot be trusted.")
    elif signals["ssl"]["days_left"] is not None and signals["ssl"]["days_left"] < 15:
        m.append("TLS certificate expires within two weeks; high risk of outage and browser warnings.")
    if not signals["https_enforced"]:
        m.append("Site does not enforce HTTPS; users may connect over plaintext HTTP.")
    missing = signals["headers_missing"]
    if "strict-transport-security" in missing:
        m.append("HSTS header missing; browsers are allowed to downgrade to HTTP.")
    if "content-security-policy" in missing:
        m.append("CSP missing; XSS protections are weak and script injection risk is higher.")
    if "x-content-type-options" in missing:
        m.append("No MIME sniffing protection (X-Content-Type-Options); content-type confusion possible.")
    if "x-frame-options" in missing:
        m.append("Clickjacking protection (X-Frame-Options) not set.")
    if signals["waf"] == "none":
        m.append("No WAF/CDN signatures detected; origin may be directly exposed to scanning or DDoS.")
    if signals["score"] >= 85:
        m.append("Overall posture appears strong with proper DNS/TLS and baseline headers in place.")
    elif signals["score"] >= 65:
        m.append("Posture is moderate; address header gaps and TLS hygiene to reach a strong baseline.")
    else:
        m.append("Posture is weak; multiple foundational controls are missing.")
    return " ".join(m)

# ------------------------ API ----------------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "fortiscan", "version": VERSION}

@app.get("/version")
async def version():
    return {"version": VERSION}

class ScanOut(BaseModel):
    host: str
    ip: Optional[str]
    https_enforced: bool
    ssl_valid: bool
    ssl_expires_in_days: Optional[int]
    ssl_issuer: Optional[str]
    headers_found: List[str]
    headers_missing: List[str]
    cdn_or_waf: str
    open_ports: Dict[str, bool]
    score: int
    grade: str
    confidence: float
    notes: List[str]
    ai_reasoning: str

@app.post("/api/scan", response_model=ScanOut)
async def scan(inp: ScanIn, request: Request):
    domain = sanitize_domain(inp.target)
    if is_ip_literal(domain):
        raise HTTPException(400, "IP addresses are not supported; provide a public domain.")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(400, "Invalid domain format.")
    if domain in {"localhost"}:
        raise HTTPException(400, "Localhost is not allowed.")

    # DNS
    ips = await resolve_dns(domain)
    if not ips:
        raise HTTPException(400, "Domain does not resolve (no A records).")
    ip = ips[0]
    if is_private_ip(ip):
        raise HTTPException(400, "Target resolves to a private or link-local address; blocked.")

    # Parallel probes
    ssl_task = asyncio.create_task(ssl_info(domain))
    hdr_task = asyncio.create_task(fetch_headers(domain))
    p80_task = asyncio.create_task(probe_port(domain, 80))
    p443_task = asyncio.create_task(probe_port(domain, 443))

    ssl_valid, days_left, issuer = await ssl_task
    headers, final_scheme, http_status = await hdr_task
    port80 = await p80_task
    port443 = await p443_task

    # HTTPS enforcement
    https_enforced = (final_scheme == "https")

    # Header checks
    expected_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    headers_found = list(headers.keys())
    headers_missing = [h for h in expected_headers if h not in headers]

    # WAF/CDN hinting
    hdr_blob = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
    if "cf-ray" in headers or "cloudflare" in hdr_blob:
        waf = "Cloudflare"
    elif "akamai" in hdr_blob:
        waf = "Akamai"
    elif "fastly" in hdr_blob:
        waf = "Fastly"
    elif "vercel" in hdr_blob or "x-vercel-id" in headers:
        waf = "Vercel Edge"
    else:
        waf = "none"

    # Scoring
    score = 100
    notes: List[str] = []

    if not https_enforced:
        score -= 15; notes.append("HTTPS not enforced (no redirect to https).")
    if not ssl_valid:
        score -= 25; notes.append("TLS/SSL invalid or handshake failure.")
    elif days_left is not None and days_left < 30:
        score -= 10; notes.append(f"TLS certificate expires soon ({days_left} days).")

    # Header penalties
    penalties = {
        "strict-transport-security": 10,
        "content-security-policy": 10,
        "x-frame-options": 5,
        "x-content-type-options": 5,
        "referrer-policy": 2,
        "permissions-policy": 2,
    }
    for h, p in penalties.items():
        if h not in headers:
            score -= p
            notes.append(f"Missing {h} header.")

    # Port exposure (informational)
    open_ports = {"80": port80, "443": port443}
    if port80 and not https_enforced:
        # If HTTP is open and not enforcing HTTPS, small extra penalty
        score -= 3; notes.append("HTTP (80) open without strict HTTPS enforcement.")

    if waf == "none":
        score -= 5; notes.append("No CDN/WAF signals detected.")

    # Clamp & grade
    score = max(0, min(100, score))
    grade = calc_grade(score)
    confidence = round(min(1.0, max(0.4, score / 100)), 2)  # never below 0.4 if we reached here

    # AI reasoning text
    signals = {
        "dns_ok": True,
        "ssl": {"valid": ssl_valid, "days_left": days_left},
        "https_enforced": https_enforced,
        "headers_missing": headers_missing,
        "waf": waf,
        "score": score,
    }
    reasoning = ai_reasoning(signals)

    return ScanOut(
        host=domain,
        ip=ip,
        https_enforced=https_enforced,
        ssl_valid=ssl_valid,
        ssl_expires_in_days=days_left,
        ssl_issuer=issuer,
        headers_found=headers_found,
        headers_missing=headers_missing,
        cdn_or_waf=waf,
        open_ports=open_ports,
        score=score,
        grade=grade,
        confidence=confidence,
        notes=notes,
        ai_reasoning=reasoning,
    )
