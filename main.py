from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx, socket, ssl, asyncio, re, datetime
import dns.resolver, whois
from ipwhois import IPWhois

app = FastAPI(title="FortiScan AI", version="1.0")

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust later for your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Helpers =====
def valid_domain(domain: str) -> bool:
    pattern = re.compile(r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$")
    return bool(pattern.match(domain))

async def get_ip(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

async def get_ssl_info(domain: str):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.utcnow()).days
                issuer = dict(x[0] for x in cert['issuer'])
                version = ssock.version()
                return {
                    "valid": True,
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "version": version,
                    "expires_in_days": days_left
                }
    except Exception:
        return {"valid": False}

async def get_headers(domain: str):
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
            r = await client.get(f"https://{domain}")
            headers = {k.lower(): v for k, v in r.headers.items()}
            security_headers = [
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "strict-transport-security",
                "permissions-policy"
            ]
            missing = [h for h in security_headers if h not in headers]
            return {"status": r.status_code, "missing_headers": missing}
    except Exception:
        return {"error": "Could not fetch headers"}

async def get_dns(domain: str):
    result = {}
    try:
        for rec in ["A", "MX", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rec)
                result[rec] = [str(rdata) for rdata in answers]
            except Exception:
                result[rec] = []
        return result
    except Exception:
        return {}

async def get_whois(domain: str):
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date)[:10] if data.creation_date else None,
            "expiration_date": str(data.expiration_date)[:10] if data.expiration_date else None,
        }
    except Exception:
        return {}

async def detect_waf(headers: dict):
    waf_signatures = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "aws": "AWS WAF",
        "imperva": "Imperva",
        "sucuri": "Sucuri",
    }
    for key, val in headers.items():
        for sig, name in waf_signatures.items():
            if sig in key.lower() or sig in val.lower():
                return name
    return None

async def compute_score(tls, headers, dns):
    score = 100
    notes = []
    if not tls["valid"]:
        score -= 30
        notes.append("SSL not valid.")
    elif tls.get("expires_in_days", 0) < 15:
        score -= 10
        notes.append("SSL expiring soon.")
    if len(headers.get("missing_headers", [])) > 2:
        score -= len(headers["missing_headers"]) * 5
        notes.append("Missing key HTTP security headers.")
    if not any("v=spf1" in txt for txt in dns.get("TXT", [])):
        score -= 10
        notes.append("No SPF record found.")
    if not dns.get("MX"):
        score -= 5
        notes.append("No MX record found.")
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade, notes

# ===== API ROUTE =====
@app.post("/api/scan")
async def scan(request: Request):
    try:
        data = await request.json()
        domain = data.get("target", "").strip().lower()

        # --- Validate ---
        if not valid_domain(domain):
            return {"error": "Invalid domain"}
        if re.match(r"^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.)", domain):
            return {"error": "Local targets not allowed"}

        ip = await get_ip(domain)
        if not ip:
            return {"error": "Cannot resolve domain"}

        # --- Run async tasks ---
        tls_task = asyncio.create_task(get_ssl_info(domain))
        headers_task = asyncio.create_task(get_headers(domain))
        dns_task = asyncio.create_task(get_dns(domain))
        whois_task = asyncio.create_task(get_whois(domain))
        await asyncio.gather(tls_task, headers_task, dns_task, whois_task)

        tls, headers, dns, whois_info = tls_task.result(), headers_task.result(), dns_task.result(), whois_task.result()
        waf = await detect_waf(headers if isinstance(headers, dict) else {})
        score, grade, notes = await compute_score(tls, headers, dns)

        # --- Combine result ---
        return {
            "host": domain,
            "ip": ip,
            "grade": grade,
            "score": score,
            "brand_trust": round(score * 0.9),
            "tls": tls,
            "dns": dns,
            "headers": headers,
            "whois": whois_info,
            "waf": waf,
            "notes": notes,
        }
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

@app.get("/")
def root():
    return {"message": "FortiScan AI Backend Active", "version": "1.0"}
