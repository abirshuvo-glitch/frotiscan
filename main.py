#!/usr/bin/env python3
"""
main.py — FortiScan Backend (Commercial-Grade Ready)
FastAPI-based backend API integrating the advanced site_assessor engine.
This version is production-hardened for deployment on Render or any cloud.

Endpoints:
  POST /api/scan  →  Perform a full passive security scan
  GET  /health    →  Health check for uptime monitors
  GET  /           →  Root message
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import re
import socket
from urllib.parse import urlparse
from app.site_assessor import assess_site  # assumes your site_assessor.py is under /app

# ------------------------------------------------------------------------------
# App setup
# ------------------------------------------------------------------------------
app = FastAPI(
    title="FortiScan API",
    description="Secure, commercial-grade passive web scanner backend for SMEs.",
    version="3.0",
)

# ------------------------------------------------------------------------------
# Security: CORS / rate control (basic) / sanitization
# ------------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    "https://fortiscan-fe.vercel.app",  # your frontend
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Input validation utilities
# ------------------------------------------------------------------------------
def sanitize_target(url: str) -> str:
    """Basic safety filter: ensures it's a real domain, not localhost/IP."""
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'target'")
    if not re.match(r"^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", url):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    parsed = urlparse(url if url.startswith("http") else f"https://{url}")
    host = parsed.hostname or ""
    if any(x in host for x in ["localhost", "127.", "0.0.0.0"]):
        raise HTTPException(status_code=400, detail="Local/internal targets not allowed")
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Domain not resolvable (DNS lookup failed)")
    return parsed.geturl()

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "✅ FortiScan backend live and secure"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/scan")
async def scan_endpoint(request: Request):
    try:
        data = await request.json()
        target = data.get("target", "").strip()
        target_url = sanitize_target(target)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or missing JSON body")

    try:
        result = await assess_site(target_url)
        return {
            "host": result["target"],
            "score": result["summary"]["overall_score"],
            "risk_level": result["summary"]["risk_level"],
            "findings": result["findings"],
            "remediations": result.get("remediations", []),
            "timestamp": result["timestamp"],
        }
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out (target unresponsive)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ------------------------------------------------------------------------------
# Run locally:  uvicorn main:app --reload
# On Render: start command should be:
#   uvicorn main:app --host 0.0.0.0 --port 10000
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
