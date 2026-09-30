import asyncio
import hashlib
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from garminconnect import Garmin
from pydantic import BaseModel

app = FastAPI(title="PolyPacer Garmin MCP multi-client gateway", version="1.0.0")
DATA_DIR = Path(os.getenv("GARMIN_DATA_DIR", "/data")).resolve()
SHARED_SECRET = os.getenv("GARMIN_MCP_GATEWAY_SECRET", "")
DATA_DIR.mkdir(parents=True, exist_ok=True)
PENDING: dict[str, dict[str, Any]] = {}
PROCESSES: dict[str, dict[str, Any]] = {}
TENANT_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,180}$")

class Credentials(BaseModel):
    email: str
    password: str

class MfaPayload(BaseModel):
    challenge: str
    code: str

def check_secret(authorization: str | None):
    if not SHARED_SECRET:
        raise HTTPException(503, "Gateway secret is not configured")
    if not authorization or not secrets.compare_digest(authorization, f"Bearer {SHARED_SECRET}"):
        raise HTTPException(401, "Unauthorized")

def tenant_key(raw: str | None) -> str:
    if not raw or not TENANT_RE.match(raw):
        raise HTTPException(400, "Invalid x-tenant-id")
    return hashlib.sha256(raw.encode()).hexdigest()

def tenant_dir(key: str) -> Path:
    p = DATA_DIR / "users" / key
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p

def token_dir(key: str) -> Path:
    return tenant_dir(key) / "tokens"

def token_b64(key: str) -> Path:
    return tenant_dir(key) / "tokens.b64"

def dump_tokens(g: Garmin, key: str):
    path = token_dir(key)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    g.client.dump(str(path))
    os.chmod(path, 0o700)
    for item in path.iterdir():
        if item.is_file():
            os.chmod(item, 0o600)

def client_for(key: str) -> Garmin:
    path = token_dir(key)
    if not path.exists():
        raise HTTPException(409, "Garmin account is not connected")
    g = Garmin()
    try:
        g.login(str(path))
    except Exception as exc:
        raise HTTPException(401, f"Garmin authentication expired: {type(exc).__name__}") from exc
    return g

def full_name(g: Garmin) -> str | None:
    try:
        return str(g.get_full_name() or "").strip() or None
    except Exception:
        return None

def clean_pending():
    now = time.time()
    for k, row in list(PENDING.items()):
        if row["exp"] < now:
            PENDING.pop(k, None)

def stop_process(key: str):
    row = PROCESSES.pop(key, None)
    if row and row["proc"].poll() is None:
        row["proc"].terminate()
        try:
            row["proc"].wait(timeout=4)
        except subprocess.TimeoutExpired:
            row["proc"].kill()

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])

async def ensure_process(key: str) -> int:
    row = PROCESSES.get(key)
    if row and row["proc"].poll() is None:
        return row["port"]
    client_for(key)  # validate tokens before spawning the MCP server
    port = free_port()
    env = os.environ.copy()
    env.update({
        "GARMINTOKENS": str(token_dir(key)),
        "GARMINTOKENS_BASE64": str(token_b64(key)),
        "GARMIN_MCP_TRANSPORT": "streamable-http",
        "GARMIN_MCP_HOST": "127.0.0.1",
        "GARMIN_MCP_PORT": str(port),
    })
    proc = subprocess.Popen(["garmin-mcp"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    PROCESSES[key] = {"proc": proc, "port": port, "started": time.time()}
    async with httpx.AsyncClient(timeout=1.0) as c:
        for _ in range(40):
            if proc.poll() is not None:
                err = (proc.stderr.read() if proc.stderr else "")[-1200:]
                PROCESSES.pop(key, None)
                raise HTTPException(502, f"Garmin MCP failed to start: {err or 'unknown error'}")
            try:
                r = await c.get(f"http://127.0.0.1:{port}/healthz")
                if r.status_code == 200:
                    return port
            except Exception:
                pass
            await asyncio.sleep(.15)
    stop_process(key)
    raise HTTPException(504, "Garmin MCP startup timeout")

@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "garmin-mcp-gateway"}

@app.post("/v1/auth/start")
def auth_start(payload: Credentials, authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id); clean_pending(); stop_process(key)
    try:
        g = Garmin(email=payload.email.strip(), password=payload.password, return_on_mfa=True)
        result = g.login()
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
            challenge = secrets.token_urlsafe(32)
            PENDING[challenge] = {"tenant": key, "garmin": g, "state": result[1], "exp": time.time() + 600}
            return {"status": "needs_mfa", "challenge": challenge}
        dump_tokens(g, key)
        return {"status": "connected", "label": full_name(g)}
    except Exception as exc:
        raise HTTPException(401, f"Connexion Garmin impossible: {type(exc).__name__}") from exc

@app.post("/v1/auth/mfa")
def auth_mfa(payload: MfaPayload, authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id); clean_pending()
    row = PENDING.get(payload.challenge)
    if not row or row["tenant"] != key:
        raise HTTPException(409, "MFA challenge expired")
    try:
        g: Garmin = row["garmin"]
        g.resume_login(row["state"], payload.code.strip())
        dump_tokens(g, key)
        PENDING.pop(payload.challenge, None)
        return {"status": "connected", "label": full_name(g)}
    except Exception as exc:
        raise HTTPException(401, f"Code MFA refusé: {type(exc).__name__}") from exc

@app.get("/v1/status")
def status(authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id)
    try:
        g = client_for(key)
        return {"connected": True, "label": full_name(g)}
    except HTTPException as exc:
        if exc.status_code in (401, 409):
            return {"connected": False, "label": None}
        raise

@app.get("/v1/activities")
def activities(limit: int = 100, authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id)
    g = client_for(key)
    try:
        rows = g.get_activities(0, max(1, min(200, limit)))
        return {"activities": rows or []}
    except Exception as exc:
        raise HTTPException(502, f"Garmin activities error: {type(exc).__name__}") from exc

@app.delete("/v1/account")
def disconnect(authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id)
    stop_process(key)
    shutil.rmtree(tenant_dir(key), ignore_errors=True)
    for challenge, row in list(PENDING.items()):
        if row["tenant"] == key:
            PENDING.pop(challenge, None)
    return {"ok": True}

@app.api_route("/mcp", methods=["GET", "POST", "DELETE"])
async def mcp_proxy(request: Request, authorization: str | None = Header(default=None), x_tenant_id: str | None = Header(default=None)):
    check_secret(authorization); key = tenant_key(x_tenant_id)
    port = await ensure_process(key)
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "authorization", "x-tenant-id", "content-length"}}
    client = httpx.AsyncClient(timeout=None)
    upstream = client.build_request(request.method, f"http://127.0.0.1:{port}/mcp", params=request.query_params, headers=headers, content=body)
    resp = await client.send(upstream, stream=True)
    out_headers = {}
    for name in ("content-type", "mcp-session-id", "cache-control"):
        if name in resp.headers:
            out_headers[name] = resp.headers[name]
    async def chunks():
        try:
            async for chunk in resp.aiter_raw():
                yield chunk
        finally:
            await resp.aclose(); await client.aclose()
    if "text/event-stream" in resp.headers.get("content-type", ""):
        return StreamingResponse(chunks(), status_code=resp.status_code, headers=out_headers, media_type="text/event-stream")
    data = await resp.aread(); await resp.aclose(); await client.aclose()
    return Response(content=data, status_code=resp.status_code, headers=out_headers)
