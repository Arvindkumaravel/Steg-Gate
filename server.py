"""
StegGate API Server v5.0
========================
Steganography detection + sanitization middleware.

Pipeline:
    Website  →  POST /api/sanitize  →  scan  →  sanitize if threat  →  clean image

Run:
    pip install fastapi "uvicorn[standard]" python-multipart httpx
    python server.py

Env vars:
    PORT            default 5050
    STEGGATE_KEY    if set, all /api/* require  Authorization: Bearer <key>
    WEBHOOK_SECRET  HMAC secret for webhook signature header
"""

import asyncio, base64, hashlib, hmac, json, os, re, shutil, sys, time, traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import httpx
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

sys.path.insert(0, os.path.dirname(__file__))
from security_engine import EnterpriseStegEngine, _sanitise_floats

# ── Config ─────────────────────────────────────────────────────────────────────
STEGGATE_KEY   = os.environ.get("STEGGATE_KEY",   "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
CAL_PATH       = os.path.join(os.path.dirname(__file__), "calibration_web.json")
MAX_BYTES      = 50 * 1024 * 1024   # 50 MB

# ── App ─────────────────────────────────────────────────────────────────────────
app = FastAPI(title="StegGate", version="5.0",
              description="Steganography detection & sanitization middleware")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=[
        "X-Threat-Detected","X-Risk-Score","X-Was-Sanitized",
        "X-Original-Filename","X-Scan-Duration-Ms","Content-Disposition",
    ])

engine = EnterpriseStegEngine()
_pool  = ThreadPoolExecutor(max_workers=4)

if os.path.exists(CAL_PATH):
    try:    engine.load_calibration(CAL_PATH); print(f"[StegGate] Calibration loaded")
    except Exception as e: print(f"[StegGate] Cal load failed: {e}")

# ── Helpers ─────────────────────────────────────────────────────────────────────
def _b64(b):  return base64.b64encode(b).decode()
def _stem(f): return re.sub(r'\.[^.]+$', '', f or "image")
def _allowed(f):
    ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
    return ext in {"png","jpg","jpeg","bmp","webp","tiff"}

async def _run(fn, *args):
    return await asyncio.get_event_loop().run_in_executor(_pool, fn, *args)

def _check_auth(auth: Optional[str]):
    if not STEGGATE_KEY: return
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Authorization: Bearer <key> required")
    if not hmac.compare_digest(auth[7:], STEGGATE_KEY):
        raise HTTPException(403, "Invalid API key")

def _sign(body: bytes) -> str:
    if not WEBHOOK_SECRET: return ""
    return "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()

async def _fire_webhook(url: str, payload: dict):
    try:
        body = json.dumps(payload).encode()
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(url, content=body, headers={
                "Content-Type":         "application/json",
                "X-StegGate-Event":     "scan.complete",
                "X-StegGate-Signature": _sign(body),
            })
    except Exception as e: print(f"[StegGate] Webhook error: {e}")

# ── Routes ───────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    p = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if not os.path.exists(p):
        return HTMLResponse("<h2>dashboard.html not found</h2>", 404)
    return HTMLResponse(open(p).read())


@app.get("/api/health", tags=["Meta"])
async def health():
    return {
        "status":"ok", "version":"5.0", "auth": bool(STEGGATE_KEY),
        "calibrated": bool(engine.calibration and engine.calibration.is_ready),
        "cal_source": engine.calibration.source_hint if engine.calibration else None,
        "cal_images": engine.calibration.n_images    if engine.calibration else 0,
        "tools": {"zsteg": bool(shutil.which("zsteg")),
                  "binwalk": bool(shutil.which("binwalk"))},
    }


@app.post("/api/sanitize", tags=["Pipeline"],
          summary="★ Scan image → sanitize if threat → return clean file")
async def sanitize(
    file:          UploadFile     = File(...,   description="Image to scan"),
    force:         bool           = Form(False, description="Always sanitize regardless of result"),
    webhook_url:   str            = Form("",    description="POST result JSON here after scan"),
    authorization: Optional[str] = Header(None),
):
    """
    **Main pipeline endpoint.**

    ```
    User uploads → website → POST /api/sanitize
                                     │
                               Full engine scan
                                     │
                           Threat detected OR force?
                            ├─ YES → JPEG DCT sanitize → return clean JPEG
                            └─ NO  → return original bytes unchanged
                                     │
                           (optional) POST scan summary to webhook_url
    ```

    Response is raw image binary. Decision metadata is in response headers:

    | Header | Value |
    |---|---|
    | `X-Threat-Detected` | `true` / `false` |
    | `X-Risk-Score` | `0.00`–`100.00` |
    | `X-Was-Sanitized` | `true` / `false` |
    | `X-Scan-Duration-Ms` | integer ms |
    | `Content-Disposition` | `attachment; filename="…_sanitized.jpg"` |
    """
    _check_auth(authorization)
    if not file.filename or not _allowed(file.filename):
        raise HTTPException(400, "Unsupported type. Allowed: PNG, JPG, BMP, WEBP, TIFF.")
    raw = await file.read()
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "File too large (max 50 MB)")

    t0 = time.monotonic()
    try:
        result = await _run(engine.process_file, raw, file.filename)
    except Exception as e:
        traceback.print_exc(); raise HTTPException(500, f"Engine error: {e}")
    ms = int((time.monotonic() - t0) * 1000)

    is_threat  = bool(result.get("is_threat", False))
    risk_score = float(result.get("risk_score", 0.0))

    if is_threat or force:
        out, mime, fname, was = result["safe_file_bytes"], "image/jpeg", \
                                f"{_stem(file.filename)}_sanitized.jpg", True
    else:
        out, mime, fname, was = raw, file.content_type or "image/jpeg", file.filename, False

    if webhook_url:
        asyncio.create_task(_fire_webhook(webhook_url, {
            "event":"scan.complete", "timestamp":int(time.time()),
            "original_filename":file.filename, "is_threat":is_threat,
            "risk_score":round(risk_score,2), "was_sanitized":was,
            "sanitized_filename":fname if was else None, "scan_duration_ms":ms,
        }))

    return Response(content=out, media_type=mime, headers={
        "X-Threat-Detected":   str(is_threat).lower(),
        "X-Risk-Score":        f"{risk_score:.2f}",
        "X-Was-Sanitized":     str(was).lower(),
        "X-Original-Filename": file.filename or "",
        "X-Scan-Duration-Ms":  str(ms),
        "Content-Disposition": f'attachment; filename="{fname}"',
    })


@app.post("/api/scan", tags=["Analysis"], summary="Full JSON forensic report")
async def scan(file: UploadFile = File(...),
               authorization: Optional[str] = Header(None)):
    """Detailed JSON analysis — used by the forensic dashboard UI."""
    _check_auth(authorization)
    if not file.filename or not _allowed(file.filename):
        raise HTTPException(400, "Unsupported file type.")
    raw = await file.read()
    if len(raw) > MAX_BYTES: raise HTTPException(413, "File too large (max 50 MB)")
    try:
        result = await _run(engine.process_file, raw, file.filename)
    except Exception as e:
        traceback.print_exc(); raise HTTPException(500, str(e))

    safe_b64    = _b64(result.pop("safe_file_bytes"))
    heatmap_b64 = _b64(result.pop("heatmap_bytes"))
    for t in ("zsteg","binwalk"):
        if isinstance(result.get(t), dict): result[t].pop("raw_output", None)
    return JSONResponse(_sanitise_floats({
        **result, "safe_b64":safe_b64, "heatmap_b64":heatmap_b64, "filename":file.filename
    }))


@app.post("/api/calibrate", tags=["Calibration"])
async def calibrate(files: list[UploadFile] = File(...), source: str = Form("unspecified"),
                    authorization: Optional[str] = Header(None)):
    _check_auth(authorization)
    raw_list, names = [], []
    for f in files:
        if f.filename and _allowed(f.filename):
            raw_list.append(await f.read()); names.append(f.filename)
    if not raw_list: raise HTTPException(400, "No valid images")
    try:
        await _run(engine.calibrate_from_bytes, raw_list, source)
        engine.save_calibration(CAL_PATH)
    except Exception as e:
        traceback.print_exc(); raise HTTPException(500, str(e))
    return {"success":True, "n_images":engine.calibration.n_images,
            "source":engine.calibration.source_hint,
            "report":engine.generate_calibration_report(), "filenames":names}


@app.get("/api/calibration/status", tags=["Calibration"])
async def calibration_status():
    if not engine.calibration or not engine.calibration.is_ready:
        return {"calibrated": False}
    cal = engine.calibration
    return {"calibrated":True,"source":cal.source_hint,"n_images":cal.n_images,
            "k_sigma":cal.K_SIGMA,"means":cal.means,"stds":cal.stds}


@app.post("/api/calibration/clear", tags=["Calibration"])
async def calibration_clear(authorization: Optional[str] = Header(None)):
    _check_auth(authorization)
    engine.calibration = None
    if os.path.exists(CAL_PATH): os.remove(CAL_PATH)
    return {"success": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5050))
    cal_info = (f"loaded ({engine.calibration.n_images} images)"
                if engine.calibration else "none  (POST /api/calibrate to build baseline)")
    print(f"""
  \u2554{'='*54}\u2557
  \u2551  StegGate API Server  v5.0{'':29}\u2551
  \u2560{'='*54}\u2563
  \u2551  http://localhost:{port:<5}{'':33}\u2551
  \u2551  http://localhost:{port:<5}/docs  \u2190 OpenAPI interactive docs{'':5}\u2551
  \u2560{'='*54}\u2563
  \u2551  POST /api/sanitize  \u2605 scan + return clean image{'':5}\u2551
  \u2551  POST /api/scan      full JSON forensic report{'':8}\u2551
  \u2551  GET  /api/health    liveness + tool status{'':11}\u2551
  \u2560{'='*54}\u2563
  \u2551  Auth : {"enabled" if STEGGATE_KEY else "disabled (set STEGGATE_KEY to enable)"}{'':19}\u2551
  \u2551  Cal  : {cal_info}{'':17}\u2551
  \u255a{'='*54}\u255d
""")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")