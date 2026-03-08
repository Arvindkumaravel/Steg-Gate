"""
StegGate Python Client SDK
===========================
Drop-in middleware for any Python web app (Flask, Django, FastAPI, etc.)

Usage — basic:
    from steggate_client import StegGateClient

    client = StegGateClient("http://localhost:5050")

    result = client.sanitize("photo.jpg", open("photo.jpg","rb").read())
    # result.safe_bytes  → clean image bytes to store
    # result.was_sanitized  → True if payload was removed
    # result.is_threat  → True if stego was detected

Usage — Flask middleware (automatic, zero-config):
    from steggate_client import StegGateFlaskMiddleware
    StegGateFlaskMiddleware(app, client, upload_fields=["avatar","image"])

Usage — Django:
    # settings.py
    STEGGATE_URL = "http://localhost:5050"
    STEGGATE_KEY = "your-key"          # optional
    STEGGATE_STORE_DIR = "media/clean" # where to write clean files

    # views.py
    from steggate_client import StegGateClient, django_clean_file
    client = StegGateClient(settings.STEGGATE_URL, api_key=settings.STEGGATE_KEY)
    cleaned = django_clean_file(client, request.FILES["avatar"])
    # cleaned is an InMemoryUploadedFile ready to save to a model field
"""

from __future__ import annotations

import io
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Optional, Union
from urllib.parse import urljoin

# ── optional deps (fail gracefully) ──────────────────────────────────────────
try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import httpx as _httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ─────────────────────────────────────────────────────────────────────────────
#  Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result of a /api/sanitize call."""
    # Decision
    is_threat:      bool
    risk_score:     float       # 0.0 – 100.0
    was_sanitized:  bool

    # File data
    safe_bytes:     bytes       # clean image bytes (store these)
    original_name:  str
    output_name:    str         # e.g. "photo_sanitized.jpg"
    content_type:   str         # e.g. "image/jpeg"

    # Timing
    scan_duration_ms: int

    # Raw headers for advanced use
    headers: dict = field(default_factory=dict)

    @property
    def threat_level(self) -> str:
        if self.risk_score >= 75:  return "HIGH"
        if self.risk_score >= 50:  return "MEDIUM"
        if self.risk_score >= 25:  return "LOW"
        return "NONE"

    def save(self, directory: Union[str, Path], filename: Optional[str] = None) -> Path:
        """Write safe_bytes to directory and return the full path."""
        out_dir  = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / (filename or self.output_name)
        out_path.write_bytes(self.safe_bytes)
        return out_path

    def __repr__(self) -> str:
        return (f"<ScanResult threat={self.is_threat} risk={self.risk_score:.1f} "
                f"sanitized={self.was_sanitized} file='{self.output_name}'>")


@dataclass
class StegGateError(Exception):
    status_code: int
    detail:      str
    def __str__(self): return f"StegGate {self.status_code}: {self.detail}"


# ─────────────────────────────────────────────────────────────────────────────
#  Core client
# ─────────────────────────────────────────────────────────────────────────────

class StegGateClient:
    """
    Synchronous StegGate API client.

    Args:
        base_url:  StegGate server URL, e.g. "http://localhost:5050"
        api_key:   Optional Bearer token (matches STEGGATE_KEY on server)
        timeout:   Per-request timeout in seconds (default 120 — scans are slow)
        on_threat: Optional callback(result: ScanResult) called when threat found
        force:     Always sanitize even if no threat detected
    """

    def __init__(
        self,
        base_url:  str,
        api_key:   str = "",
        timeout:   int = 120,
        on_threat: Optional[Callable[[ScanResult], None]] = None,
        force:     bool = False,
    ):
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url  = base_url.rstrip("/")
        self.api_key   = api_key
        self.timeout   = timeout
        self.on_threat = on_threat
        self.force     = force
        self._headers  = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    # ── Public API ────────────────────────────────────────────────────────────

    def sanitize(
        self,
        filename: str,
        data:     Union[bytes, BinaryIO],
        force:    Optional[bool] = None,
        webhook_url: str = "",
    ) -> ScanResult:
        """
        Scan an image and return a ScanResult.

        Args:
            filename:    Original filename (used for MIME detection)
            data:        Raw image bytes or file-like object
            force:       Override instance-level force setting
            webhook_url: Server will POST result JSON here after scanning

        Returns:
            ScanResult — check .was_sanitized and store .safe_bytes
        """
        raw = data if isinstance(data, bytes) else data.read()
        result = self._post_sanitize(filename, raw,
                                     force=force if force is not None else self.force,
                                     webhook_url=webhook_url)
        if result.is_threat and self.on_threat:
            self.on_threat(result)
        return result

    def sanitize_file(
        self,
        path: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
        **kwargs,
    ) -> ScanResult:
        """
        Scan a file on disk. If a threat is found and output_dir is set,
        writes the clean version there automatically.
        """
        p = Path(path)
        result = self.sanitize(p.name, p.read_bytes(), **kwargs)
        if output_dir and result.was_sanitized:
            result.save(output_dir)
        return result

    def health(self) -> dict:
        """Return API health status."""
        url = f"{self.base_url}/api/health"
        if _HAS_REQUESTS:
            r = _requests.get(url, headers=self._headers, timeout=10)
            return r.json()
        elif _HAS_HTTPX:
            with _httpx.Client() as c:
                return c.get(url, headers=self._headers, timeout=10).json()
        raise ImportError("Install requests or httpx: pip install requests")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _post_sanitize(self, filename: str, raw: bytes,
                       force: bool, webhook_url: str) -> ScanResult:
        url  = f"{self.base_url}/api/sanitize"
        data = {"force": str(force).lower(), "webhook_url": webhook_url}
        files = {"file": (filename, io.BytesIO(raw), _guess_mime(filename))}

        t0 = time.monotonic()
        if _HAS_REQUESTS:
            resp = _requests.post(url, files=files, data=data,
                                  headers=self._headers, timeout=self.timeout)
        elif _HAS_HTTPX:
            with _httpx.Client() as c:
                resp = c.post(url, files=files, data=data,
                              headers=self._headers, timeout=self.timeout)
        else:
            raise ImportError("Install requests or httpx: pip install requests")

        if resp.status_code >= 400:
            try:    detail = resp.json().get("detail", resp.text)
            except: detail = resp.text
            raise StegGateError(resp.status_code, detail)

        h = dict(resp.headers)
        elapsed = int((time.monotonic() - t0) * 1000)

        return ScanResult(
            is_threat      = h.get("x-threat-detected",  "false").lower() == "true",
            risk_score     = float(h.get("x-risk-score", "0")),
            was_sanitized  = h.get("x-was-sanitized",   "false").lower() == "true",
            safe_bytes     = resp.content,
            original_name  = h.get("x-original-filename", filename),
            output_name    = _parse_filename(h.get("content-disposition", ""), filename),
            content_type   = h.get("content-type", "image/jpeg"),
            scan_duration_ms = int(h.get("x-scan-duration-ms", elapsed)),
            headers        = h,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Async client
# ─────────────────────────────────────────────────────────────────────────────

class AsyncStegGateClient:
    """
    Async StegGate client for FastAPI / asyncio apps.

    Requires: pip install httpx

    Usage (FastAPI):
        client = AsyncStegGateClient("http://localhost:5050")

        @app.post("/upload")
        async def upload(file: UploadFile):
            raw = await file.read()
            result = await client.sanitize(file.filename, raw)
            await save_to_storage(result.output_name, result.safe_bytes)
    """

    def __init__(self, base_url: str, api_key: str = "", timeout: int = 120,
                 force: bool = False):
        if not _HAS_HTTPX:
            raise ImportError("pip install httpx")
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.force    = force
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    async def sanitize(self, filename: str, data: Union[bytes, BinaryIO],
                       force: Optional[bool] = None, webhook_url: str = "") -> ScanResult:
        raw = data if isinstance(data, bytes) else data.read()
        url = f"{self.base_url}/api/sanitize"
        frm = {"force": str(force if force is not None else self.force).lower(),
               "webhook_url": webhook_url}
        fls = {"file": (filename, io.BytesIO(raw), _guess_mime(filename))}

        async with _httpx.AsyncClient(timeout=self.timeout) as c:
            resp = await c.post(url, files=fls, data=frm, headers=self._headers)

        if resp.status_code >= 400:
            try:    detail = resp.json().get("detail", resp.text)
            except: detail = resp.text
            raise StegGateError(resp.status_code, detail)

        h = dict(resp.headers)
        return ScanResult(
            is_threat      = h.get("x-threat-detected",  "false").lower() == "true",
            risk_score     = float(h.get("x-risk-score", "0")),
            was_sanitized  = h.get("x-was-sanitized",   "false").lower() == "true",
            safe_bytes     = resp.content,
            original_name  = h.get("x-original-filename", filename),
            output_name    = _parse_filename(h.get("content-disposition", ""), filename),
            content_type   = h.get("content-type", "image/jpeg"),
            scan_duration_ms = int(h.get("x-scan-duration-ms", 0)),
            headers        = h,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Framework integrations
# ─────────────────────────────────────────────────────────────────────────────

class StegGateFlaskMiddleware:
    """
    Automatic Flask upload sanitization.

    Wraps request.files — any file in upload_fields is transparently
    scanned and replaced with the clean version before your view runs.

    Usage:
        app = Flask(__name__)
        client = StegGateClient("http://localhost:5050")
        StegGateFlaskMiddleware(app, client, upload_fields=["avatar","photo"])

        @app.route("/upload", methods=["POST"])
        def upload():
            # request.files["avatar"] is already sanitized here
            f = request.files["avatar"]
            f.save(f"uploads/{f.filename}")
    """

    def __init__(self, app, client: StegGateClient,
                 upload_fields: list[str] = None,
                 on_threat: Optional[Callable] = None):
        self.app     = app
        self.client  = client
        self.fields  = set(upload_fields or [])
        self.on_threat = on_threat
        app.before_request(self._intercept)

    def _intercept(self):
        try:
            from flask import request
            from werkzeug.datastructures import FileStorage
        except ImportError:
            return

        for field in self.fields:
            if field not in request.files:
                continue
            fs = request.files[field]
            if not fs or not fs.filename:
                continue
            try:
                raw    = fs.read()
                result = self.client.sanitize(fs.filename, raw)
                if result.is_threat and self.on_threat:
                    self.on_threat(result, field)
                # Replace with clean bytes, transparently
                new_fs = FileStorage(
                    stream   = io.BytesIO(result.safe_bytes),
                    filename = result.output_name,
                    content_type = result.content_type,
                    name     = field,
                )
                request.files = request.files.copy()
                request.files[field] = new_fs
            except Exception as e:
                app = self.app
                app.logger.error(f"[StegGate] scan failed for '{field}': {e}")


def django_clean_file(client: StegGateClient, uploaded_file) -> object:
    """
    Scan a Django UploadedFile and return a clean InMemoryUploadedFile.

    Usage:
        from steggate_client import StegGateClient, django_clean_file

        client = StegGateClient(settings.STEGGATE_URL)

        class AvatarUploadView(View):
            def post(self, request):
                clean = django_clean_file(client, request.FILES["avatar"])
                profile.avatar.save(clean.name, clean, save=True)
    """
    try:
        from django.core.files.uploadedfile import InMemoryUploadedFile
    except ImportError:
        raise ImportError("Django is not installed")

    raw    = uploaded_file.read()
    result = client.sanitize(uploaded_file.name, raw)
    return InMemoryUploadedFile(
        file         = io.BytesIO(result.safe_bytes),
        field_name   = None,
        name         = result.output_name,
        content_type = result.content_type,
        size         = len(result.safe_bytes),
        charset      = None,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Utilities
# ─────────────────────────────────────────────────────────────────────────────

_MIME_MAP = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "bmp": "image/bmp",  "webp": "image/webp", "tiff": "image/tiff",
}

def _guess_mime(filename: str) -> str:
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    return _MIME_MAP.get(ext, "application/octet-stream")

def _parse_filename(disposition: str, fallback: str) -> str:
    import re
    m = re.search(r'filename="?([^";\r\n]+)"?', disposition)
    return m.group(1) if m else fallback