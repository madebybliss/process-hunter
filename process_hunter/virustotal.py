"""VirusTotal file lookup and upload helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from process_hunter.config import project_root

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_GUI_FILE = "https://www.virustotal.com/gui/file/{sha256}"
MAX_UPLOAD_BYTES = 32 * 1024 * 1024  # Free API direct upload limit


@dataclass
class VirusTotalResult:
    """Summary of a VirusTotal file analysis."""

    ok: bool
    message: str
    sha256: str = ""
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    permalink: str = ""
    uploaded: bool = False

    @property
    def summary_line(self) -> str:
        if not self.ok:
            return self.message
        return (
            f"Malicious: {self.malicious}  |  Suspicious: {self.suspicious}  |  "
            f"Undetected: {self.undetected}  |  Harmless: {self.harmless}"
        )


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE pairs from .env into os.environ (does not override existing)."""
    env_path = path or (project_root() / ".env")
    if not env_path.is_file():
        return
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Could not read .env")
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def get_api_key() -> str:
    load_dotenv()
    return (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _vt_request(
    method: str,
    url: str,
    api_key: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> tuple[int, dict]:
    req_headers = {"x-apikey": api_key, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    request = urllib.request.Request(
        url, data=data, headers=req_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            payload = json.loads(body) if body else {}
            return int(response.status), payload if isinstance(payload, dict) else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {"error": {"message": body or str(exc)}}
        if not isinstance(payload, dict):
            payload = {"error": {"message": str(exc)}}
        return int(exc.code), payload
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.exception("VirusTotal request failed")
        return 0, {"error": {"message": str(exc)}}


def _stats_from_attributes(attrs: dict) -> tuple[int, int, int, int, int]:
    stats = attrs.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    return (
        int(stats.get("malicious") or 0),
        int(stats.get("suspicious") or 0),
        int(stats.get("undetected") or 0),
        int(stats.get("harmless") or 0),
        int(stats.get("timeout") or 0),
    )


def _result_from_file_data(
    data: dict, sha256: str, uploaded: bool = False
) -> VirusTotalResult:
    attrs = data.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}
    malicious, suspicious, undetected, harmless, timeout = _stats_from_attributes(
        attrs
    )
    link = VT_GUI_FILE.format(sha256=sha256)
    verdict = "clean"
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "suspicious"
    uploaded_note = " (newly uploaded; engines may still be scanning)" if uploaded else ""
    return VirusTotalResult(
        ok=True,
        message=(
            f"VirusTotal verdict: {verdict}{uploaded_note}\n"
            f"Malicious: {malicious} | Suspicious: {suspicious} | "
            f"Undetected: {undetected} | Harmless: {harmless}"
        ),
        sha256=sha256,
        malicious=malicious,
        suspicious=suspicious,
        undetected=undetected,
        harmless=harmless,
        timeout=timeout,
        permalink=link,
        uploaded=uploaded,
    )


def _multipart_body(file_path: Path) -> tuple[bytes, str]:
    boundary = f"----ProcessHunterBoundary{int(time.time())}"
    filename = file_path.name
    file_bytes = file_path.read_bytes()
    parts = [
        f"--{boundary}\r\n".encode(),
        (
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode(),
        file_bytes,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    body = b"".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def _poll_analysis(
    api_key: str, analysis_id: str, sha256: str, attempts: int = 12
) -> VirusTotalResult:
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    for _ in range(attempts):
        status, payload = _vt_request("GET", url, api_key, timeout=30.0)
        if status != 200:
            time.sleep(2)
            continue
        data = payload.get("data") or {}
        attrs = data.get("attributes") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        state = str(attrs.get("status") or "")
        if state == "completed":
            # Prefer file report for full stats
            return _fetch_file_report(api_key, sha256, uploaded=True)
        time.sleep(2)
    return _fetch_file_report(api_key, sha256, uploaded=True)


def _fetch_file_report(
    api_key: str, sha256: str, uploaded: bool = False
) -> VirusTotalResult:
    status, payload = _vt_request(
        "GET", f"{VT_API_BASE}/files/{sha256}", api_key, timeout=45.0
    )
    if status == 200:
        data = payload.get("data") or {}
        if isinstance(data, dict):
            return _result_from_file_data(data, sha256, uploaded=uploaded)
    return VirusTotalResult(
        ok=True,
        message=(
            "Submitted to VirusTotal. Analysis may still be running — "
            "open the report link for live results."
        ),
        sha256=sha256,
        permalink=VT_GUI_FILE.format(sha256=sha256),
        uploaded=uploaded,
    )


def lookup_or_upload(
    file_path: Path | None,
    sha256: str | None = None,
    api_key: str | None = None,
) -> VirusTotalResult:
    """
    Look up a file on VirusTotal by SHA-256; upload if unknown and path is given.
    """
    key = (api_key or get_api_key()).strip()
    if not key:
        return VirusTotalResult(
            ok=False,
            message=(
                "VirusTotal API key not set. Add VIRUSTOTAL_API_KEY to the .env "
                "file in the Process Hunter folder, then restart."
            ),
        )

    path: Path | None = None
    if file_path is not None:
        path = Path(file_path)
        if not path.is_file():
            return VirusTotalResult(
                ok=False,
                message=f"File not found: {path}",
            )
        try:
            digest = sha256_file(path)
        except OSError as exc:
            return VirusTotalResult(ok=False, message=f"Could not hash file: {exc}")
    else:
        digest = (sha256 or "").strip().lower()
        if not digest:
            return VirusTotalResult(ok=False, message="No file hash available.")

    status, payload = _vt_request(
        "GET", f"{VT_API_BASE}/files/{digest}", key, timeout=45.0
    )
    if status == 200:
        data = payload.get("data") or {}
        if isinstance(data, dict):
            return _result_from_file_data(data, digest, uploaded=False)
        return VirusTotalResult(ok=False, message="Unexpected VirusTotal response.")

    if status == 404:
        if path is None:
            return VirusTotalResult(
                ok=False,
                message="File is not on VirusTotal yet (no local file to upload).",
                sha256=digest,
                permalink=VT_GUI_FILE.format(sha256=digest),
            )
        size = path.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            return VirusTotalResult(
                ok=False,
                message=(
                    f"File is {size // (1024 * 1024)} MB; free VirusTotal upload "
                    f"limit is 32 MB. Hash: {digest}"
                ),
                sha256=digest,
                permalink=VT_GUI_FILE.format(sha256=digest),
            )
        body, content_type = _multipart_body(path)
        up_status, up_payload = _vt_request(
            "POST",
            f"{VT_API_BASE}/files",
            key,
            data=body,
            headers={"Content-Type": content_type},
            timeout=120.0,
        )
        if up_status not in (200, 201):
            err = "Upload failed"
            error_obj = up_payload.get("error")
            if isinstance(error_obj, dict) and error_obj.get("message"):
                err = str(error_obj["message"])
            elif status == 401 or up_status == 401:
                err = "Invalid VirusTotal API key."
            elif up_status == 429:
                err = "VirusTotal rate limit hit — try again in a minute."
            return VirusTotalResult(
                ok=False,
                message=err,
                sha256=digest,
                permalink=VT_GUI_FILE.format(sha256=digest),
            )
        analysis = (up_payload.get("data") or {}).get("id")
        if isinstance(analysis, str) and analysis:
            result = _poll_analysis(key, analysis, digest)
            if result.ok:
                result.uploaded = True
                if "newly uploaded" not in result.message:
                    result.message = (
                        "Uploaded to VirusTotal.\n" + result.message
                    )
            return result
        return VirusTotalResult(
            ok=True,
            message="Uploaded to VirusTotal. Open the report link for results.",
            sha256=digest,
            permalink=VT_GUI_FILE.format(sha256=digest),
            uploaded=True,
        )

    if status == 401:
        return VirusTotalResult(ok=False, message="Invalid VirusTotal API key.")
    if status == 429:
        return VirusTotalResult(
            ok=False,
            message="VirusTotal rate limit hit — try again in a minute.",
            sha256=digest,
        )

    err = "VirusTotal request failed"
    error_obj = payload.get("error")
    if isinstance(error_obj, dict) and error_obj.get("message"):
        err = str(error_obj["message"])
    return VirusTotalResult(ok=False, message=err, sha256=digest)


def scan_executable(exe_path: str) -> VirusTotalResult:
    """Scan a process executable path on VirusTotal."""
    if not exe_path or not exe_path.strip():
        return VirusTotalResult(
            ok=False,
            message="No executable path available to submit.",
        )
    return lookup_or_upload(Path(exe_path))
