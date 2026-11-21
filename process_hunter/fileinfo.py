"""Collect detailed information about a process and its executable file."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

import psutil

from process_hunter.explanations import explain_process

logger = logging.getLogger(__name__)


def _fmt_bytes(num: int | float) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num} B"


def _fmt_ts(timestamp: float | None) -> str:
    if not timestamp:
        return "(unknown)"
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "(invalid date)"


def _hash_file(path: Path, algorithm: str = "sha256", limit: int | None = None) -> str:
    """Hash a file; optional limit reads only the first N bytes (for huge files)."""
    h = hashlib.new(algorithm)
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
            if limit is not None and total >= limit:
                return h.hexdigest() + f" (first {_fmt_bytes(limit)} only)"
    return h.hexdigest()


def _version_info(path: Path) -> dict[str, str]:
    """Read Windows version resource strings via PowerShell (best-effort)."""
    fields = (
        "FileDescription",
        "ProductName",
        "CompanyName",
        "FileVersion",
        "ProductVersion",
        "OriginalFilename",
        "InternalName",
        "LegalCopyright",
    )
    script = (
        "$p = $env:PH_PATH; "
        "try { "
        "  $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p); "
        "  foreach ($n in @("
        + ",".join(f"'{f}'" for f in fields)
        + ")) { "
        "    $val = $v.$n; "
        "    if ($null -eq $val) { $val = '' }; "
        "    Write-Output ($n + '=' + ($val -replace '[\\r\\n]', ' ')); "
        "  } "
        "} catch { Write-Output ('ERROR=' + $_.Exception.Message) }"
    )
    env = os.environ.copy()
    env["PH_PATH"] = str(path)
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Version info failed: %s", exc)
        return {}

    result: dict[str, str] = {}
    for line in (completed.stdout or "").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


def _signature_info(path: Path) -> dict[str, str]:
    """Read Authenticode signature status via PowerShell."""
    script = (
        "$p = $env:PH_PATH; "
        "try { "
        "  $s = Get-AuthenticodeSignature -FilePath $p; "
        "  Write-Output ('Status=' + $s.Status); "
        "  Write-Output ('StatusMessage=' + ($s.StatusMessage -replace '[\\r\\n]', ' ')); "
        "  if ($s.SignerCertificate) { "
        "    Write-Output ('Signer=' + ($s.SignerCertificate.Subject -replace '[\\r\\n]', ' ')); "
        "    Write-Output ('Issuer=' + ($s.SignerCertificate.Issuer -replace '[\\r\\n]', ' ')); "
        "    Write-Output ('Thumbprint=' + $s.SignerCertificate.Thumbprint); "
        "    Write-Output ('NotBefore=' + $s.SignerCertificate.NotBefore.ToString('yyyy-MM-dd')); "
        "    Write-Output ('NotAfter=' + $s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd')); "
        "  } else { Write-Output 'Signer=(none)'; } "
        "} catch { Write-Output ('ERROR=' + $_.Exception.Message) }"
    )
    env = os.environ.copy()
    env["PH_PATH"] = str(path)
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Signature info failed: %s", exc)
        return {"Status": "Unavailable", "StatusMessage": str(exc)}

    result: dict[str, str] = {}
    for line in (completed.stdout or "").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            result[key] = value or "(empty)"
    return result or {"Status": "Unknown"}


def _process_details(pid: int) -> dict[str, str]:
    details: dict[str, str] = {"PID": str(pid)}
    try:
        proc = psutil.Process(pid)
    except (psutil.Error, OSError):
        details["Status"] = "Process no longer running"
        return details

    try:
        details["Name"] = proc.name() or "(unknown)"
    except (psutil.Error, OSError):
        details["Name"] = "(unknown)"

    try:
        details["Status"] = proc.status()
    except (psutil.Error, OSError):
        pass

    try:
        details["Username"] = proc.username()
    except (psutil.Error, OSError):
        details["Username"] = "(access denied)"

    try:
        details["Create time"] = _fmt_ts(proc.create_time())
    except (psutil.Error, OSError):
        pass

    try:
        details["Command line"] = " ".join(proc.cmdline()) or "(empty)"
    except (psutil.Error, OSError):
        details["Command line"] = "(access denied)"

    try:
        parent = proc.parent()
        if parent:
            details["Parent"] = f"{parent.name()} (PID {parent.pid})"
        else:
            details["Parent"] = "(none)"
    except (psutil.Error, OSError):
        details["Parent"] = "(access denied)"

    try:
        mem = proc.memory_info()
        details["Memory (RSS)"] = _fmt_bytes(mem.rss)
        details["Memory (VMS)"] = _fmt_bytes(mem.vms)
    except (psutil.Error, OSError):
        pass

    try:
        cpu = proc.cpu_percent(interval=0.15)
        details["CPU % (sample)"] = f"{cpu:.1f}"
    except (psutil.Error, OSError):
        pass

    try:
        details["Executable"] = proc.exe() or "(unknown)"
    except (psutil.Error, OSError):
        details["Executable"] = "(access denied)"

    try:
        cwd = proc.cwd()
        if cwd:
            details["Working directory"] = cwd
    except (psutil.Error, OSError):
        pass

    try:
        nice = proc.nice()
        details["Priority"] = str(nice)
    except (psutil.Error, OSError):
        pass

    try:
        connections = proc.net_connections(kind="inet")
        established = [
            c
            for c in connections
            if c.status == psutil.CONN_ESTABLISHED and c.raddr
        ]
        details["Network connections"] = str(len(connections))
        if established:
            sample = established[:5]
            lines = []
            for conn in sample:
                rhost = conn.raddr.ip if conn.raddr else "?"
                rport = conn.raddr.port if conn.raddr else "?"
                lines.append(f"{rhost}:{rport}")
            details["Remote endpoints (sample)"] = ", ".join(lines)
    except (psutil.Error, OSError):
        details["Network connections"] = "(access denied)"

    return details


def _file_details(path: Path) -> dict[str, str]:
    info: dict[str, str] = {"Path": str(path)}
    if not path.exists():
        info["Exists"] = "No — file missing or inaccessible"
        return info

    info["Exists"] = "Yes"
    try:
        stat = path.stat()
        info["Size"] = f"{_fmt_bytes(stat.st_size)} ({stat.st_size} bytes)"
        info["Created"] = _fmt_ts(getattr(stat, "st_ctime", None))
        info["Modified"] = _fmt_ts(getattr(stat, "st_mtime", None))
        info["Accessed"] = _fmt_ts(getattr(stat, "st_atime", None))
    except OSError as exc:
        info["Stat error"] = str(exc)
        return info

    try:
        info["SHA-256"] = _hash_file(path)
    except PermissionError as exc:
        info["SHA-256"] = (
            f"(access denied — file locked or ACL protected: {exc})"
        )
    except OSError as exc:
        info["SHA-256"] = f"(failed: {exc})"

    try:
        info["MD5"] = _hash_file(path, "md5")
    except PermissionError as exc:
        info["MD5"] = f"(access denied: {exc})"
    except OSError as exc:
        info["MD5"] = f"(failed: {exc})"

    # Location heuristics
    lower = str(path).lower()
    hints: list[str] = []
    if "\\temp\\" in lower or lower.endswith("\\temp"):
        hints.append("Runs from a Temp folder (often suspicious for unknown apps)")
    if "\\downloads\\" in lower:
        hints.append("Runs from Downloads")
    if "\\appdata\\" in lower:
        hints.append("Runs from AppData")
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()
    if lower.startswith(windir.lower()):
        hints.append("Located under the Windows directory")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files").lower()
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower()
    if lower.startswith(pf) or lower.startswith(pf86):
        hints.append("Located under Program Files (typical for installed software)")
    if hints:
        info["Location notes"] = "; ".join(hints)

    return info


def _assess_safety(
    *,
    name: str,
    exe: str,
    reason: str,
    file_info: dict[str, str],
    version: dict[str, str],
    signature: dict[str, str],
    process: dict[str, str],
) -> list[str]:
    """
    Heuristic safety summary based on gathered signals.

    Not antivirus — a practical judgment to help the user decide.
    """
    positives: list[str] = []
    warnings: list[str] = []
    risks: list[str] = []
    score = 0  # higher = safer; negative = more concerning

    path_lower = (exe or "").lower().replace("/", "\\")
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()
    pf = os.environ.get("ProgramFiles", r"C:\Program Files").lower()
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower()

    # Location
    if path_lower.startswith(pf) or path_lower.startswith(pf86):
        positives.append("Installed under Program Files (normal for legitimate software)")
        score += 2
    elif path_lower.startswith(windir) and "\\temp\\" not in path_lower:
        positives.append("Located under the Windows folder (typical for system components)")
        score += 2
    if "\\temp\\" in path_lower:
        risks.append("Running from a Temp folder")
        score -= 3
    if "\\downloads\\" in path_lower:
        risks.append("Running from Downloads")
        score -= 3
    if "\\appdata\\local\\temp\\" in path_lower:
        risks.append("Running from AppData Local Temp")
        score -= 3
    elif "\\appdata\\" in path_lower:
        warnings.append("Running from AppData (common for some apps, also for malware)")
        score -= 1

    # Signature
    status = (signature.get("Status") or "").lower()
    signer = signature.get("Signer") or ""
    if status == "valid":
        positives.append(f"Valid digital signature ({signer or 'publisher present'})")
        score += 4
        signer_l = signer.lower()
        trusted_markers = (
            "microsoft",
            "windows",
            "google",
            "mozilla",
            "adobe",
            "intel",
            "nvidia",
            "amd ",
            "apple",
            "dropbox",
            "surfshark",
            "cisco",
            "norton",
            "avast",
            "bitdefender",
        )
        if any(marker in signer_l for marker in trusted_markers):
            positives.append("Signer looks like a known software vendor")
            score += 2
    elif status == "notsigned":
        warnings.append("File is not digitally signed")
        score -= 2
    elif status in {"hashmismatch", "nottrusted", "unknownerror"} or status:
        if status not in {"", "unknown", "unavailable"}:
            risks.append(f"Signature status is '{signature.get('Status')}'")
            score -= 3

    # Version / publisher metadata
    company = (version.get("CompanyName") or "").strip()
    product = (version.get("ProductName") or "").strip()
    description = (version.get("FileDescription") or "").strip()
    if company:
        positives.append(f"Has company metadata: {company}")
        score += 1
    else:
        warnings.append("No CompanyName in file version info")
        score -= 1
    if product or description:
        positives.append(
            f"Identifies as: {product or description}"
        )
        score += 1
    else:
        warnings.append("No product/description metadata")
        score -= 1

    # Alert reason
    reason_l = (reason or "").lower()
    if "suspicious path" in reason_l:
        warnings.append("Flagged because of an unusual executable path")
        score -= 1
    if "high cpu" in reason_l:
        warnings.append("Using sustained high CPU (could be busy work or a runaway process)")
        # High CPU alone is not malware
        score -= 0

    # Process behaviour hints
    cmdline = (process.get("Command line") or "").lower()
    if "powershell" in name.lower() and (
        "-enc" in cmdline or "-e " in cmdline or "downloadstring" in cmdline
    ):
        risks.append("PowerShell with encoded/download-style command line")
        score -= 4
    if "\\temp\\" in cmdline and ".exe" in cmdline:
        warnings.append("Command line references a Temp path")
        score -= 1

    net = process.get("Network connections") or ""
    if net.isdigit() and int(net) > 20:
        warnings.append(f"Many network connections open ({net})")
        score -= 1

    if file_info.get("Exists", "").startswith("No"):
        risks.append("Executable file could not be found on disk")
        score -= 2

    # Verdict
    if score >= 5:
        verdict = "LIKELY SAFE"
        summary = (
            "This looks like a normal signed/installed program. "
            "Still confirm you recognise the publisher and why it was flagged."
        )
    elif score >= 2:
        verdict = "PROBABLY SAFE — VERIFY"
        summary = (
            "More signs point to a legitimate app than malware, but check the "
            "publisher name and that you expect this process to be running."
        )
    elif score >= -1:
        verdict = "CAUTION — UNCLEAR"
        summary = (
            "Mixed signals. It may be legitimate (portable app, updater, etc.) "
            "or unwanted. Prefer More info + VirusTotal before allowing it."
        )
    elif score >= -4:
        verdict = "SUSPICIOUS"
        summary = (
            "Several warning signs. Do not allow-list it yet. Consider VirusTotal, "
            "kill it, or open the folder and inspect the file."
        )
    else:
        verdict = "HIGH RISK — TREAT AS UNSAFE"
        summary = (
            "Strong risk indicators. Prefer kill/ban (and VirusTotal). "
            "Only keep it if you are certain you trust this exact program."
        )

    lines = [
        "",
        "=== Assessment (heuristic — not antivirus) ===",
        f"Verdict: {verdict}",
        summary,
        f"Confidence score: {score} (higher = safer)",
    ]
    if positives:
        lines.append("Positive signs:")
        lines.extend(f"  + {item}" for item in positives)
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"  ! {item}" for item in warnings)
    if risks:
        lines.append("Risk signs:")
        lines.extend(f"  - {item}" for item in risks)

    lines.append(
        "Suggested action: "
        + (
            "Allow list if you trust it, or Dismiss."
            if score >= 2
            else (
                "Submit to VirusTotal and/or Kill — avoid Allow list until checked."
                if score < 0
                else "Verify publisher, then Allow list or Kill as appropriate."
            )
        )
    )
    return lines


def gather_file_intelligence(
    *,
    pid: int,
    name: str,
    exe: str,
    reason: str = "",
    cpu_percent: float | None = None,
) -> str:
    """
    Build a human-readable report about a process and its on-disk file,
    ending with a safety assessment.
    """
    sections: list[str] = []

    sections.append("=== Alert ===")
    sections.append(f"Process name: {name}")
    sections.append(f"PID: {pid}")
    if reason:
        sections.append(f"Flagged for: {reason}")
    if cpu_percent is not None:
        sections.append(f"CPU at alert: {cpu_percent:.1f}%")
    sections.append(f"Built-in note: {explain_process(name)}")
    sections.append("")

    process = _process_details(pid)
    sections.append("=== Process ===")
    for key, value in process.items():
        sections.append(f"{key}: {value}")
    sections.append("")

    path = Path(exe) if exe else None
    file_info: dict[str, str] = {}
    version: dict[str, str] = {}
    signature: dict[str, str] = {}

    if path is None or not str(path).strip():
        sections.append("=== File ===")
        sections.append("No executable path available.")
        sections.extend(
            _assess_safety(
                name=name,
                exe="",
                reason=reason,
                file_info={"Exists": "No"},
                version={},
                signature={},
                process=process,
            )
        )
        return "\n".join(sections)

    try:
        file_info = _file_details(path)
    except PermissionError as exc:
        file_info = {
            "Path": str(path),
            "Exists": "Yes (likely) — Access denied when reading",
            "Note": str(exc),
        }
    sections.append("=== File ===")
    for key, value in file_info.items():
        sections.append(f"{key}: {value}")
    sections.append("")

    # DismHost in Windows\Temp is a common Windows servicing helper
    if path.name.lower() == "dismhost.exe":
        sections.append(
            "Note: DismHost.exe is normally Windows DISM (image servicing). "
            "It often appears under C:\\Windows\\Temp while Windows Update / "
            "DISM runs. Access denied usually means the file is locked by that "
            "process — kill it first, then delete if you still want it gone."
        )
        sections.append("")

    if path.exists():
        sections.append("=== Version info ===")
        try:
            version = _version_info(path)
        except Exception:
            version = {}
        if version:
            for key, value in version.items():
                sections.append(f"{key}: {value}")
        else:
            sections.append("(none available or access denied)")
        sections.append("")

        sections.append("=== Digital signature ===")
        try:
            signature = _signature_info(path)
        except Exception:
            signature = {"Status": "Unavailable"}
        for key, value in signature.items():
            sections.append(f"{key}: {value}")
        status = (signature.get("Status") or "").lower()
        if status == "valid":
            sections.append(
                "Interpretation: Signed by a trusted publisher (still verify the signer name)."
            )
        elif status == "notsigned":
            sections.append(
                "Interpretation: Not signed — common for malware and also some legit portable apps."
            )
        elif status:
            sections.append(
                "Interpretation: Signature problem or locked file — treat with caution."
            )

    sections.extend(
        _assess_safety(
            name=name,
            exe=str(path),
            reason=reason,
            file_info=file_info,
            version=version,
            signature=signature,
            process=process,
        )
    )

    return "\n".join(sections)
