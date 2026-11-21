"""Heuristics for high-CPU and suspicious executable paths."""

from __future__ import annotations

import os
from pathlib import Path

from process_hunter.processes import ProcessInfo


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path.strip()))


def suspicious_path_roots() -> list[str]:
    """Directories that commonly host unwanted or temporary executables."""
    roots: list[str] = []
    candidates = [
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
        r"C:\Windows\Temp",
        r"C:\Temp",
    ]
    for item in candidates:
        if item and os.path.isdir(item):
            roots.append(_norm(item))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for root in roots:
        if root not in seen:
            seen.add(root)
            unique.append(root)
    return unique


def trusted_path_prefixes() -> list[str]:
    """Paths generally considered normal for software to run from."""
    prefixes: list[str] = []
    windir = os.environ.get("WINDIR", r"C:\Windows")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get(
        "ProgramFiles(x86)", r"C:\Program Files (x86)"
    )
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")

    for item in (
        windir,
        program_files,
        program_files_x86,
        program_data,
        local_appdata,
        appdata,
    ):
        if item:
            prefixes.append(_norm(item))
    return prefixes


def is_under(path: str, roots: list[str]) -> bool:
    if not path:
        return False
    normalized = _norm(path)
    for root in roots:
        if normalized == root or normalized.startswith(root + os.sep):
            return True
    return False


def is_suspicious_path(exe: str) -> bool:
    """
    True if the executable lives under Temp/Downloads/Desktop, or outside
    common trusted install locations.
    """
    if not exe:
        return False

    path = Path(exe)
    # Only flag real .exe paths we can resolve
    if path.suffix.lower() not in {".exe", ".com", ".scr", ".bat", ".cmd"}:
        return False

    if is_under(exe, suspicious_path_roots()):
        return True

    # Unknown location outside trusted prefixes is mildly suspicious
    if not is_under(exe, trusted_path_prefixes()):
        # Ignore bare names / inaccessible paths
        if os.sep in exe or (len(exe) >= 3 and exe[1] == ":"):
            return True
    return False


def is_high_cpu(info: ProcessInfo, threshold: float) -> bool:
    return info.cpu_percent >= threshold


def classify_alert_reason(
    info: ProcessInfo,
    threshold: float,
    sustained_hit: bool,
) -> str | None:
    """
    Return a short reason string if this process should raise an alert,
    otherwise None.
    """
    reasons: list[str] = []
    if sustained_hit and is_high_cpu(info, threshold):
        reasons.append(f"high CPU ({info.cpu_percent:.1f}%)")
    if is_suspicious_path(info.exe):
        reasons.append("suspicious path")
    if not reasons:
        return None
    return "; ".join(reasons)
