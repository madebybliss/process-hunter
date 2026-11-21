"""Process listing, never-kill guard, and safe terminate helpers."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)

# Hardcoded — cannot be overridden by config.
NEVER_KILL_NAMES: frozenset[str] = frozenset(
    {
        "system",
        "system idle process",
        "registry",
        "memory compression",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "dwm.exe",
        "explorer.exe",
        "fontdrvhost.exe",
        "conhost.exe",
        "sihost.exe",
        "taskhostw.exe",
        "ctfmon.exe",
        "securityhealthservice.exe",
        "msmpeng.exe",
        "nissrv.exe",
        "sgrmbroker.exe",
    }
)


@dataclass(frozen=True)
class ProcessInfo:
    """Snapshot of a running process used by the monitor."""

    pid: int
    name: str
    exe: str
    cpu_percent: float


def is_never_kill(name: str | None) -> bool:
    if not name:
        return True
    return name.strip().lower() in NEVER_KILL_NAMES


def _safe_name(proc: psutil.Process) -> str:
    try:
        return proc.name() or ""
    except (psutil.Error, OSError):
        return ""


def _safe_exe(proc: psutil.Process) -> str:
    try:
        exe = proc.exe()
        return exe or ""
    except (psutil.Error, OSError):
        return ""


def iter_process_snapshots() -> list[ProcessInfo]:
    """
    Collect process snapshots with CPU percentages.

    Calls cpu_percent twice with a short interval so values are meaningful.
    """
    procs: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            procs.append(proc)
            proc.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            continue

    # Brief sample window so cpu_percent returns non-zero where busy.
    psutil.cpu_percent(interval=0.2)

    snapshots: list[ProcessInfo] = []
    for proc in procs:
        try:
            if not proc.is_running():
                continue
            name = _safe_name(proc)
            exe = _safe_exe(proc)
            cpu = float(proc.cpu_percent(interval=None) or 0.0)
            snapshots.append(
                ProcessInfo(
                    pid=proc.pid,
                    name=name,
                    exe=exe,
                    cpu_percent=cpu,
                )
            )
        except (psutil.Error, OSError):
            continue
    return snapshots


def kill_process(pid: int, name_hint: str = "") -> tuple[bool, str]:
    """
    Terminate a process by PID if it is not on the never-kill list.

    Returns (success, message).
    """
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.Error):
        return False, f"Process PID {pid} no longer exists."

    name = _safe_name(proc) or name_hint or f"PID {pid}"
    if is_never_kill(name):
        return False, f"Refused to kill protected process: {name}"

    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        return True, f"Killed {name} (PID {pid})"
    except psutil.AccessDenied:
        return (
            False,
            f"Access denied killing {name} (PID {pid}). "
            "Try running Process Hunter as Administrator.",
        )
    except psutil.NoSuchProcess:
        return True, f"{name} (PID {pid}) already exited."
    except (psutil.Error, OSError) as exc:
        logger.exception("Failed to kill PID %s", pid)
        return False, f"Failed to kill {name} (PID {pid}): {exc}"


def open_path(path: Path) -> None:
    """Open a file or folder with the default Windows handler."""
    target = str(path)
    if path.is_dir():
        os.startfile(target)  # type: ignore[attr-defined]
    else:
        subprocess.Popen(["notepad.exe", target], shell=False)


def open_containing_folder(exe_path: str) -> tuple[bool, str]:
    """Open Explorer focused on the executable (or its parent folder)."""
    if not exe_path or not exe_path.strip():
        return False, "No executable path available."

    path = Path(exe_path)
    try:
        if path.is_file():
            # Select the file in Explorer
            subprocess.Popen(
                ["explorer.exe", f"/select,{path}"],
                shell=False,
            )
            return True, f"Opened folder for {path.name}"
        if path.parent.is_dir():
            os.startfile(str(path.parent))  # type: ignore[attr-defined]
            return True, f"Opened folder {path.parent}"
        return False, f"Path not found: {exe_path}"
    except OSError as exc:
        logger.exception("Failed to open folder for %s", exe_path)
        return False, f"Could not open folder: {exc}"


def _is_protected_delete_path(exe_path: str) -> bool:
    """Refuse deleting binaries from core Windows / Program Files locations."""
    if not exe_path:
        return True
    normalized = os.path.normcase(os.path.normpath(exe_path))
    windir = os.path.normcase(
        os.path.normpath(os.environ.get("WINDIR", r"C:\Windows"))
    )
    program_files = os.path.normcase(
        os.path.normpath(os.environ.get("ProgramFiles", r"C:\Program Files"))
    )
    program_files_x86 = os.path.normcase(
        os.path.normpath(
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        )
    )
    # Allow Windows\Temp only
    win_temp = os.path.normcase(os.path.normpath(os.path.join(windir, "Temp")))

    protected_roots = (program_files, program_files_x86)
    for root in protected_roots:
        if normalized == root or normalized.startswith(root + os.sep):
            return True

    if normalized == windir or normalized.startswith(windir + os.sep):
        if not (
            normalized == win_temp or normalized.startswith(win_temp + os.sep)
        ):
            return True
    return False


def kill_processes_using_exe(exe_path: str) -> list[str]:
    """Terminate any running processes whose exe matches this path."""
    if not exe_path:
        return []
    target = os.path.normcase(os.path.normpath(exe_path))
    messages: list[str] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc_exe = proc.exe()
        except (psutil.Error, OSError):
            continue
        if not proc_exe:
            continue
        if os.path.normcase(os.path.normpath(proc_exe)) != target:
            continue
        name = _safe_name(proc) or Path(proc_exe).name
        if is_never_kill(name):
            messages.append(f"Skipped protected process {name} (PID {proc.pid})")
            continue
        ok, msg = kill_process(proc.pid, name)
        messages.append(msg if ok else f"Could not kill {name}: {msg}")
    return messages


def _try_take_ownership(path: Path) -> str | None:
    """
    Best-effort takeown + grant Administrators full control (Windows).
    Returns an error string on failure, or None on success.
    """
    try:
        takeown = subprocess.run(
            ["takeown", "/F", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        icacls = subprocess.run(
            ["icacls", str(path), "/grant", "Administrators:F"],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        if takeown.returncode != 0 and icacls.returncode != 0:
            detail = (takeown.stderr or takeown.stdout or icacls.stderr or "").strip()
            return detail or "takeown/icacls failed"
        return None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)


def delete_executable(exe_path: str, name_hint: str = "") -> tuple[bool, str]:
    """
    Delete an executable file after basic safety checks.

    Refuses protected system/Program Files paths and never-kill process names.
    For locked Temp files, kills holders and may take ownership.
    """
    if not exe_path or not exe_path.strip():
        return False, "No executable path to delete."

    path = Path(exe_path)
    name = name_hint or path.name
    if is_never_kill(name):
        return False, f"Refused to delete protected process file: {name}"

    if _is_protected_delete_path(str(path)):
        return (
            False,
            f"Refused to delete file in a protected system location: {path}",
        )

    if not path.is_file():
        return False, f"File not found (already removed?): {path}"

    # Stop anything still locking the file
    lock_msgs = kill_processes_using_exe(str(path))
    time.sleep(0.4)

    last_error: Exception | None = None
    took_ownership = False
    for attempt in range(12):
        try:
            path.unlink()
            extra = ""
            if lock_msgs:
                extra = " | " + "; ".join(lock_msgs[:3])
            if took_ownership:
                extra += " | took ownership"
            return True, f"Deleted {path}{extra}"
        except PermissionError as exc:
            last_error = exc
            if not took_ownership:
                own_err = _try_take_ownership(path)
                took_ownership = True
                if own_err:
                    logger.info("takeown failed for %s: %s", path, own_err)
            time.sleep(0.4)
        except OSError as exc:
            last_error = exc
            # WinError 5 / 32 — retry after another kill pass
            if attempt in {3, 7}:
                kill_processes_using_exe(str(path))
            time.sleep(0.4)

    logger.exception("Failed to delete %s", path)
    hint = (
        " If this keeps failing: end DismHost.exe in Task Manager, "
        "or reboot and delete the folder under C:\\Windows\\Temp."
    )
    return False, f"Could not delete {path}: {last_error}.{hint}"


def kill_and_delete(
    pid: int, exe_path: str, name_hint: str = ""
) -> tuple[bool, str]:
    """Kill a process (and any other process using the same exe), then delete."""
    ok, kill_msg = kill_process(pid, name_hint)
    others = kill_processes_using_exe(exe_path)
    del_ok, del_msg = delete_executable(exe_path, name_hint or "")
    parts = [kill_msg]
    if others:
        parts.append("; ".join(others[:3]))
    parts.append(del_msg)
    combined = " | ".join(parts)
    return ok and del_ok, combined
