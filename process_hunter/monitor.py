"""Background monitor: auto-kill blocklist and alert on heuristics."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from pathlib import Path

from process_hunter.config import AppConfig, add_to_allowlist, add_to_banlist
from process_hunter.explanations import explain_process
from process_hunter.heuristics import classify_alert_reason
from process_hunter.processes import (
    ProcessInfo,
    is_never_kill,
    iter_process_snapshots,
    kill_and_delete,
    kill_process,
    open_containing_folder,
)

logger = logging.getLogger(__name__)


def alert_category(reason: str) -> str:
    """
    Short category for UI: suspicious_file, high_load, suspicious_and_high_load,
    or suspicious_process.
    """
    lower = (reason or "").lower()
    has_cpu = "high cpu" in lower
    has_path = "suspicious path" in lower
    if has_cpu and has_path:
        return "suspicious_and_high_load"
    if has_path:
        return "suspicious_file"
    if has_cpu:
        return "high_load"
    return "suspicious_process"


def alert_headline(reason: str) -> str:
    """Big banner title based on why the process was flagged."""
    kind = alert_category(reason)
    return {
        "suspicious_file": "Suspicious file found.",
        "high_load": "High load process found.",
        "suspicious_and_high_load": "Suspicious file + high load process.",
        "suspicious_process": "Suspicious process found.",
    }.get(kind, "Suspicious process found.")


def alert_type_label(reason: str) -> str:
    """Readable type line for the banner details."""
    kind = alert_category(reason)
    return {
        "suspicious_file": "Type: Suspicious file (unusual location)",
        "high_load": "Type: High load (sustained high CPU)",
        "suspicious_and_high_load": (
            "Type: Suspicious file + high load"
        ),
        "suspicious_process": "Type: Suspicious process",
    }.get(kind, "Type: Suspicious process")


@dataclass
class Alert:
    """A user-facing alert about a process."""

    pid: int
    name: str
    exe: str
    cpu_percent: float
    reason: str
    explanation: str
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.pid}) — {self.reason}"

    @property
    def headline(self) -> str:
        return alert_headline(self.reason)

    @property
    def type_label(self) -> str:
        return alert_type_label(self.reason)

    @property
    def category(self) -> str:
        return alert_category(self.reason)


NotifyCallback = Callable[[Alert], None]
KillLogCallback = Callable[[str], None]


class ProcessMonitor:
    """Polls processes, auto-kills blocklist entries, emits alerts."""

    def __init__(
        self,
        config: AppConfig,
        on_alert: NotifyCallback | None = None,
        on_kill_message: KillLogCallback | None = None,
    ) -> None:
        self.config = config
        self.on_alert = on_alert
        self.on_kill_message = on_kill_message
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._monitoring = True
        self._cpu_hits: dict[int, int] = defaultdict(int)
        self._session_ignore: set[str] = set()
        self._notified_keys: set[str] = set()
        # Names already shown a high-CPU banner while continuously hot
        self._hot_alerted_names: set[str] = set()
        self.recent_alerts: list[Alert] = []
        self.last_status: str = "Idle"
        self.on_suppress_name: Callable[[str], None] | None = None

    @property
    def is_monitoring(self) -> bool:
        with self._lock:
            return self._monitoring

    def set_monitoring(self, enabled: bool) -> None:
        with self._lock:
            self._monitoring = enabled
            self.last_status = "Monitoring" if enabled else "Paused"

    def ignore_for_session(self, name: str) -> None:
        with self._lock:
            self._session_ignore.add(name.strip().lower())

    def clear_alert(self, pid: int) -> None:
        with self._lock:
            self.recent_alerts = [a for a in self.recent_alerts if a.pid != pid]

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ProcessHunterMonitor",
            daemon=True,
        )
        self._thread.start()
        self.last_status = "Monitoring"

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.config.poll_interval_seconds + 2)
        self.last_status = "Stopped"

    def _run_loop(self) -> None:
        # Prime CPU counters once so the first real poll is more accurate.
        try:
            iter_process_snapshots()
        except Exception:
            logger.exception("Initial process snapshot failed")

        while not self._stop.is_set():
            started = time.monotonic()
            try:
                if self.is_monitoring:
                    self._poll_once()
            except Exception:
                logger.exception("Monitor poll failed")
            elapsed = time.monotonic() - started
            wait = max(0.5, self.config.poll_interval_seconds - elapsed)
            self._stop.wait(wait)

    def _should_skip(self, info: ProcessInfo) -> bool:
        name_l = info.name.strip().lower()
        if not name_l:
            return True
        if is_never_kill(name_l):
            return True
        if self.config.is_safeguarded(name_l):
            return True
        # Also safeguard by executable basename (covers renamed process titles)
        if info.exe:
            exe_base = Path(info.exe).name.strip().lower()
            if exe_base and (
                self.config.is_safeguarded(exe_base)
                or exe_base in self._session_ignore
            ):
                return True
        with self._lock:
            if name_l in self._session_ignore:
                return True
        return False

    def _poll_once(self) -> None:
        snapshots = iter_process_snapshots()
        seen_pids: set[int] = set()

        for info in snapshots:
            seen_pids.add(info.pid)
            if self._should_skip(info):
                # Do not keep building CPU streak for allowlisted processes
                self._cpu_hits.pop(info.pid, None)
                continue

            if self.config.is_auto_kill_target(info.name):
                self._auto_kill(info)
                continue

            self._evaluate_alert(info)

        # Drop CPU hit counters for processes that exited
        stale = [pid for pid in self._cpu_hits if pid not in seen_pids]
        for pid in stale:
            self._cpu_hits.pop(pid, None)

        with self._lock:
            self.recent_alerts = [
                a for a in self.recent_alerts if a.pid in seen_pids
            ]

    def _auto_kill(self, info: ProcessInfo) -> None:
        ok, message = kill_process(info.pid, info.name)
        logger.info("%s | path=%s", message, info.exe or "(unknown)")
        if self.on_kill_message:
            self.on_kill_message(message)
        self._append_log(
            f"AUTO-KILL {'OK' if ok else 'FAIL'}: {message} | {info.exe}"
        )

    def _evaluate_alert(self, info: ProcessInfo) -> None:
        # Re-check safeguard in case allowlist was updated mid-poll
        if self._should_skip(info):
            self._cpu_hits.pop(info.pid, None)
            return

        name_l = info.name.strip().lower()
        threshold = self.config.cpu_threshold_percent
        if info.cpu_percent >= threshold:
            self._cpu_hits[info.pid] += 1
        else:
            self._cpu_hits[info.pid] = 0
            # Cooled down — allow a future high-load alert if it heats up again
            with self._lock:
                self._hot_alerted_names.discard(name_l)

        sustained = self._cpu_hits[info.pid] >= self.config.cpu_sustained_polls
        reason = classify_alert_reason(info, threshold, sustained)
        if not reason:
            return

        key = f"{name_l}|{(info.exe or '').lower()}|{reason.split(';')[0]}"
        with self._lock:
            # Never re-popup for the same identity while still in notified set
            # (path alerts). High-CPU: only once per name while continuously hot.
            if "high CPU" in reason.lower():
                if name_l in self._hot_alerted_names:
                    return
                self._hot_alerted_names.add(name_l)
            elif key in self._notified_keys:
                return
            self._notified_keys.add(key)

        alert = Alert(
            pid=info.pid,
            name=info.name,
            exe=info.exe,
            cpu_percent=info.cpu_percent,
            reason=reason,
            explanation=explain_process(info.name),
        )
        with self._lock:
            self.recent_alerts = [
                a for a in self.recent_alerts if a.pid != info.pid
            ]
            self.recent_alerts.insert(0, alert)
            self.recent_alerts = self.recent_alerts[
                : self.config.max_recent_alerts
            ]

        self._append_log(
            f"ALERT: {alert.name} PID={alert.pid} CPU={alert.cpu_percent:.1f}% "
            f"reason={alert.reason} path={alert.exe}"
        )
        if self.on_alert:
            self.on_alert(alert)

    def kill_alert(self, pid: int) -> tuple[bool, str]:
        with self._lock:
            alert = next((a for a in self.recent_alerts if a.pid == pid), None)
            name = alert.name if alert else ""
        ok, message = kill_process(pid, name)
        self._append_log(f"USER-KILL {'OK' if ok else 'FAIL'}: {message}")
        if ok:
            self.clear_alert(pid)
        if self.on_kill_message:
            self.on_kill_message(message)
        return ok, message

    def open_alert_folder(self, pid: int) -> tuple[bool, str]:
        with self._lock:
            alert = next((a for a in self.recent_alerts if a.pid == pid), None)
            exe = alert.exe if alert else ""
        ok, message = open_containing_folder(exe)
        self._append_log(f"OPEN-FOLDER {'OK' if ok else 'FAIL'}: {message}")
        return ok, message

    def kill_delete_alert(self, pid: int) -> tuple[bool, str]:
        with self._lock:
            alert = next((a for a in self.recent_alerts if a.pid == pid), None)
            name = alert.name if alert else ""
            exe = alert.exe if alert else ""
        # Open folder first so the user can see what is being removed
        open_containing_folder(exe)
        ok, message = kill_and_delete(pid, exe, name)
        self._append_log(
            f"USER-KILL-DELETE {'OK' if ok else 'FAIL'}: {message}"
        )
        if ok:
            self.clear_alert(pid)
        if self.on_kill_message:
            self.on_kill_message(message)
        return ok, message

    def ban_process(self, name: str) -> tuple[bool, str]:
        if is_never_kill(name):
            return False, f"Refused to ban protected process: {name}"
        ok, message = add_to_banlist(self.config, name)
        self._append_log(f"BAN {'OK' if ok else 'FAIL'}: {message}")
        return ok, message

    def allow_process(self, name: str) -> tuple[bool, str]:
        ok, message = add_to_allowlist(self.config, name)
        if ok:
            self._suppress_name(name)
        self._append_log(f"ALLOW {'OK' if ok else 'FAIL'}: {message}")
        return ok, message

    def _suppress_name(self, name: str) -> None:
        """Stop further alerts/banners for this process name this session."""
        name_l = name.strip().lower()
        self.ignore_for_session(name_l)
        with self._lock:
            matching_pids = [
                a.pid
                for a in self.recent_alerts
                if a.name.strip().lower() == name_l
            ]
            self.recent_alerts = [
                a
                for a in self.recent_alerts
                if a.name.strip().lower() != name_l
            ]
            self._hot_alerted_names.discard(name_l)
            self._notified_keys = {
                key
                for key in self._notified_keys
                if not key.startswith(f"{name_l}|")
            }
        for pid in matching_pids:
            self._cpu_hits.pop(pid, None)
        if self.on_suppress_name:
            try:
                self.on_suppress_name(name_l)
            except Exception:
                logger.exception("on_suppress_name failed")

    def kill_and_ban_alert(self, pid: int) -> tuple[bool, str]:
        with self._lock:
            alert = next((a for a in self.recent_alerts if a.pid == pid), None)
            name = alert.name if alert else ""
        kill_ok, kill_msg = self.kill_alert(pid)
        ban_ok, ban_msg = self.ban_process(name) if name else (False, "No name")
        combined = f"{kill_msg} | {ban_msg}"
        return kill_ok and ban_ok, combined

    def kill_ban_delete_alert(self, pid: int) -> tuple[bool, str]:
        with self._lock:
            alert = next((a for a in self.recent_alerts if a.pid == pid), None)
            name = alert.name if alert else ""
            exe = alert.exe if alert else ""
        open_containing_folder(exe)
        ok, message = kill_and_delete(pid, exe, name)
        ban_ok, ban_msg = self.ban_process(name) if name else (False, "No name")
        combined = f"{message} | {ban_msg}"
        self._append_log(
            f"USER-KILL-BAN-DELETE {'OK' if ok and ban_ok else 'FAIL'}: {combined}"
        )
        if ok:
            self.clear_alert(pid)
        if self.on_kill_message:
            self.on_kill_message(combined)
        return ok and ban_ok, combined

    def _append_log(self, line: str) -> None:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = f"[{stamp}] {line}\n"
        try:
            log_path = self.config.log_path
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(text)
        except OSError:
            logger.exception("Could not write log file")
