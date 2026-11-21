"""System tray UI for Process Hunter."""

from __future__ import annotations

import logging
import threading
from typing import Callable

import pystray
from PIL import Image, ImageDraw
from pystray import MenuItem as Item

from process_hunter.banner import AlertBannerManager, BannerActions
from process_hunter.config import AppConfig, project_root
from process_hunter.monitor import Alert, ProcessMonitor
from process_hunter.processes import (
    is_never_kill,
    iter_process_snapshots,
    open_containing_folder,
    open_path,
)
from process_hunter.fileinfo import gather_file_intelligence
from process_hunter.virustotal import scan_executable

logger = logging.getLogger(__name__)


def _create_icon_image(size: int = 64) -> Image.Image:
    """Draw a simple crosshair-style hunter icon."""
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    margin = 6
    # Dark circle background
    draw.ellipse(
        (margin, margin, size - margin, size - margin),
        fill=(26, 26, 26, 255),
        outline=(59, 130, 246, 255),
        width=3,
    )
    cx = cy = size // 2
    # Crosshair
    draw.line((cx, margin + 8, cx, size - margin - 8), fill=(59, 130, 246, 255), width=3)
    draw.line((margin + 8, cy, size - margin - 8, cy), fill=(59, 130, 246, 255), width=3)
    draw.ellipse(
        (cx - 8, cy - 8, cx + 8, cy + 8),
        outline=(248, 250, 252, 255),
        width=2,
    )
    return image


def show_toast(title: str, message: str, app_id: str = "Process Hunter") -> None:
    """Show a Windows toast notification (best-effort)."""
    try:
        from winotify import Notification, audio

        toast = Notification(
            app_id=app_id,
            title=title,
            msg=message[:250],
            duration="short",
        )
        toast.set_audio(audio.Default, loop=False)
        toast.show()
    except Exception:
        logger.exception("Toast notification failed: %s — %s", title, message)


class TrayApp:
    """Owns the pystray icon and wires it to the process monitor."""

    def __init__(self, config: AppConfig, monitor: ProcessMonitor) -> None:
        self.config = config
        self.monitor = monitor
        self._icon: pystray.Icon | None = None
        self._banner = AlertBannerManager()
        self.monitor.on_alert = self._handle_alert
        self.monitor.on_kill_message = self._handle_kill_message
        self.monitor.on_suppress_name = self._banner.clear_for_name

    def run(self) -> None:
        self._banner.start()
        self.monitor.start()
        self._icon = pystray.Icon(
            "process_hunter",
            _create_icon_image(),
            "Process Hunter",
            menu=self._build_menu(),
        )
        # pystray blocks here on the main thread
        self._icon.run()

    def stop(self) -> None:
        self.monitor.stop()
        self._banner.stop()
        if self._icon:
            self._icon.stop()

    def _refresh_menu(self) -> None:
        if self._icon:
            self._icon.menu = self._build_menu()
            try:
                self._icon.update_menu()
            except Exception:
                logger.debug("update_menu not available", exc_info=True)

    def _build_menu(self) -> pystray.Menu:
        monitoring = self.monitor.is_monitoring
        status = self.monitor.last_status
        alert_items = self._alert_menu_items()

        ban_items = self._banlist_menu_items()

        return pystray.Menu(
            Item(f"Status: {status}", None, enabled=False),
            Item(
                "Monitoring: On" if monitoring else "Monitoring: Off",
                self._toggle_monitoring,
            ),
            pystray.Menu.SEPARATOR,
            Item(
                "Recent alerts",
                pystray.Menu(*alert_items)
                if alert_items
                else pystray.Menu(Item("(none)", None, enabled=False)),
            ),
            Item(
                "Ban list",
                pystray.Menu(*ban_items),
            ),
            pystray.Menu.SEPARATOR,
            Item("Open config folder", self._open_config_folder),
            Item("Edit config.json", self._edit_config),
            Item("View log", self._view_log),
            pystray.Menu.SEPARATOR,
            Item("Quit", self._quit),
        )

    def _banlist_menu_items(self) -> list[Item]:
        items: list[Item] = [
            Item("Add name or pattern...", self._add_ban_by_name),
            Item("Ban a running process...", self._add_ban_running),
            Item("Edit ban list (config.json)", self._edit_config),
        ]
        current = list(self.config.banlist)
        if current:
            items.append(pystray.Menu.SEPARATOR)
            items.append(Item("Currently banned:", None, enabled=False))
            for name in current[:20]:
                items.append(
                    Item(
                        f"  {name}"[:60],
                        None,
                        enabled=False,
                    )
                )
            if len(current) > 20:
                items.append(
                    Item(
                        f"  …and {len(current) - 20} more",
                        None,
                        enabled=False,
                    )
                )
        return items

    def _alert_menu_items(self) -> list[Item]:
        items: list[Item] = []
        with self.monitor._lock:
            alerts = list(self.monitor.recent_alerts)

        for alert in alerts:
            items.append(
                Item(
                    alert.label[:60],
                    pystray.Menu(
                        Item(
                            "Kill",
                            self._make_kill_handler(alert.pid),
                        ),
                        Item(
                            "Kill and ban",
                            self._make_kill_ban_handler(alert.pid),
                        ),
                        Item(
                            "Add to ban list",
                            self._make_ban_only_handler(alert.name),
                        ),
                        Item(
                            "Add to allow list",
                            self._make_allow_handler(alert.name),
                        ),
                        Item(
                            "Ignore for session",
                            self._make_ignore_handler(alert.name),
                        ),
                        Item(
                            f"CPU {alert.cpu_percent:.1f}%",
                            None,
                            enabled=False,
                        ),
                        Item(
                            (alert.exe or "(no path)")[:70],
                            None,
                            enabled=False,
                        ),
                    ),
                )
            )
        return items

    def _make_kill_handler(self, pid: int) -> Callable[[object, Item], None]:
        def handler(icon: object, item: Item) -> None:
            ok, message = self.monitor.kill_alert(pid)
            show_toast(
                "Process Hunter",
                message if ok else f"Kill failed: {message}",
            )
            self._refresh_menu()

        return handler

    def _make_kill_ban_handler(self, pid: int) -> Callable[[object, Item], None]:
        def handler(icon: object, item: Item) -> None:
            ok, message = self.monitor.kill_and_ban_alert(pid)
            show_toast(
                "Process Hunter",
                message if ok else f"Kill/ban failed: {message}",
            )
            self._refresh_menu()

        return handler

    def _make_ban_only_handler(self, name: str) -> Callable[[object, Item], None]:
        def handler(icon: object, item: Item) -> None:
            self._apply_ban(name)
            self._refresh_menu()

        return handler

    def _make_allow_handler(self, name: str) -> Callable[[object, Item], None]:
        def handler(icon: object, item: Item) -> None:
            self._apply_allow(name)
            self._refresh_menu()

        return handler

    def _apply_ban(self, name: str) -> None:
        ok, message = self.monitor.ban_process(name)
        show_toast(
            "Process Hunter",
            message if ok else f"Ban failed: {message}",
        )
        self._refresh_menu()

    def _apply_allow(self, name: str) -> None:
        ok, message = self.monitor.allow_process(name)
        show_toast(
            "Process Hunter",
            message if ok else f"Allow failed: {message}",
        )
        self._refresh_menu()

    def _add_ban_by_name(self, icon: object, item: Item) -> None:
        self._banner.prompt_ban_name(self._apply_ban)

    def _add_ban_running(self, icon: object, item: Item) -> None:
        names: list[str] = []
        try:
            for info in iter_process_snapshots():
                name = (info.name or "").strip()
                if not name or is_never_kill(name):
                    continue
                if self.config.is_safeguarded(name):
                    continue
                names.append(name)
        except Exception:
            logger.exception("Failed to list processes for ban dialog")
            show_toast("Process Hunter", "Could not list running processes.")
            return
        if not names:
            show_toast("Process Hunter", "No ban-able processes found.")
            return
        self._banner.prompt_ban_running(names, self._apply_ban)

    def _make_ignore_handler(self, name: str) -> Callable[[object, Item], None]:
        def handler(icon: object, item: Item) -> None:
            self.monitor.ignore_for_session(name)
            with self.monitor._lock:
                self.monitor.recent_alerts = [
                    a
                    for a in self.monitor.recent_alerts
                    if a.name.strip().lower() != name.strip().lower()
                ]
            show_toast("Process Hunter", f"Ignoring {name} for this session")
            self._refresh_menu()

        return handler

    def _toggle_monitoring(self, icon: object, item: Item) -> None:
        self.monitor.set_monitoring(not self.monitor.is_monitoring)
        self._refresh_menu()

    def _open_config_folder(self, icon: object, item: Item) -> None:
        open_path(project_root())

    def _edit_config(self, icon: object, item: Item) -> None:
        path = self.config.config_path or (project_root() / "config.json")
        open_path(path)

    def _view_log(self, icon: object, item: Item) -> None:
        log_path = self.config.log_path
        if not log_path.exists():
            try:
                log_path.write_text("", encoding="utf-8")
            except OSError:
                show_toast("Process Hunter", f"Cannot create log: {log_path}")
                return
        open_path(log_path)

    def _quit(self, icon: object, item: Item) -> None:
        self.monitor.stop()
        self._banner.stop()
        if self._icon:
            self._icon.stop()

    def _handle_alert(self, alert: Alert) -> None:
        body = (
            f"{alert.name} (PID {alert.pid})\n"
            f"{alert.reason}\n"
            f"{alert.explanation}"
        )
        show_toast("Process Hunter alert", body)
        self._banner.show(
            alert,
            BannerActions(
                on_kill=self._banner_kill,
                on_kill_and_ban=self._banner_kill_and_ban,
                on_allow=self._banner_allow,
                on_open_folder=self._banner_open_folder,
                on_open_kill_delete=self._banner_open_kill_delete,
                on_open_kill_ban_delete=self._banner_open_kill_ban_delete,
                on_virustotal=self._banner_virustotal,
                on_more_info=self._banner_more_info,
                on_dismiss=None,
            ),
        )
        self._refresh_menu()

    def _banner_kill(self, alert: Alert) -> None:
        ok, message = self.monitor.kill_alert(alert.pid)
        show_toast(
            "Process Hunter",
            message if ok else f"Kill failed: {message}",
        )
        self._refresh_menu()

    def _banner_kill_and_ban(self, alert: Alert) -> None:
        ok, message = self.monitor.kill_and_ban_alert(alert.pid)
        show_toast(
            "Process Hunter",
            message if ok else f"Kill/ban failed: {message}",
        )
        self._refresh_menu()

    def _banner_allow(self, alert: Alert) -> None:
        ok, message = self.monitor.allow_process(alert.name)
        show_toast(
            "Process Hunter",
            message if ok else f"Allow failed: {message}",
        )
        self._refresh_menu()

    def _banner_open_folder(self, alert: Alert) -> None:
        ok, message = self.monitor.open_alert_folder(alert.pid)
        if not ok:
            ok, message = open_containing_folder(alert.exe)
        if not ok:
            show_toast("Process Hunter", message)
        self._refresh_menu()

    def _banner_more_info(self, alert: Alert) -> None:
        show_toast(
            "Process Hunter",
            f"Gathering info on {alert.name}…",
        )

        def worker() -> None:
            try:
                report = gather_file_intelligence(
                    pid=alert.pid,
                    name=alert.name,
                    exe=alert.exe,
                    reason=alert.reason,
                    cpu_percent=alert.cpu_percent,
                )
            except PermissionError as exc:
                logger.exception("More info access denied")
                report = (
                    f"Access denied while reading the file:\n{alert.exe}\n\n"
                    f"{exc}\n\n"
                    "This often means the file is locked by a running process "
                    "(common for DismHost.exe under C:\\Windows\\Temp).\n\n"
                    "Try: Kill process first, then More info again — or use "
                    "'Open folder, kill, ban, and delete' if you want it removed.\n\n"
                    "Note: DismHost.exe is normally a Windows DISM helper and "
                    "is often legitimate."
                )
            except Exception as exc:
                logger.exception("More info failed")
                report = f"Could not gather info: {exc}"
            self.monitor._append_log(
                f"MORE-INFO: {alert.name} PID={alert.pid} "
                f"path={alert.exe or '(none)'}"
            )
            self._banner.show_info_dialog(
                f"File info — {alert.name}",
                report,
                None,
            )

        threading.Thread(
            target=worker,
            name="ProcessHunterMoreInfo",
            daemon=True,
        ).start()

    def _banner_virustotal(self, alert: Alert) -> None:
        show_toast(
            "Process Hunter",
            f"Submitting {alert.name} to VirusTotal…",
        )

        def worker() -> None:
            result = scan_executable(alert.exe)
            self.monitor._append_log(
                f"VIRUSTOTAL {'OK' if result.ok else 'FAIL'}: "
                f"{alert.name} | {result.message.replace(chr(10), ' ')}"
            )
            title = (
                "VirusTotal result"
                if result.ok
                else "VirusTotal — could not complete"
            )
            detail = (
                f"{alert.name}\n{alert.exe or '(no path)'}\n\n"
                f"{result.message}"
            )
            if result.sha256:
                detail += f"\n\nSHA-256: {result.sha256}"
            self._banner.show_info_dialog(
                title,
                detail,
                result.permalink or None,
            )
            show_toast("Process Hunter", result.summary_line[:250])

        threading.Thread(
            target=worker,
            name="ProcessHunterVirusTotal",
            daemon=True,
        ).start()

    def _banner_open_kill_delete(self, alert: Alert) -> None:
        ok, message = self.monitor.kill_delete_alert(alert.pid)
        show_toast(
            "Process Hunter",
            message if ok else f"Action failed: {message}",
        )
        self._refresh_menu()

    def _banner_open_kill_ban_delete(self, alert: Alert) -> None:
        ok, message = self.monitor.kill_ban_delete_alert(alert.pid)
        show_toast(
            "Process Hunter",
            message if ok else f"Action failed: {message}",
        )
        self._refresh_menu()

    def _handle_kill_message(self, message: str) -> None:
        # Auto-kill feedback via toast (short)
        lower = message.lower()
        if (
            lower.startswith("killed")
            or "access denied" in lower
            or "deleted" in lower
        ):
            show_toast("Process Hunter", message)
        self._refresh_menu()
