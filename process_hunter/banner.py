"""Always-on-top red alert banner for suspicious process findings."""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from dataclasses import dataclass
from typing import Callable

from process_hunter.monitor import Alert

logger = logging.getLogger(__name__)

BANNER_HEIGHT = 270
MINI_WIDTH = 360
MINI_HEIGHT = 52
BG_RED = "#b91c1c"
BG_ORANGE = "#c2410c"
FG_WHITE = "#ffffff"
BTN_BG = "#7f1d1d"
BTN_BG_ORANGE = "#9a3412"
BTN_ACTIVE = "#991b1b"
BTN_ACTIVE_ORANGE = "#b45309"
BTN_FG = "#ffffff"


def _banner_colors(category: str) -> tuple[str, str, str]:
    """Return (background, button_bg, button_active) for the alert category."""
    if category == "high_load":
        return BG_ORANGE, BTN_BG_ORANGE, BTN_ACTIVE_ORANGE
    return BG_RED, BTN_BG, BTN_ACTIVE


@dataclass
class BannerActions:
    """Callbacks for banner buttons (run on the banner/UI thread)."""

    on_kill: Callable[[Alert], None]
    on_kill_and_ban: Callable[[Alert], None]
    on_allow: Callable[[Alert], None]
    on_open_folder: Callable[[Alert], None]
    on_open_kill_delete: Callable[[Alert], None]
    on_open_kill_ban_delete: Callable[[Alert], None]
    on_virustotal: Callable[[Alert], None]
    on_more_info: Callable[[Alert], None]
    on_dismiss: Callable[[Alert], None] | None = None


class AlertBannerManager:
    """
    Runs a hidden Tk root on a background thread and shows a full-width
    top-of-screen banner when suspicious processes are found.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[tuple[str, object | None]] = queue.Queue()
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run_ui,
            name="ProcessHunterBanner",
            daemon=True,
        )
        self._root: tk.Tk | None = None
        self._banner: tk.Toplevel | None = None
        self._current_alert: Alert | None = None
        self._actions: BannerActions | None = None
        self._pending: list[Alert] = []
        self._started = False
        self._minimized = False
        self._full_frame: tk.Frame | None = None
        self._mini_frame: tk.Frame | None = None
        self._mini_label: tk.Label | None = None
        self._title_label: tk.Label | None = None

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._thread.start()
        self._ready.wait(timeout=8)

    def stop(self) -> None:
        if not self._started:
            return
        self._queue.put(("stop", None))

    def show(self, alert: Alert, actions: BannerActions) -> None:
        """Show (or queue) a malicious-process banner for this alert."""
        self.start()
        self._actions = actions
        self._queue.put(("show", alert))

    def prompt_ban_name(self, on_submit: Callable[[str], None]) -> None:
        """Open a dialog to type a process name or wildcard pattern to ban."""
        self.start()
        self._queue.put(("prompt_ban_name", on_submit))

    def prompt_ban_running(
        self,
        process_names: list[str],
        on_submit: Callable[[str], None],
    ) -> None:
        """Open a dialog to pick a running process name to ban."""
        self.start()
        self._queue.put(
            ("prompt_ban_running", (list(process_names), on_submit))
        )

    def show_info_dialog(
        self,
        title: str,
        message: str,
        open_url: str | None = None,
    ) -> None:
        """Show a result/info dialog on the UI thread."""
        self.start()
        self._queue.put(("info_dialog", (title, message, open_url)))

    def clear_for_name(self, name: str) -> None:
        """Drop current/pending banners for this process name."""
        self.start()
        self._queue.put(("clear_name", name.strip().lower()))

    def _run_ui(self) -> None:
        try:
            self._root = tk.Tk()
            self._root.withdraw()
            self._root.title("Process Hunter")
            self._ready.set()
            self._root.after(100, self._pump_queue)
            self._root.mainloop()
        except Exception:
            logger.exception("Alert banner UI thread failed")
            self._ready.set()

    def _pump_queue(self) -> None:
        assert self._root is not None
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "stop":
                    self._destroy_banner()
                    self._root.quit()
                    return
                if kind == "show" and isinstance(payload, Alert):
                    self._handle_show(payload)
                elif kind == "prompt_ban_name" and callable(payload):
                    self._show_ban_name_dialog(payload)
                elif kind == "prompt_ban_running" and isinstance(payload, tuple):
                    names, callback = payload
                    self._show_ban_running_dialog(list(names), callback)
                elif kind == "info_dialog" and isinstance(payload, tuple):
                    title, message, open_url = payload
                    self._show_info_dialog(
                        str(title),
                        str(message),
                        str(open_url) if open_url else None,
                    )
                elif kind == "clear_name" and isinstance(payload, str):
                    self._clear_for_name(payload)
        except queue.Empty:
            pass
        self._root.after(150, self._pump_queue)

    def _clear_for_name(self, name_l: str) -> None:
        name_l = name_l.strip().lower()
        self._pending = [
            a
            for a in self._pending
            if a.name.strip().lower() != name_l
        ]
        if (
            self._current_alert is not None
            and self._current_alert.name.strip().lower() == name_l
        ):
            self._destroy_banner()
            if self._pending:
                nxt = self._pending.pop(0)
                self._build_banner(nxt)

    def _show_info_dialog(
        self,
        title: str,
        message: str,
        open_url: str | None = None,
    ) -> None:
        assert self._root is not None
        win = tk.Toplevel(self._root)
        win.title(title)
        # Larger window for detailed reports / VirusTotal (room for both buttons)
        long_report = len(message) > 500 or message.count("\n") > 12
        if open_url:
            win.geometry("640x420")
            win.minsize(520, 320)
        elif long_report:
            win.geometry("720x560")
            win.minsize(560, 400)
        else:
            win.geometry("560x360")
            win.minsize(480, 280)
        win.resizable(True, True)
        self._style_dialog(win)

        frame = tk.Frame(win, bg="#1a1a1a", padx=16, pady=16)
        frame.pack(fill=tk.BOTH, expand=True)

        def close() -> None:
            win.destroy()

        def open_report() -> None:
            if open_url:
                import webbrowser

                webbrowser.open(open_url)

        # Pack button bar first at the bottom so it never gets clipped
        btns = tk.Frame(frame, bg="#1a1a1a")
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(14, 0))

        tk.Button(
            btns,
            text="Close",
            command=close,
            bg="#3b3b3b",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=16,
            pady=8,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.RIGHT)
        if open_url:
            tk.Button(
                btns,
                text="Open VirusTotal report",
                command=open_report,
                bg="#3b82f6",
                fg="#ffffff",
                relief=tk.FLAT,
                padx=16,
                pady=8,
                font=("Segoe UI", 10, "bold"),
            ).pack(side=tk.RIGHT, padx=(0, 10))

        tk.Label(
            frame,
            text=title,
            bg="#1a1a1a",
            fg="#f8fafc",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", side=tk.TOP)

        text_frame = tk.Frame(frame, bg="#1a1a1a")
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        scroll = tk.Scrollbar(text_frame)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text = tk.Text(
            text_frame,
            wrap=tk.WORD,
            font=("Consolas", 10) if long_report else ("Segoe UI", 11),
            bg="#2d2d2d",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=10,
            yscrollcommand=scroll.set,
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=text.yview)
        text.insert("1.0", message)
        text.configure(state=tk.DISABLED)

    def _style_dialog(self, win: tk.Toplevel) -> None:
        win.configure(bg="#1a1a1a")
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()

    def _show_ban_name_dialog(self, on_submit: Callable[[str], None]) -> None:
        assert self._root is not None
        win = tk.Toplevel(self._root)
        win.title("Add to ban list")
        win.geometry("480x180")
        win.resizable(False, False)
        self._style_dialog(win)

        frame = tk.Frame(win, bg="#1a1a1a", padx=16, pady=16)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            frame,
            text="Process name or pattern to ban",
            bg="#1a1a1a",
            fg="#f8fafc",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text="Examples: BadApp.exe   Cursor*   *Cap.exe",
            bg="#1a1a1a",
            fg="#94a3b8",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 10))

        entry = tk.Entry(
            frame,
            font=("Segoe UI", 12),
            bg="#2d2d2d",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief=tk.FLAT,
        )
        entry.pack(fill=tk.X, ipady=6)
        entry.focus_set()

        def submit() -> None:
            value = entry.get().strip()
            win.destroy()
            if value:
                on_submit(value)

        def cancel() -> None:
            win.destroy()

        btns = tk.Frame(frame, bg="#1a1a1a")
        btns.pack(anchor="e", pady=(14, 0))
        tk.Button(
            btns,
            text="Cancel",
            command=cancel,
            bg="#3b3b3b",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=6,
        ).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(
            btns,
            text="Add to ban list",
            command=submit,
            bg="#3b82f6",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=6,
        ).pack(side=tk.RIGHT)
        win.bind("<Return>", lambda _e: submit())
        win.bind("<Escape>", lambda _e: cancel())

    def _show_ban_running_dialog(
        self,
        process_names: list[str],
        on_submit: Callable[[str], None],
    ) -> None:
        assert self._root is not None
        win = tk.Toplevel(self._root)
        win.title("Ban a running process")
        win.geometry("520x420")
        win.resizable(False, False)
        self._style_dialog(win)

        frame = tk.Frame(win, bg="#1a1a1a", padx=16, pady=16)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            frame,
            text="Select a running process to ban",
            bg="#1a1a1a",
            fg="#f8fafc",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text="It will be auto-killed whenever it appears.",
            bg="#1a1a1a",
            fg="#94a3b8",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(4, 10))

        filter_var = tk.StringVar()
        filter_entry = tk.Entry(
            frame,
            textvariable=filter_var,
            font=("Segoe UI", 11),
            bg="#2d2d2d",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief=tk.FLAT,
        )
        filter_entry.pack(fill=tk.X, ipady=5)
        filter_entry.focus_set()

        list_frame = tk.Frame(frame, bg="#1a1a1a")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        scroll = tk.Scrollbar(list_frame)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        listbox = tk.Listbox(
            list_frame,
            font=("Segoe UI", 11),
            bg="#2d2d2d",
            fg="#ffffff",
            selectbackground="#2563eb",
            activestyle="dotbox",
            yscrollcommand=scroll.set,
            exportselection=False,
        )
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.config(command=listbox.yview)

        all_names = sorted(set(process_names), key=str.lower)

        def refresh_list(*_args: object) -> None:
            needle = filter_var.get().strip().lower()
            listbox.delete(0, tk.END)
            for name in all_names:
                if not needle or needle in name.lower():
                    listbox.insert(tk.END, name)

        filter_var.trace_add("write", refresh_list)
        refresh_list()

        def submit() -> None:
            selection = listbox.curselection()
            if not selection:
                return
            value = str(listbox.get(selection[0])).strip()
            win.destroy()
            if value:
                on_submit(value)

        def cancel() -> None:
            win.destroy()

        btns = tk.Frame(frame, bg="#1a1a1a")
        btns.pack(anchor="e", pady=(14, 0))
        tk.Button(
            btns,
            text="Cancel",
            command=cancel,
            bg="#3b3b3b",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=6,
        ).pack(side=tk.RIGHT, padx=(8, 0))
        tk.Button(
            btns,
            text="Add to ban list",
            command=submit,
            bg="#3b82f6",
            fg="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=6,
        ).pack(side=tk.RIGHT)
        listbox.bind("<Double-Button-1>", lambda _e: submit())
        win.bind("<Return>", lambda _e: submit())
        win.bind("<Escape>", lambda _e: cancel())

    def _handle_show(self, alert: Alert) -> None:
        name_l = alert.name.strip().lower()
        # Ignore duplicate pending entries for the same process name
        self._pending = [
            a for a in self._pending if a.name.strip().lower() != name_l
        ]
        if self._banner is not None and self._current_alert is not None:
            current_name = self._current_alert.name.strip().lower()
            # Same process already showing — just refresh details
            if (
                self._current_alert.pid == alert.pid
                or current_name == name_l
            ):
                self._current_alert = alert
                self._refresh_details()
                return
            self._pending.append(alert)
            return
        self._build_banner(alert)

    def _build_banner(self, alert: Alert) -> None:
        assert self._root is not None
        was_minimized = self._minimized
        self._destroy_banner()
        self._current_alert = alert
        self._minimized = was_minimized

        bg, btn_bg, btn_active = _banner_colors(alert.category)
        self._bg = bg
        self._btn_bg = btn_bg
        self._btn_active = btn_active

        screen_w = self._root.winfo_screenwidth()
        win = tk.Toplevel(self._root)
        win.title(f"Process Hunter — {alert.headline}")
        win.configure(bg=bg)
        win.resizable(False, False)
        win.attributes("-topmost", True)
        try:
            win.overrideredirect(True)
        except tk.TclError:
            pass
        # Stay on top but do not steal keyboard focus from other apps
        win.lift()

        # ---- Full banner content ----
        full = tk.Frame(win, bg=bg, padx=24, pady=12)
        self._full_frame = full

        header = tk.Frame(full, bg=bg)
        header.pack(fill=tk.X)

        title = tk.Label(
            header,
            text=alert.headline,
            bg=bg,
            fg=FG_WHITE,
            font=("Segoe UI", 28, "bold"),
        )
        title.pack(side=tk.LEFT, anchor="w")
        self._title_label = title

        minimize_btn = tk.Button(
            header,
            text="─",
            command=self._minimize_banner,
            bg=btn_bg,
            fg=FG_WHITE,
            activebackground=btn_active,
            activeforeground=FG_WHITE,
            font=("Segoe UI", 14, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            width=3,
        )
        minimize_btn.pack(side=tk.RIGHT, anchor="ne")
        tk.Label(
            header,
            text="Minimize",
            bg=bg,
            fg=FG_WHITE,
            font=("Segoe UI", 9),
        ).pack(side=tk.RIGHT, padx=(0, 6), pady=(8, 0))

        self._detail = tk.Label(
            full,
            text=self._detail_text(alert),
            bg=bg,
            fg=FG_WHITE,
            font=("Segoe UI", 12),
            justify=tk.LEFT,
            wraplength=screen_w - 80,
        )
        self._detail.pack(anchor="w", pady=(8, 16))

        btn_row = tk.Frame(full, bg=bg)
        btn_row.pack(anchor="w", fill=tk.X)
        btn_row2 = tk.Frame(full, bg=bg)
        btn_row2.pack(anchor="w", fill=tk.X, pady=(10, 0))

        self._make_button(
            btn_row, "Kill process", self._on_kill
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row, "Kill and ban", self._on_kill_and_ban
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row, "Add to allow list", self._on_allow
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row, "Open folder", self._on_open_folder
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row, "Dismiss", self._on_dismiss
        ).pack(side=tk.LEFT)

        self._make_button(
            btn_row2,
            "More info",
            self._on_more_info,
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row2,
            "Submit to VirusTotal",
            self._on_virustotal,
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row2,
            "Open folder, kill process, and delete process",
            self._on_open_kill_delete,
        ).pack(side=tk.LEFT, padx=(0, 12))
        self._make_button(
            btn_row2,
            "Open folder, kill, ban, and delete",
            self._on_open_kill_ban_delete,
        ).pack(side=tk.LEFT)

        # ---- Minimized corner tab ----
        mini = tk.Frame(win, bg=bg, padx=10, pady=8)
        self._mini_frame = mini
        self._mini_label = tk.Label(
            mini,
            text=self._mini_text(alert),
            bg=bg,
            fg=FG_WHITE,
            font=("Segoe UI", 10, "bold"),
            justify=tk.LEFT,
            wraplength=MINI_WIDTH - 100,
        )
        self._mini_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        expand_btn = tk.Button(
            mini,
            text="▲ Expand",
            command=self._expand_banner,
            bg=btn_bg,
            fg=FG_WHITE,
            activebackground=btn_active,
            activeforeground=FG_WHITE,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=10,
            pady=6,
            cursor="hand2",
        )
        expand_btn.pack(side=tk.RIGHT, padx=(8, 0))

        self._banner = win
        if self._minimized:
            self._apply_minimized_layout()
        else:
            self._apply_expanded_layout()

    def _mini_text(self, alert: Alert) -> str:
        return f"{alert.headline}\n{alert.name}  ·  click Expand"

    def _apply_expanded_layout(self) -> None:
        if self._banner is None or self._root is None:
            return
        self._minimized = False
        screen_w = self._root.winfo_screenwidth()
        if self._mini_frame is not None:
            self._mini_frame.pack_forget()
        if self._full_frame is not None:
            self._full_frame.pack(fill=tk.BOTH, expand=True)
        self._banner.geometry(f"{screen_w}x{BANNER_HEIGHT}+0+0")
        self._banner.lift()

    def _apply_minimized_layout(self) -> None:
        if self._banner is None or self._root is None:
            return
        self._minimized = True
        screen_w = self._root.winfo_screenwidth()
        x = max(8, screen_w - MINI_WIDTH - 16)
        if self._full_frame is not None:
            self._full_frame.pack_forget()
        if self._mini_frame is not None:
            self._mini_frame.pack(fill=tk.BOTH, expand=True)
        self._banner.geometry(f"{MINI_WIDTH}x{MINI_HEIGHT}+{x}+8")
        self._banner.lift()

    def _minimize_banner(self) -> None:
        self._apply_minimized_layout()

    def _expand_banner(self) -> None:
        self._apply_expanded_layout()

    def _make_button(
        self, parent: tk.Widget, text: str, command: Callable[[], None]
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=getattr(self, "_btn_bg", BTN_BG),
            fg=BTN_FG,
            activebackground=getattr(self, "_btn_active", BTN_ACTIVE),
            activeforeground=BTN_FG,
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=10,
            cursor="hand2",
        )

    @staticmethod
    def _detail_text(alert: Alert) -> str:
        path = alert.exe or "(path unknown)"
        return (
            f"{alert.type_label}\n"
            f"{alert.name}  |  PID {alert.pid}  |  "
            f"CPU {alert.cpu_percent:.1f}%  |  {alert.reason}\n"
            f"{path}"
        )

    def _refresh_details(self) -> None:
        if self._current_alert is None:
            return
        try:
            if hasattr(self, "_detail") and self._detail is not None:
                self._detail.configure(
                    text=self._detail_text(self._current_alert)
                )
            if self._title_label is not None:
                self._title_label.configure(text=self._current_alert.headline)
            if self._mini_label is not None:
                self._mini_label.configure(
                    text=self._mini_text(self._current_alert)
                )
        except tk.TclError:
            pass

    def _destroy_banner(self) -> None:
        if self._banner is not None:
            try:
                self._banner.destroy()
            except tk.TclError:
                pass
        self._banner = None
        self._current_alert = None
        self._full_frame = None
        self._mini_frame = None
        self._mini_label = None
        self._title_label = None
        # Keep self._minimized so the next alert respects the user's preference

    def _close_and_next(self) -> None:
        self._destroy_banner()
        if self._pending:
            nxt = self._pending.pop(0)
            self._build_banner(nxt)
        else:
            self._minimized = False

    def _on_kill(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        try:
            self._actions.on_kill(alert)
        finally:
            self._close_and_next()

    def _on_kill_and_ban(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        try:
            self._actions.on_kill_and_ban(alert)
        finally:
            self._close_and_next()

    def _on_allow(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        try:
            self._actions.on_allow(alert)
        finally:
            self._close_and_next()

    def _on_open_folder(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        # Keep banner open so user can still kill/delete
        self._actions.on_open_folder(alert)

    def _on_virustotal(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        # Keep banner open while scan runs / results show
        self._actions.on_virustotal(alert)

    def _on_more_info(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        self._actions.on_more_info(alert)

    def _on_open_kill_delete(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        try:
            self._actions.on_open_kill_delete(alert)
        finally:
            self._close_and_next()

    def _on_open_kill_ban_delete(self) -> None:
        alert = self._current_alert
        if alert is None or self._actions is None:
            return
        try:
            self._actions.on_open_kill_ban_delete(alert)
        finally:
            self._close_and_next()

    def _on_dismiss(self) -> None:
        alert = self._current_alert
        if alert is not None and self._actions and self._actions.on_dismiss:
            try:
                self._actions.on_dismiss(alert)
            except Exception:
                logger.exception("Dismiss callback failed")
        self._close_and_next()
