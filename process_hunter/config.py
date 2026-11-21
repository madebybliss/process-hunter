"""Load and validate Process Hunter configuration."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def project_root() -> Path:
    """Return the project root (parent of the process_hunter package)."""
    return Path(__file__).resolve().parent.parent


def normalize_pattern(pattern: str) -> str:
    """Lowercase and trim a name/pattern for matching."""
    return pattern.strip().lower()


def is_overly_broad_pattern(pattern: str) -> bool:
    """
    True for patterns that would match almost everything (e.g. '*', '*.*', '?').
    These are ignored for safety.
    """
    cleaned = normalize_pattern(pattern)
    if not cleaned:
        return True
    # Only wildcards / dots left — too broad
    literal = re.sub(r"[*?\.]", "", cleaned)
    return literal == ""


def name_matches_any(name: str, patterns: list[str] | set[str]) -> bool:
    """
    Case-insensitive match of a process name against exact names or wildcards.

    Supports * and ? (fnmatch), e.g.:
      Cursor*     -> Cursor.exe, Cursor Helper.exe
      *Host.exe   -> TextInputHost.exe
      *Cursor*    -> any name containing Cursor
    """
    name_l = normalize_pattern(name)
    if not name_l:
        return False
    for raw in patterns:
        pattern = normalize_pattern(str(raw))
        if not pattern or is_overly_broad_pattern(pattern):
            continue
        if fnmatch.fnmatchcase(name_l, pattern):
            return True
    return False


@dataclass
class AppConfig:
    """Runtime configuration for Process Hunter."""

    poll_interval_seconds: float = 5.0
    cpu_threshold_percent: float = 15.0
    cpu_sustained_polls: int = 3
    max_recent_alerts: int = 10
    blocklist: list[str] = field(default_factory=list)
    banlist: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    ignore_names: list[str] = field(default_factory=list)
    log_file: str = "process_hunter.log"
    config_path: Path | None = None

    @property
    def blocklist_patterns(self) -> list[str]:
        return [
            normalize_pattern(name)
            for name in self.blocklist
            if name.strip() and not is_overly_broad_pattern(name)
        ]

    @property
    def banlist_patterns(self) -> list[str]:
        return [
            normalize_pattern(name)
            for name in self.banlist
            if name.strip() and not is_overly_broad_pattern(name)
        ]

    @property
    def allowlist_patterns(self) -> list[str]:
        return [
            normalize_pattern(name)
            for name in self.allowlist
            if name.strip() and not is_overly_broad_pattern(name)
        ]

    @property
    def ignore_patterns(self) -> list[str]:
        return [
            normalize_pattern(name)
            for name in self.ignore_names
            if name.strip() and not is_overly_broad_pattern(name)
        ]

    def is_blocklisted(self, name: str) -> bool:
        return name_matches_any(name, self.blocklist_patterns)

    def is_banned(self, name: str) -> bool:
        return name_matches_any(name, self.banlist_patterns)

    def is_allowed(self, name: str) -> bool:
        return name_matches_any(name, self.allowlist_patterns)

    def is_auto_kill_target(self, name: str) -> bool:
        """True if name matches blocklist or banlist (and is not allowlisted)."""
        if self.is_allowed(name) or self.is_ignored(name):
            return False
        return self.is_blocklisted(name) or self.is_banned(name)

    def is_ignored(self, name: str) -> bool:
        return name_matches_any(name, self.ignore_patterns)

    def is_safeguarded(self, name: str) -> bool:
        """True if process should not be flagged or auto-killed."""
        return self.is_allowed(name) or self.is_ignored(name)

    @property
    def log_path(self) -> Path:
        path = Path(self.log_file)
        if not path.is_absolute():
            path = project_root() / path
        return path


def _as_float(value: Any, default: float, minimum: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, result)


def _as_int(value: Any, default: int, minimum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, result)


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            cleaned = item.strip()
            if cleaned:
                result.append(cleaned)
    return result


def default_config_path() -> Path:
    env_path = os.environ.get("PROCESS_HUNTER_CONFIG", "").strip()
    if env_path:
        return Path(env_path)
    return project_root() / "config.json"


def load_config(path: Path | None = None) -> AppConfig:
    """Load config from JSON, falling back to safe defaults if missing/invalid."""
    config_path = path or default_config_path()
    data: dict[str, Any] = {}

    if config_path.is_file():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}

    return AppConfig(
        poll_interval_seconds=_as_float(
            data.get("poll_interval_seconds"), 5.0, 1.0
        ),
        cpu_threshold_percent=_as_float(
            data.get("cpu_threshold_percent"), 15.0, 1.0
        ),
        cpu_sustained_polls=_as_int(data.get("cpu_sustained_polls"), 3, 1),
        max_recent_alerts=_as_int(data.get("max_recent_alerts"), 10, 1),
        blocklist=_as_str_list(data.get("blocklist")),
        banlist=_as_str_list(data.get("banlist")),
        allowlist=_as_str_list(data.get("allowlist")),
        ignore_names=_as_str_list(data.get("ignore_names")),
        log_file=str(data.get("log_file") or "process_hunter.log").strip()
        or "process_hunter.log",
        config_path=config_path,
    )


def _append_name_to_config_list(
    config: AppConfig,
    *,
    attr_name: str,
    json_key: str,
    process_name: str,
    already_check: Any,
    list_label: str,
) -> tuple[bool, str]:
    """Append a process name to a named list on config and persist to JSON."""
    name = process_name.strip()
    if not name:
        return False, f"No process name to add to the {list_label}."
    if is_overly_broad_pattern(name):
        return False, f"Refused overly broad pattern: {name}"

    if already_check(name):
        return True, f"{name} is already on the {list_label}."

    current: list[str] = getattr(config, attr_name)
    existing_lower = {normalize_pattern(item) for item in current}
    if normalize_pattern(name) in existing_lower:
        return True, f"{name} is already on the {list_label}."

    current.append(name)
    path = config.config_path or default_config_path()

    data: dict[str, Any] = {}
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}

    stored = _as_str_list(data.get(json_key))
    if normalize_pattern(name) not in {normalize_pattern(item) for item in stored}:
        stored.append(name)
    data[json_key] = stored

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        if current and normalize_pattern(current[-1]) == normalize_pattern(name):
            current.pop()
        return False, f"Could not save {list_label}: {exc}"

    return True, f"Added {name} to {list_label}."


def add_to_banlist(config: AppConfig, process_name: str) -> tuple[bool, str]:
    """Add a process name to the persistent banlist in config.json."""
    name = process_name.strip()
    if config.is_banned(name) or config.is_blocklisted(name):
        return True, f"{name} is already on the ban/block list."
    return _append_name_to_config_list(
        config,
        attr_name="banlist",
        json_key="banlist",
        process_name=name,
        already_check=lambda n: False,
        list_label="ban list",
    )


def add_to_allowlist(config: AppConfig, process_name: str) -> tuple[bool, str]:
    """Add a process name to the persistent allowlist in config.json."""
    name = process_name.strip()
    if config.is_allowed(name) or config.is_ignored(name):
        return True, f"{name} is already on the allow/ignore list."
    return _append_name_to_config_list(
        config,
        attr_name="allowlist",
        json_key="allowlist",
        process_name=name,
        already_check=lambda n: False,
        list_label="allow list",
    )
