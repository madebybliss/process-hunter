"""Process Hunter entry point."""

from __future__ import annotations

import logging
import sys


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main() -> int:
    if sys.platform != "win32":
        print("Process Hunter only supports Windows.", file=sys.stderr)
        return 1

    _configure_logging()

    from process_hunter.config import load_config
    from process_hunter.monitor import ProcessMonitor
    from process_hunter.tray import TrayApp

    config = load_config()
    monitor = ProcessMonitor(config)
    app = TrayApp(config, monitor)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
