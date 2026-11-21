"""Short plain-English blurbs for common Windows processes."""

from __future__ import annotations

EXPLANATIONS: dict[str, str] = {
    "searchindexer.exe": (
        "Windows Search indexer. Builds the search index; can spike CPU "
        "while scanning files. Safe to kill temporarily; it may restart "
        "if the Windows Search (WSearch) service is running."
    ),
    "textinputhost.exe": (
        "Text Input / emoji panel / touch keyboard host. Harmless but "
        "often unnecessary if you do not use those features."
    ),
    "phoneexperiencehost.exe": (
        "Phone Link / Your Phone companion. Syncs with a paired phone; "
        "safe to kill if you do not use Phone Link."
    ),
    "onedrivesetup.exe": (
        "OneDrive installer/updater helper. Not needed once OneDrive is set up."
    ),
    "onedrive.exe": (
        "Microsoft OneDrive sync client. Needed only if you sync files to OneDrive."
    ),
    "runtimebroker.exe": (
        "Windows Runtime Broker. Mediates permissions for Store/UWP apps. "
        "Usually leave it alone unless CPU is stuck high."
    ),
    "startmenuexperiencehost.exe": (
        "Hosts the Start menu UI. Do not kill unless it is hung."
    ),
    "shellexperiencehost.exe": (
        "Hosts taskbar/notification center UI. Avoid killing unless hung."
    ),
    "searchhost.exe": (
        "Windows Search UI host (search box / Start search)."
    ),
    "widgets.exe": (
        "Windows Widgets board. Safe to kill if you do not use widgets."
    ),
    "msedgewebview2.exe": (
        "Microsoft Edge WebView2 runtime used by many apps to show web UI. "
        "Killing it may break the parent app until it restarts."
    ),
    "securityhealthservice.exe": (
        "Windows Security health service. Leave running for Defender status."
    ),
    "antimalware service executable": (
        "Windows Defender (MsMpEng). High CPU during scans is normal; "
        "do not kill unless diagnosing a stuck scan."
    ),
    "msmpeng.exe": (
        "Windows Defender antivirus engine. Leave running."
    ),
    "compatteirunner.exe": (
        "Windows compatibility telemetry/assessment runner. "
        "Can be killed if it is stuck using CPU."
    ),
    "tiworker.exe": (
        "Windows Modules Installer Worker (updates). High CPU during updates "
        "is expected; prefer waiting over killing mid-update."
    ),
    "msiexec.exe": (
        "Windows Installer. Active during software install/uninstall."
    ),
    "dwm.exe": (
        "Desktop Window Manager. Critical for the desktop UI — never kill."
    ),
    "explorer.exe": (
        "Windows Explorer (desktop and File Explorer). Critical UI process."
    ),
    "svchost.exe": (
        "Generic host for Windows services. Do not auto-kill; identify the "
        "specific service first."
    ),
    "system": (
        "Windows System process. Critical kernel-related process — never kill."
    ),
    "csrss.exe": (
        "Client/Server Runtime Subsystem. Critical — never kill."
    ),
    "lsass.exe": (
        "Local Security Authority. Critical authentication process — never kill."
    ),
    "services.exe": (
        "Service Control Manager. Critical — never kill."
    ),
    "winlogon.exe": (
        "Windows logon process. Critical — never kill."
    ),
}


def explain_process(name: str | None) -> str:
    """Return a short explanation for a process name, or a generic message."""
    if not name:
        return "Unknown process. Check the full path before killing."
    key = name.strip().lower()
    if key in EXPLANATIONS:
        return EXPLANATIONS[key]
    return (
        "No built-in description. Check the executable path and publisher. "
        "If the path looks unusual (Temp/Downloads), treat with caution."
    )
