# Process Hunter

Windows system-tray app that watches running processes, **auto-kills** entries on your hard blocklist, and **notifies** you about high-CPU or suspicious-path processes so you can kill or ignore them from the tray menu.

This is **not antivirus**. It does not judge malware. It helps with known CPU hogs and unusual locations, with short explanations for common Windows processes.

## Requirements

- Windows 10/11
- Python 3.10+

## Install

Open a terminal in this folder (Python 3.12 recommended if you have several versions):

```bat
py -3.12 -m pip install -r requirements.txt
```

Or:

```bat
pip install -r requirements.txt
```

## Run

Double-click `run.bat`, or:

```bat
pyw -3.12 -m process_hunter
```

To see console logs while testing:

```bat
py -3.12 -m process_hunter
```

A tray icon (crosshair) appears near the clock. Right-click it for the menu.

## Tray menu

- **Monitoring On/Off** — pause or resume watching
- **Recent alerts** — for each alert: **Kill** or **Ignore for session**
- **Open config folder** / **Edit config.json**
- **View log** — opens `process_hunter.log`
- **Quit**

## Configuration (`config.json`)

| Key | Meaning |
|-----|---------|
| `poll_interval_seconds` | How often to scan (default `5`) |
| `cpu_threshold_percent` | CPU % that counts as “hot” (default `15`) |
| `cpu_sustained_polls` | How many hot polls in a row before alerting (default `3`) |
| `blocklist` | Process names/patterns to **auto-kill** (exact or wildcards) |
| `banlist` | Names banned from the alert banner; also **auto-killed** if seen again |
| `allowlist` | Trusted names/patterns — never flagged and never auto-killed |
| `ignore_names` | Always skip these names/patterns (same safeguard as allowlist) |

### Wildcards

`blocklist` and `ignore_names` support `*` and `?` (case-insensitive):

| Pattern | Matches |
|---------|---------|
| `Cursor*` | `Cursor.exe`, `Cursor Helper.exe`, … |
| `*Host.exe` | `TextInputHost.exe`, `ShellExperienceHost.exe`, … |
| `*Cursor*` | any process name containing `Cursor` |
| `SearchIndexer.exe` | exact name only (same as before) |

A bare `*` (or similar all-wildcard patterns) is ignored for safety.
| `max_recent_alerts` | How many alerts to keep in the tray menu |
| `log_file` | Log path (relative to project folder unless absolute) |

Default blocklist includes:

- `SearchIndexer.exe` — Windows Search indexer (CPU spikes)
- `TextInputHost.exe` — emoji / touch keyboard host
- `PhoneExperienceHost.exe` — Phone Link
- `OneDriveSetup.exe` — OneDrive setup helper

Edit the list anytime, then restart Process Hunter (Quit and run again) so the new config loads.

## Safety

A built-in **never-kill** list blocks terminating critical processes (`csrss.exe`, `lsass.exe`, `services.exe`, `dwm.exe`, `explorer.exe`, `svchost.exe`, Defender, etc.). Config cannot override that list.

`run.bat` prompts for Administrator (UAC) so protected processes can be killed. Approve the prompt when it appears.

## Windows Search indexer tip

Killing `SearchIndexer.exe` only helps until Windows Search starts it again.

For a lasting fix if you do not need indexing:

1. Press `Win + R`, type `services.msc`, Enter
2. Find **Windows Search**
3. Right-click → **Properties**
4. Set Startup type to **Disabled**, then **Stop**

You can still keep `SearchIndexer.exe` on the blocklist as a backup.

## Start with Windows

Double-click `install_startup.bat` and approve the UAC prompt. That creates a Task Scheduler entry (`ProcessHunter`) that runs at logon with Administrator rights (no UAC prompt every login).

To remove it later, run `uninstall_startup.bat`.

## Suspicious / high-CPU alerts

You get a toast **and** a full-width red banner across the top of the screen when:

- A process stays above `cpu_threshold_percent` for `cpu_sustained_polls` polls, or
- Its `.exe` is under Temp / Downloads (or outside normal Program Files / Windows / AppData locations)

The banner title shows **why** it was flagged:

- **Suspicious file found.** — unusual path (Temp/Downloads/etc.)
- **High load process found.** — sustained high CPU (orange banner)
- **Suspicious file + high load process.** — both

Banner actions:

- **Kill process** — terminate it
- **Kill and ban** — terminate it and add the name to `banlist` in `config.json` (auto-killed if it returns)
- **Add to allow list** — trust it; save to `allowlist` so it won’t be flagged again
- **Open folder** — open Explorer on the executable
- **More info** — detailed report (path, hashes, version, signature, command line, parent, memory, network sample)
- **Submit to VirusTotal** — hash/upload the `.exe` and show the scan result (needs API key)
- **Open folder, kill process, and delete process** — open Explorer, kill it, then delete the `.exe` (refuses Windows / Program Files protected paths)
- **Open folder, kill, ban, and delete** — same as above, plus add to `banlist`
- **Dismiss** — close the banner without acting
- **Minimize** (top-right) — collapse to a small corner tab so you can keep working; **Expand** restores the full banner

### VirusTotal

1. Create a free API key at [VirusTotal API key](https://www.virustotal.com/gui/my-apikey)
2. Put it in `.env` in this folder:

```env
VIRUSTOTAL_API_KEY=your_key_here
```

3. Restart Process Hunter

The banner button looks up the file by SHA-256 and uploads it if VirusTotal has never seen it (max 32 MB on the free API).

### Tray ban list menu

Right-click the tray icon → **Ban list**:

- **Add name or pattern...** — type e.g. `BadApp.exe` or `*Cap.exe`
- **Ban a running process...** — pick from a searchable list of current processes
- Shows names currently on the ban list

**Recent alerts** also has **Add to ban list** / **Kill and ban**. This is not antivirus — use **Windows Security** or VirusTotal if something looks truly malicious.
