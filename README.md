https://github.com/AkankshaSingh-droid/Forensic-collector/blob/5809bed93b64b85eda46b912049d27fbf2bbbe9b/screenshot.jpeg                                                                                                                                                                                                                                                                                                                                                               
# Android Forensic Collector
A read-only forensic data collection tool for Android devices (and Windows PCs) using ADB.

> **Legal Notice:** Use only on devices you own or have explicit written authorization to examine.

---

## Features

- Read-only ADB collection — does not modify the device
- Timestamped case folder per run
- Detailed HTML report with device info, apps, accounts, storage summary
- SHA-256 hash manifest for evidence integrity
- CSV exports (apps, accounts, storage, timeline hints)
- Optional: screenshot capture, SMS/call/contacts collection, media copy, recovery attempt
- Windows PC collection mode (via PowerShell)
- GUI launcher (Tkinter)
- ZIP export for case packaging

---

## Requirements

- Python 3.10+
- [Android Platform Tools (ADB)](https://developer.android.com/tools/releases/platform-tools)
- Android phone with **USB debugging enabled**

---

## Installation

```bash
git clone https://github.com/AkankshaSingh-droid/Forensic-collector.git
cd Forensic-collector
```

No pip install needed — uses Python standard library only.

Optional better PDF reports:
```bash
pip install reportlab
```

---

## Usage

### GUI (Recommended)

```bash
python forensic_gui.py
```

### Command Line — Android

```bash
# Standard scan
python android_forensic_adb_tool.py --case-id CASE001 --examiner "Your Name"

# Full scan with media copy, screenshot, personal records
python android_forensic_adb_tool.py --case-id CASE001 \
  --examiner "Your Name" \
  --owner "Subject Name" \
  --evidence-id EV-001 \
  --screenshot \
  --collect-personal \
  --pull-media \
  --recovery-attempt

# Regenerate report for existing case
python android_forensic_adb_tool.py --rewrite-report path/to/case_folder

# Create ZIP export
python android_forensic_adb_tool.py --make-zip path/to/case_folder
```

### Command Line — Windows PC

```bash
python windows_forensic_collector.py --case-id CASE001 --examiner "Your Name"
```

---

## Output Structure

```
android_forensic_cases/
└── CASE001_20260629_120000/
    ├── report.html              ← Main report, open in browser
    ├── report_summary.pdf       ← Printable PDF summary
    ├── manifest_hashes.csv      ← SHA-256 hashes for all files
    ├── run_metadata.json        ← Run details and command log
    ├── raw/                     ← Raw ADB command outputs
    │   ├── getprop.txt
    │   ├── installed_packages.txt
    │   ├── logcat_dump.txt
    │   └── ... (30+ artifact files)
    ├── exports/                 ← Structured CSV exports
    │   ├── apps.csv
    │   ├── accounts.csv
    │   ├── storage_summary.csv
    │   └── timeline_hints.csv
    └── pulled_files/            ← Copied media (if --pull-media used)
```

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--case-id` | Case name/ID (required) |
| `--output` | Output folder (default: `android_forensic_cases`) |
| `--serial` | ADB device serial (for multiple devices) |
| `--examiner` | Examiner name for report |
| `--owner` | Device owner/subject name |
| `--evidence-id` | Evidence ID for report |
| `--notes` | Case notes |
| `--screenshot` | Capture device screenshot |
| `--collect-personal` | Request SMS, calls, contacts, calendar |
| `--pull-media` | Copy media folders from device |
| `--recovery-attempt` | Attempt to copy thumbnails, trash, WhatsApp/Telegram media |
| `--rewrite-report` | Regenerate report for existing case folder |
| `--make-zip` | Create ZIP evidence package |

---

## Files

| File | Description |
|------|-------------|
| `android_forensic_adb_tool.py` | Main Android ADB collector |
| `forensic_gui.py` | Tkinter GUI launcher |
| `windows_forensic_collector.py` | Windows local collector |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
