#!/usr/bin/env python3
"""
Android ADB Forensic Collector

Use only on devices you own or have explicit written authorization to examine.
The tool performs read-only collection through ADB and writes a timestamped
case folder with raw artifacts, hashes, and an HTML summary report.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable


COMMON_PATHS = [
    "/sdcard/DCIM",
    "/sdcard/Download",
    "/sdcard/Documents",
    "/sdcard/Pictures",
    "/sdcard/Movies",
    "/sdcard/WhatsApp/Media",
    "/sdcard/Android/media/com.whatsapp",
    "/sdcard/Android/media/org.telegram.messenger",
    "/sdcard/Android/media",
]

RECOVERY_PATHS = [
    "/sdcard/DCIM/.thumbnails",
    "/sdcard/Pictures/.thumbnails",
    "/sdcard/.Trash",
    "/sdcard/.trash",
    "/sdcard/Trash",
    "/sdcard/RecycleBin",
    "/sdcard/Pictures/Screenshot",
    "/sdcard/Pictures/WhatsApp",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/.Statuses",
    "/sdcard/Android/media/org.telegram.messenger/Telegram",
]

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".heic"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".3gp", ".mov", ".avi", ".webm"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"}

PERSONAL_DATA_QUERIES = {
    "sms_messages": "content://sms",
    "mms_messages": "content://mms",
    "call_logs": "content://call_log/calls",
    "contacts_phones": "content://contacts/phones",
    "contacts_people": "content://contacts/people",
    "calendar_events": "content://com.android.calendar/events",
}


def find_adb_executable() -> str | None:
    found = shutil.which("adb")
    if found:
        return found
    user_profile = os.environ.get("USERPROFILE")
    candidates: list[Path] = []
    if user_profile:
        base = Path(user_profile)
        candidates.extend([
            base / "Downloads" / "platform-tools-latest-windows" / "platform-tools" / "adb.exe",
            base / "Downloads" / "platform-tools" / "adb.exe",
            base / "Desktop" / "platform-tools" / "adb.exe",
        ])
    candidates.extend([
        Path("C:/platform-tools/adb.exe"),
        Path("C:/platform-tools/platform-tools/adb.exe"),
    ])
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


ARTIFACT_GUIDE = {
    "adb_devices": ("Device connection", "Connected Android device model, serial number, and ADB status."),
    "getprop": ("Device identity", "Phone model, Android version, build number, SIM/network properties, and system identifiers."),
    "date": ("Device time", "Device date and time at collection. Useful for timeline verification."),
    "uptime": ("Device uptime", "How long the phone has been running. This can help identify a recent reboot."),
    "settings_secure": ("Secure settings", "Lock, input, accessibility, location, and account-related secure settings."),
    "settings_system": ("System settings", "Display, sound, ringtone, time format, and general user settings."),
    "settings_global": ("Global settings", "ADB, network, airplane mode, developer settings, and device-wide options."),
    "installed_packages": ("Installed apps", "Installed apps, package paths, user IDs, and installer source."),
    "package_details": ("App details", "App permissions, services, receivers, install/update details, and component metadata."),
    "account_services": ("Accounts", "System-level view of account services configured on the device."),
    "wifi_info": ("Wi-Fi evidence", "Wi-Fi subsystem status and network details exposed by Android."),
    "battery": ("Battery status", "Battery health, charging state, level, and power source."),
    "netstats": ("Network usage", "Network usage counters and traffic history for apps/system components."),
    "activity_recents": ("Recent activity", "System record of recent apps/tasks, useful for timeline clues."),
    "notification": ("Notifications", "Notification subsystem dump. May contain traces of recent app notifications."),
    "location": ("Location subsystem", "Location providers, settings, and exposed Android location service records."),
    "logcat_dump": ("System logs", "Android runtime logs. Useful for recent app/system events and errors."),
    "sms_messages": ("SMS messages", "SMS records exported through Android content provider."),
    "mms_messages": ("MMS messages", "MMS records exported through Android content provider."),
    "call_logs": ("Call logs", "Call log records exported through Android content provider."),
    "contacts_phones": ("Contacts phones", "Contact phone records exported through Android content provider."),
    "contacts_people": ("Contacts people", "Contact records exported through Android content provider."),
    "calendar_events": ("Calendar events", "Calendar event records exported through Android content provider."),
}


def describe_artifact(name: str) -> tuple[str, str]:
    if name.startswith("pull_"):
        return ("Copied media/files", "Record of user-accessible folders copied from the device.")
    return ARTIFACT_GUIDE.get(name, ("Collected artifact", "Raw forensic output collected through ADB."))


def read_case_text(case_dir: Path, relative_path: str, max_chars: int = 500_000) -> str:
    path = case_dir / relative_path
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


def parse_getprop(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\[(.+?)\]: \[(.*)\]$", line.strip())
        if match:
            props[match.group(1)] = match.group(2)
    return props


def count_listing_entries(text: str) -> int:
    total = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":") or stripped.startswith("total "):
            continue
        total += 1
    return total


def first_matching_lines(text: str, keywords: list[str], limit: int = 12) -> list[str]:
    hits = []
    lowered = [k.lower() for k in keywords]
    for line in text.splitlines():
        clean = line.strip()
        if clean and any(k in clean.lower() for k in lowered):
            hits.append(clean)
        if len(hits) >= limit:
            break
    return hits


def build_detailed_findings(case_dir: Path) -> dict[str, object]:
    getprop = parse_getprop(read_case_text(case_dir, "raw/getprop.txt"))
    installed_packages = read_case_text(case_dir, "raw/installed_packages.txt")
    accounts = read_case_text(case_dir, "raw/account_services.txt")
    recents = read_case_text(case_dir, "raw/activity_recents.txt")
    notifications = read_case_text(case_dir, "raw/notification.txt")
    logcat = read_case_text(case_dir, "raw/logcat_dump.txt")
    battery = read_case_text(case_dir, "raw/battery.txt")

    listing_files = [
        ("Camera/DCIM", "raw/listing_sdcard_DCIM.txt"),
        ("Downloads", "raw/listing_sdcard_Download.txt"),
        ("Documents", "raw/listing_sdcard_Documents.txt"),
        ("Pictures", "raw/listing_sdcard_Pictures.txt"),
        ("Movies", "raw/listing_sdcard_Movies.txt"),
        ("Legacy WhatsApp Media", "raw/listing_sdcard_WhatsApp_Media.txt"),
        ("Android App Media", "raw/listing_sdcard_Android_media.txt"),
    ]
    storage_summary = []
    for label, relative_path in listing_files:
        text = read_case_text(case_dir, relative_path)
        storage_summary.append({
            "label": label,
            "entries": count_listing_entries(text),
            "file": relative_path.replace("/", "\\"),
        })

    account_lines = [
        line.strip() for line in accounts.splitlines()
        if line.strip().startswith("Account {")
    ]

    package_lines = [l for l in installed_packages.splitlines() if l.startswith("package:")]
    interesting_apps = []
    app_keywords = ["whatsapp", "telegram", "instagram", "facebook", "snapchat",
                    "chrome", "truecaller", "drive", "office", "pay", "bank", "maps"]
    for line in package_lines:
        if any(k in line.lower() for k in app_keywords):
            interesting_apps.append(line)
        if len(interesting_apps) >= 18:
            break

    return {
        "device": {
            "manufacturer": getprop.get("ro.product.manufacturer") or getprop.get("ro.product.vendor.manufacturer", ""),
            "brand": getprop.get("ro.product.brand", ""),
            "model": getprop.get("ro.product.model", ""),
            "device": getprop.get("ro.product.device", ""),
            "android_version": getprop.get("ro.build.version.release", ""),
            "sdk": getprop.get("ro.build.version.sdk", ""),
            "security_patch": getprop.get("ro.build.version.security_patch", ""),
            "build_fingerprint": getprop.get("ro.build.fingerprint", ""),
            "serial": getprop.get("ro.serialno", ""),
        },
        "collection": {
            "device_date": read_case_text(case_dir, "raw/date.txt", 2_000).strip(),
            "uptime": read_case_text(case_dir, "raw/uptime.txt", 2_000).strip(),
            "battery_lines": first_matching_lines(battery, ["level", "status", "health", "powered"], 10),
        },
        "apps": {
            "count": len(package_lines),
            "examples": interesting_apps,
            "source": "raw\\installed_packages.txt",
        },
        "accounts": {
            "count": len(account_lines),
            "examples": account_lines[:20],
            "source": "raw\\account_services.txt",
        },
        "storage": storage_summary,
        "activity": {
            "recent_lines": first_matching_lines(recents, ["Recent", "TaskRecord", "realActivity", "baseIntent", "affinity"], 14),
            "notification_lines": first_matching_lines(notifications, ["NotificationRecord", "pkg=", "package=", "android.title", "ticker"], 14),
            "log_lines": first_matching_lines(logcat, [" E ", " W ", "ActivityTaskManager", "START", "Displayed"], 18),
        },
    }


def render_detail_table(rows: list[tuple[str, str]]) -> str:
    rendered = []
    for label, value in rows:
        rendered.append(f"<tr><th>{html.escape(label)}</th><td>{html.escape(value or 'Not available')}</td></tr>")
    return "".join(rendered)


def render_list(items: list[str], empty_text: str = "No direct entries extracted for this summary.") -> str:
    if not items:
        return f"<p class=\"empty\">{html.escape(empty_text)}</p>"
    return "<ul>" + "".join(f"<li><code>{html.escape(item)}</code></li>" for item in items) + "</ul>"


def render_image_gallery(items: list[tuple[str, int]]) -> str:
    if not items:
        return "<p class=\"empty\">No copied image files were found for preview indexing.</p>"
    rows = []
    for relative_path, size in items:
        rows.append(f"<tr><td><code>{html.escape(relative_path)}</code></td><td>{html.escape(str(size))}</td></tr>")
    return (
        "<table><thead><tr><th>Image path</th><th>Size bytes</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


@dataclass
class CommandResult:
    name: str
    command: list[str]
    returncode: int
    stdout_file: str | None = None
    stderr_file: str | None = None
    error: str | None = None


class Collector:
    def __init__(self, case_id, output_root, serial, pull_media,
                 examiner="", owner="", evidence_id="", notes="",
                 screenshot=False, collect_personal=False, recovery_attempt=False):
        started = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_case = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_id)
        self.case_dir = output_root / f"{safe_case}_{started}"
        self.raw_dir = self.case_dir / "raw"
        self.pulled_dir = self.case_dir / "pulled_files"
        self.serial = serial
        self.pull_media = pull_media
        self.screenshot = screenshot
        self.collect_personal = collect_personal
        self.recovery_attempt = recovery_attempt
        self.results: list[CommandResult] = []
        self.metadata = {
            "case_id": case_id, "started_at": datetime.now().isoformat(timespec="seconds"),
            "adb_serial": serial, "pull_media": pull_media, "examiner": examiner,
            "device_owner": owner, "evidence_id": evidence_id, "notes": notes,
            "screenshot": screenshot, "collect_personal": collect_personal,
            "recovery_attempt": recovery_attempt,
        }

    def adb_base(self):
        adb = find_adb_executable() or "adb"
        cmd = [adb]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(self, name, adb_args):
        stdout_path = self.raw_dir / f"{name}.txt"
        stderr_path = self.raw_dir / f"{name}.stderr.txt"
        command = self.adb_base() + adb_args
        try:
            completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=120)
            stdout_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
            stderr_path.write_text(completed.stderr, encoding="utf-8", errors="replace")
            result = CommandResult(name=name, command=command, returncode=completed.returncode,
                                   stdout_file=str(stdout_path.relative_to(self.case_dir)),
                                   stderr_file=str(stderr_path.relative_to(self.case_dir)))
        except Exception as exc:
            result = CommandResult(name=name, command=command, returncode=-1, error=str(exc))
        self.results.append(result)
        return result

    def pull(self, device_path):
        safe_name = device_path.strip("/").replace("/", "_").replace(":", "_") or "root"
        destination = self.pulled_dir / safe_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        command = self.adb_base() + ["pull", device_path, str(destination)]
        stderr_path = self.raw_dir / f"pull_{safe_name}.stderr.txt"
        try:
            completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=900)
            stderr_path.write_text(completed.stderr + completed.stdout, encoding="utf-8", errors="replace")
            result = CommandResult(name=f"pull_{safe_name}", command=command, returncode=completed.returncode,
                                   stderr_file=str(stderr_path.relative_to(self.case_dir)))
        except Exception as exc:
            result = CommandResult(name=f"pull_{safe_name}", command=command, returncode=-1, error=str(exc))
        self.results.append(result)
        return result

    def capture_screenshot(self):
        screenshot_path = self.case_dir / "device_screenshot.png"
        stderr_path = self.raw_dir / "device_screenshot.stderr.txt"
        command = self.adb_base() + ["exec-out", "screencap", "-p"]
        try:
            completed = subprocess.run(command, capture_output=True, timeout=60)
            screenshot_path.write_bytes(completed.stdout)
            stderr_path.write_bytes(completed.stderr)
            result = CommandResult(name="device_screenshot", command=command, returncode=completed.returncode,
                                   stdout_file=str(screenshot_path.relative_to(self.case_dir)),
                                   stderr_file=str(stderr_path.relative_to(self.case_dir)))
        except Exception as exc:
            result = CommandResult(name="device_screenshot", command=command, returncode=-1, error=str(exc))
        self.results.append(result)
        return result

    def collect(self):
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.pulled_dir.mkdir(parents=True, exist_ok=True)
        self.run("adb_devices", ["devices", "-l"])
        self.run("getprop", ["shell", "getprop"])
        self.run("date", ["shell", "date"])
        self.run("uptime", ["shell", "uptime"])
        self.run("settings_secure", ["shell", "settings", "list", "secure"])
        self.run("settings_system", ["shell", "settings", "list", "system"])
        self.run("settings_global", ["shell", "settings", "list", "global"])
        self.run("installed_packages", ["shell", "pm", "list", "packages", "-f", "-U", "-i"])
        self.run("package_details", ["shell", "dumpsys", "package"])
        self.run("account_services", ["shell", "dumpsys", "account"])
        self.run("wifi_info", ["shell", "dumpsys", "wifi"])
        self.run("battery", ["shell", "dumpsys", "battery"])
        self.run("netstats", ["shell", "dumpsys", "netstats"])
        self.run("activity_recents", ["shell", "dumpsys", "activity", "recents"])
        self.run("notification", ["shell", "dumpsys", "notification"])
        self.run("location", ["shell", "dumpsys", "location"])
        self.run("logcat_dump", ["logcat", "-d", "-v", "threadtime"])
        if self.screenshot:
            self.capture_screenshot()
        if self.collect_personal:
            for name, uri in PERSONAL_DATA_QUERIES.items():
                self.run(name, ["shell", "content", "query", "--uri", uri])
        for device_path in COMMON_PATHS:
            name = "listing_" + device_path.strip("/").replace("/", "_")
            self.run(name, ["shell", "ls", "-laR", device_path])
        if self.pull_media:
            for device_path in COMMON_PATHS:
                self.pull(device_path)
        if self.recovery_attempt:
            self.run_recovery_attempt()
        self.write_csv_exports()
        self.write_manifest()
        self.write_report()

    def run_recovery_attempt(self):
        recovery_dir = self.case_dir / "recovery_attempt"
        recovery_dir.mkdir(parents=True, exist_ok=True)
        for device_path in RECOVERY_PATHS:
            safe_name = device_path.strip("/").replace("/", "_").replace(":", "_") or "root"
            self.run(f"recovery_listing_{safe_name}", ["shell", "ls", "-laR", device_path])
            destination = recovery_dir / safe_name
            command = self.adb_base() + ["pull", device_path, str(destination)]
            stderr_path = self.raw_dir / f"recovery_pull_{safe_name}.stderr.txt"
            try:
                completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=900)
                stderr_path.write_text(completed.stderr + completed.stdout, encoding="utf-8", errors="replace")
                result = CommandResult(name=f"recovery_pull_{safe_name}", command=command,
                                       returncode=completed.returncode,
                                       stderr_file=str(stderr_path.relative_to(self.case_dir)))
            except Exception as exc:
                result = CommandResult(name=f"recovery_pull_{safe_name}", command=command, returncode=-1, error=str(exc))
            self.results.append(result)

    def file_type_summary(self):
        summary = {"images": 0, "videos": 0, "documents": 0, "other": 0}
        for root_name in ["pulled_files", "recovery_attempt"]:
            root = self.case_dir / root_name
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                suffix = path.suffix.lower()
                if suffix in IMAGE_EXTENSIONS:
                    summary["images"] += 1
                elif suffix in VIDEO_EXTENSIONS:
                    summary["videos"] += 1
                elif suffix in DOCUMENT_EXTENSIONS:
                    summary["documents"] += 1
                else:
                    summary["other"] += 1
        return summary

    def image_gallery_items(self, limit=80):
        items = []
        for root_name in ["recovery_attempt", "pulled_files"]:
            root = self.case_dir / root_name
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
                    items.append((str(path.relative_to(self.case_dir)), path.stat().st_size))
                    if len(items) >= limit:
                        return items
        return items

    def write_csv_exports(self):
        exports_dir = self.case_dir / "exports"
        exports_dir.mkdir(parents=True, exist_ok=True)
        findings = build_detailed_findings(self.case_dir)
        installed_packages = read_case_text(self.case_dir, "raw/installed_packages.txt")
        apps_path = exports_dir / "apps.csv"
        with apps_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["package_line", "category"])
            writer.writeheader()
            for line in installed_packages.splitlines():
                if not line.startswith("package:"):
                    continue
                lo = line.lower()
                if any(k in lo for k in ["whatsapp", "telegram", "instagram", "facebook", "snapchat"]):
                    cat = "Messaging / Social"
                elif any(k in lo for k in ["chrome", "browser", "firefox"]):
                    cat = "Browser"
                elif any(k in lo for k in ["pay", "bank", "wallet", "upi"]):
                    cat = "Payment / Banking"
                elif any(k in lo for k in ["drive", "dropbox", "onedrive", "dubox"]):
                    cat = "Cloud Storage"
                else:
                    cat = "Other"
                writer.writerow({"package_line": line, "category": cat})
        accounts_path = exports_dir / "accounts.csv"
        with accounts_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["account_entry"])
            writer.writeheader()
            for entry in findings["accounts"]["examples"]:
                writer.writerow({"account_entry": entry})
        storage_path = exports_dir / "storage_summary.csv"
        with storage_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["folder", "visible_entries", "source_file"])
            writer.writeheader()
            for item in findings["storage"]:
                writer.writerow({"folder": item["label"], "visible_entries": item["entries"], "source_file": item["file"]})
        timeline_path = exports_dir / "timeline_hints.csv"
        with timeline_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["source", "line"])
            writer.writeheader()
            for line in findings["activity"]["recent_lines"]:
                writer.writerow({"source": "activity_recents", "line": line})
            for line in findings["activity"]["notification_lines"]:
                writer.writerow({"source": "notification", "line": line})
            for line in findings["activity"]["log_lines"]:
                writer.writerow({"source": "logcat", "line": line})

    def iter_files(self):
        for path in self.case_dir.rglob("*"):
            if path.is_file() and path.name != "manifest_hashes.csv":
                yield path

    def write_manifest(self):
        manifest_path = self.case_dir / "manifest_hashes.csv"
        with manifest_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["relative_path", "size_bytes", "sha256"])
            writer.writeheader()
            for path in sorted(self.iter_files()):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                writer.writerow({"relative_path": str(path.relative_to(self.case_dir)),
                                 "size_bytes": path.stat().st_size, "sha256": digest})
        (self.case_dir / "run_metadata.json").write_text(
            json.dumps({"metadata": self.metadata, "commands": [asdict(r) for r in self.results]}, indent=2),
            encoding="utf-8")

    def write_case_zip(self):
        zip_path = self.case_dir / f"{self.case_dir.name}_evidence.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(self.case_dir.rglob("*")):
                if not path.is_file() or path == zip_path:
                    continue
                archive.write(path, path.relative_to(self.case_dir))

    def write_report(self):
        report_path = self.case_dir / "report.html"
        findings = build_detailed_findings(self.case_dir)
        device = findings["device"]
        collection = findings["collection"]
        apps = findings["apps"]
        accounts = findings["accounts"]
        storage = findings["storage"]
        activity = findings["activity"]
        file_summary = self.file_type_summary()
        gallery_items = self.image_gallery_items()
        ok_count = sum(1 for r in self.results if r.returncode == 0)
        issue_count = len(self.results) - ok_count
        rows = []
        for result in self.results:
            status = "OK" if result.returncode == 0 else f"Exit {result.returncode}"
            title, meaning = describe_artifact(result.name)
            status_note = "Collected successfully." if result.returncode == 0 else "Warning/error. Check error file."
            rows.append(
                f"<tr><td><strong>{html.escape(title)}</strong><br><span>{html.escape(result.name)}</span></td>"
                f"<td><strong>{html.escape(status)}</strong><br><span>{html.escape(status_note)}</span></td>"
                f"<td>{html.escape(meaning)}</td>"
                f"<td>{html.escape(result.stdout_file or '')}</td>"
                f"<td>{html.escape(result.stderr_file or '')}</td>"
                f"<td><code>{html.escape(' '.join(result.command))}</code></td></tr>"
            )
        storage_rows = []
        for item in storage:
            storage_rows.append(
                f"<tr><td>{html.escape(item['label'])}</td>"
                f"<td>{html.escape(str(item['entries']))}</td>"
                f"<td><code>{html.escape(item['file'])}</code></td></tr>"
            )
        content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Android Forensic Report - {html.escape(self.metadata["case_id"])}</title>
  <style>
    body{{font-family:Arial,sans-serif;margin:0;color:#202124;background:#f8fafc;line-height:1.45}}
    header{{background:#17324d;color:white;padding:28px 36px}}
    main{{margin:24px 36px 40px}}
    h1{{margin:0 0 6px;font-size:28px}}h2{{margin-top:28px;font-size:19px}}
    .muted{{color:#d7e2ea}}.panel{{background:white;border:1px solid #d9e2ec;border-radius:8px;padding:18px;margin:16px 0}}
    .grid{{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px}}
    .metric{{background:#eef4f8;border:1px solid #d5e1e8;border-radius:6px;padding:12px}}
    .metric strong{{display:block;font-size:22px}}.note{{background:#fff7e6;border:1px solid #f0d28a;border-radius:6px;padding:12px}}
    .empty{{color:#667085}}.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
    .detail-table th{{width:220px}}ul{{margin-top:8px;padding-left:22px}}li{{margin:5px 0}}
    table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:13px;background:white}}
    th,td{{border:1px solid #d9e2ec;padding:9px;vertical-align:top}}th{{background:#eef4f8;text-align:left}}
    td span{{color:#667085;font-size:12px}}code{{white-space:pre-wrap;word-break:break-word}}
  </style>
</head>
<body>
  <header>
    <h1>Android Forensic Report</h1>
    <div class="muted">Case: {html.escape(self.metadata["case_id"])} | Started: {html.escape(self.metadata["started_at"])}</div>
  </header>
  <main>
    <section class="panel">
      <h2>Summary</h2>
      <div class="grid">
        <div class="metric"><strong>{len(self.results)}</strong>Total checks</div>
        <div class="metric"><strong>{ok_count}</strong>Successful</div>
        <div class="metric"><strong>{issue_count}</strong>Warnings/errors</div>
        <div class="metric"><strong>{html.escape(str(self.metadata.get("adb_serial") or "Default"))}</strong>ADB device</div>
      </div>
    </section>
    <section class="panel">
      <h2>Case Details</h2>
      <table class="detail-table"><tbody>
        {render_detail_table([
            ("Case ID", str(self.metadata.get("case_id",""))),
            ("Evidence ID", str(self.metadata.get("evidence_id",""))),
            ("Examiner", str(self.metadata.get("examiner",""))),
            ("Device owner / subject", str(self.metadata.get("device_owner",""))),
            ("Notes", str(self.metadata.get("notes",""))),
        ])}
      </tbody></table>
    </section>
    <section class="panel">
      <h2>Device Details</h2>
      <table class="detail-table"><tbody>
        {render_detail_table([
            ("Manufacturer", str(device["manufacturer"])),("Brand", str(device["brand"])),
            ("Model", str(device["model"])),("Android version", str(device["android_version"])),
            ("SDK", str(device["sdk"])),("Security patch", str(device["security_patch"])),
            ("Build fingerprint", str(device["build_fingerprint"])),
        ])}
      </tbody></table>
    </section>
    <section class="two-col">
      <div class="panel">
        <h2>Collection Timeline</h2>
        <table class="detail-table"><tbody>
          {render_detail_table([("Device date/time", str(collection["device_date"])),("Uptime", str(collection["uptime"]))])}
        </tbody></table>
        <h3>Battery</h3>{render_list(collection["battery_lines"], "No battery lines extracted.")}
      </div>
      <div class="panel">
        <h2>Installed Apps ({html.escape(str(apps["count"]))} total)</h2>
        <h3>Priority Apps</h3>{render_list(apps["examples"], "No priority apps found.")}
      </div>
    </section>
    <section class="panel">
      <h2>Accounts ({html.escape(str(accounts["count"]))} found)</h2>
      {render_list(accounts["examples"], "No account entries extracted.")}
    </section>
    <section class="panel">
      <h2>Storage Summary</h2>
      <table><thead><tr><th>Folder</th><th>Visible entries</th><th>Source file</th></tr></thead>
      <tbody>{''.join(storage_rows)}</tbody></table>
    </section>
    <section class="panel">
      <h2>Copied Files</h2>
      <table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>
        <tr><td>Images</td><td>{file_summary["images"]}</td></tr>
        <tr><td>Videos</td><td>{file_summary["videos"]}</td></tr>
        <tr><td>Documents</td><td>{file_summary["documents"]}</td></tr>
        <tr><td>Other</td><td>{file_summary["other"]}</td></tr>
      </tbody></table>
    </section>
    <section class="panel">
      <h2>Image Preview Index</h2>{render_image_gallery(gallery_items)}
    </section>
    <section class="two-col">
      <div class="panel"><h2>Recent Activity</h2>{render_list(activity["recent_lines"],"No activity lines.")}</div>
      <div class="panel"><h2>Notifications</h2>{render_list(activity["notification_lines"],"No notification lines.")}</div>
    </section>
    <section class="panel"><h2>System Log Hints</h2>{render_list(activity["log_lines"],"No log hints.")}</section>
    <section>
      <h2>Evidence Index</h2>
      <table><thead><tr><th>Item</th><th>Status</th><th>Description</th><th>Output</th><th>Error log</th><th>Command</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>
    </section>
  </main>
</body>
</html>"""
        report_path.write_text(content, encoding="utf-8")


def rewrite_report(case_dir: Path) -> None:
    metadata_path = case_dir / "run_metadata.json"
    if not metadata_path.exists():
        print(f"run_metadata.json not found in {case_dir}", file=sys.stderr)
        raise SystemExit(2)
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata = data.get("metadata", {})
    collector = Collector(
        case_id=metadata.get("case_id", "CASE"), output_root=case_dir.parent,
        serial=metadata.get("adb_serial"), pull_media=bool(metadata.get("pull_media")),
        examiner=metadata.get("examiner", ""), owner=metadata.get("device_owner", ""),
        evidence_id=metadata.get("evidence_id", ""), notes=metadata.get("notes", ""),
        screenshot=bool(metadata.get("screenshot")), collect_personal=bool(metadata.get("collect_personal")),
        recovery_attempt=bool(metadata.get("recovery_attempt")),
    )
    collector.case_dir = case_dir
    collector.raw_dir = case_dir / "raw"
    collector.pulled_dir = case_dir / "pulled_files"
    collector.metadata = metadata
    collector.results = [CommandResult(**item) for item in data.get("commands", [])]
    collector.write_csv_exports()
    collector.write_report()
    print(f"Report updated: {case_dir / 'report.html'}")


def make_zip_export(case_dir: Path) -> None:
    metadata_path = case_dir / "run_metadata.json"
    metadata = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8")).get("metadata", {})
    collector = Collector(
        case_id=metadata.get("case_id", case_dir.name), output_root=case_dir.parent,
        serial=metadata.get("adb_serial"), pull_media=bool(metadata.get("pull_media")),
    )
    collector.case_dir = case_dir
    collector.raw_dir = case_dir / "raw"
    collector.pulled_dir = case_dir / "pulled_files"
    collector.metadata = metadata
    collector.write_case_zip()
    print(f"ZIP created: {case_dir / (case_dir.name + '_evidence.zip')}")


def ensure_adb_available() -> None:
    if not find_adb_executable():
        print("ADB not found. Install Android Platform Tools and add adb to PATH.", file=sys.stderr)
        raise SystemExit(2)


def parse_args():
    parser = argparse.ArgumentParser(description="Read-only Android forensic collection tool using ADB.")
    parser.add_argument("--case-id", help="Case name or evidence ID.")
    parser.add_argument("--output", default="android_forensic_cases", help="Output folder.")
    parser.add_argument("--serial", help="ADB device serial.")
    parser.add_argument("--examiner", default="")
    parser.add_argument("--owner", default="")
    parser.add_argument("--evidence-id", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--collect-personal", action="store_true")
    parser.add_argument("--recovery-attempt", action="store_true")
    parser.add_argument("--pull-media", action="store_true")
    parser.add_argument("--rewrite-report", help="Regenerate report for existing case folder.")
    parser.add_argument("--make-zip", help="Create ZIP export for existing case folder.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.rewrite_report:
        rewrite_report(Path(args.rewrite_report).resolve())
        return 0
    if args.make_zip:
        make_zip_export(Path(args.make_zip).resolve())
        return 0
    if not args.case_id:
        print("--case-id is required.", file=sys.stderr)
        return 2
    ensure_adb_available()
    collector = Collector(
        case_id=args.case_id, output_root=Path(args.output).resolve(),
        serial=args.serial, pull_media=args.pull_media,
        examiner=args.examiner, owner=args.owner,
        evidence_id=args.evidence_id, notes=args.notes,
        screenshot=args.screenshot, collect_personal=args.collect_personal,
        recovery_attempt=args.recovery_attempt,
    )
    collector.collect()
    print(f"Collection complete: {collector.case_dir}")
    print(f"Open report: {collector.case_dir / 'report.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
