#!/usr/bin/env python3
"""
Windows Forensic Collector

Read-only local Windows collection for devices you own or are authorized to examine.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import subprocess
import sys
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

USER_LISTING_FOLDERS = ["Desktop", "Downloads", "Documents", "Pictures", "Videos"]


@dataclass
class CommandResult:
    name: str
    command: list[str]
    returncode: int
    stdout_file: str | None = None
    stderr_file: str | None = None
    error: str | None = None


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in value) or "CASE"


class WindowsCollector:
    def __init__(self, case_id, output_root, examiner="", owner="",
                 evidence_id="", notes="", copy_user_media=False):
        started = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.case_dir = output_root / f"{safe_name(case_id)}_{started}"
        self.raw_dir = self.case_dir / "raw"
        self.exports_dir = self.case_dir / "exports"
        self.copied_dir = self.case_dir / "copied_user_files"
        self.results: list[CommandResult] = []
        self.copy_user_media = copy_user_media
        self.metadata = {
            "case_id": case_id, "started_at": datetime.now().isoformat(timespec="seconds"),
            "platform": "Windows", "examiner": examiner, "device_owner": owner,
            "evidence_id": evidence_id, "notes": notes, "copy_user_media": copy_user_media,
        }

    def run(self, name, command, timeout=120):
        stdout_path = self.raw_dir / f"{name}.txt"
        stderr_path = self.raw_dir / f"{name}.stderr.txt"
        try:
            completed = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout)
            stdout_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
            stderr_path.write_text(completed.stderr, encoding="utf-8", errors="replace")
            result = CommandResult(name=name, command=command, returncode=completed.returncode,
                                   stdout_file=str(stdout_path.relative_to(self.case_dir)),
                                   stderr_file=str(stderr_path.relative_to(self.case_dir)))
        except Exception as exc:
            result = CommandResult(name=name, command=command, returncode=-1, error=str(exc))
        self.results.append(result)
        return result

    def ps(self, name, script, timeout=120):
        return self.run(name, ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)

    def collect(self):
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.copied_dir.mkdir(parents=True, exist_ok=True)
        self.run("hostname", ["hostname"])
        self.run("whoami", ["whoami", "/all"])
        self.run("systeminfo", ["systeminfo"])
        self.run("ipconfig_all", ["ipconfig", "/all"])
        self.run("tasklist", ["tasklist", "/v"])
        self.run("netstat", ["netstat", "-ano"])
        self.run("net_users", ["net", "user"])
        self.ps("local_users", "Get-LocalUser | Format-List *")
        self.ps("local_groups", "Get-LocalGroup | Format-Table -AutoSize")
        self.ps("services", "Get-Service | Sort-Object Status,Name | Format-Table -AutoSize")
        self.ps("startup_items", "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | Format-List")
        self.ps("installed_programs",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
                "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
                "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | "
                "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object {$_.DisplayName} | "
                "Sort-Object DisplayName | Format-Table -AutoSize", timeout=180)
        self.ps("recent_user_files",
                "$h=$env:USERPROFILE; Get-ChildItem $h\\Desktop,$h\\Downloads,$h\\Documents,$h\\Pictures,$h\\Videos "
                "-Recurse -Force -ErrorAction SilentlyContinue | "
                "Select-Object FullName,Length,CreationTime,LastWriteTime | Sort-Object LastWriteTime -Descending | "
                "Select-Object -First 1000 | Format-Table -AutoSize", timeout=240)
        self.write_folder_csv()
        if self.copy_user_media:
            self.copy_selected_user_files()
        self.write_metadata()
        self.write_manifest()
        self.write_report()

    def write_folder_csv(self):
        csv_path = self.exports_dir / "user_folder_listing.csv"
        home = Path.home()
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["folder", "path", "size_bytes", "created", "modified"])
            writer.writeheader()
            for folder in USER_LISTING_FOLDERS:
                root = home / folder
                if not root.exists():
                    continue
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    try:
                        stat = path.stat()
                        writer.writerow({
                            "folder": folder, "path": str(path), "size_bytes": stat.st_size,
                            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds"),
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                        })
                    except OSError:
                        continue

    def copy_selected_user_files(self):
        allowed = {".jpg", ".jpeg", ".png", ".webp", ".mp4", ".mov", ".pdf", ".docx", ".xlsx", ".txt"}
        home = Path.home()
        for folder in USER_LISTING_FOLDERS:
            root = home / folder
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in allowed:
                    continue
                try:
                    relative = path.relative_to(home)
                    destination = self.copied_dir / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if path.stat().st_size <= 50 * 1024 * 1024:
                        destination.write_bytes(path.read_bytes())
                except OSError:
                    continue

    def iter_files(self):
        for path in self.case_dir.rglob("*"):
            if path.is_file() and path.name != "manifest_hashes.csv":
                yield path

    def write_metadata(self):
        (self.case_dir / "run_metadata.json").write_text(
            json.dumps({"metadata": self.metadata, "commands": [asdict(r) for r in self.results]}, indent=2),
            encoding="utf-8")

    def write_manifest(self):
        manifest_path = self.case_dir / "manifest_hashes.csv"
        with manifest_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["relative_path", "size_bytes", "sha256"])
            writer.writeheader()
            for path in sorted(self.iter_files()):
                writer.writerow({
                    "relative_path": str(path.relative_to(self.case_dir)),
                    "size_bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })

    def write_report(self):
        ok_count = sum(1 for r in self.results if r.returncode == 0)
        rows = []
        for result in self.results:
            status = "OK" if result.returncode == 0 else f"Exit {result.returncode}"
            rows.append(
                f"<tr><td>{html.escape(result.name)}</td><td>{html.escape(status)}</td>"
                f"<td>{html.escape(result.stdout_file or '')}</td>"
                f"<td>{html.escape(result.stderr_file or '')}</td>"
                f"<td><code>{html.escape(' '.join(result.command))}</code></td></tr>"
            )
        content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Windows Forensic Report - {html.escape(self.metadata["case_id"])}</title>
  <style>
    body{{font-family:Arial,sans-serif;margin:0;background:#f6f8fb;color:#202124;line-height:1.45}}
    header{{background:#17324d;color:white;padding:28px 36px}}
    main{{margin:24px 36px 40px}}
    section{{background:white;border:1px solid #d9e2ec;border-radius:8px;padding:18px;margin:16px 0}}
    table{{border-collapse:collapse;width:100%;font-size:13px}}
    th,td{{border:1px solid #d9e2ec;padding:8px;vertical-align:top;text-align:left}}
    th{{background:#eef4f8}}code{{white-space:pre-wrap;word-break:break-word}}
  </style>
</head>
<body>
  <header><h1>Windows Forensic Report</h1>
  <div>Case: {html.escape(self.metadata["case_id"])} | Started: {html.escape(self.metadata["started_at"])}</div></header>
  <main>
    <section>
      <h2>Summary</h2>
      <p>Read-only local Windows collection. Raw outputs in <code>raw/</code>, structured exports in <code>exports/</code>, hashes in <code>manifest_hashes.csv</code>.</p>
      <p>Successful: <strong>{ok_count}</strong> / {len(self.results)}</p>
      <table><tbody>
        <tr><th>Evidence ID</th><td>{html.escape(self.metadata.get("evidence_id",""))}</td></tr>
        <tr><th>Examiner</th><td>{html.escape(self.metadata.get("examiner",""))}</td></tr>
        <tr><th>Device owner</th><td>{html.escape(self.metadata.get("device_owner",""))}</td></tr>
        <tr><th>Notes</th><td>{html.escape(self.metadata.get("notes",""))}</td></tr>
      </tbody></table>
    </section>
    <section>
      <h2>Key Files</h2>
      <ul>
        <li><code>raw/systeminfo.txt</code></li>
        <li><code>raw/installed_programs.txt</code></li>
        <li><code>raw/tasklist.txt</code></li>
        <li><code>raw/startup_items.txt</code></li>
        <li><code>exports/user_folder_listing.csv</code></li>
      </ul>
    </section>
    <section>
      <h2>Evidence Index</h2>
      <table><thead><tr><th>Artifact</th><th>Status</th><th>Output</th><th>Error log</th><th>Command</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>
    </section>
  </main>
</body>
</html>"""
        (self.case_dir / "report.html").write_text(content, encoding="utf-8")


def make_zip(case_dir: Path) -> None:
    zip_path = case_dir / f"{case_dir.name}_windows_evidence.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(case_dir.rglob("*")):
            if path.is_file() and path != zip_path:
                archive.write(path, path.relative_to(case_dir))
    print(f"ZIP created: {zip_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Read-only Windows forensic collection tool.")
    parser.add_argument("--case-id")
    parser.add_argument("--output", default="windows_forensic_cases")
    parser.add_argument("--examiner", default="")
    parser.add_argument("--owner", default="")
    parser.add_argument("--evidence-id", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--copy-user-media", action="store_true")
    parser.add_argument("--make-zip")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.check:
        print("Windows forensic collector ready.")
        print(f"Current user: {os.environ.get('USERNAME', 'Unknown')}")
        print(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        return 0
    if args.make_zip:
        make_zip(Path(args.make_zip).resolve())
        return 0
    if not args.case_id:
        print("--case-id is required.", file=sys.stderr)
        return 2
    collector = WindowsCollector(
        case_id=args.case_id, output_root=Path(args.output).resolve(),
        examiner=args.examiner, owner=args.owner,
        evidence_id=args.evidence_id, notes=args.notes,
        copy_user_media=args.copy_user_media,
    )
    collector.collect()
    print(f"Collection complete: {collector.case_dir}")
    print(f"Open report: {collector.case_dir / 'report.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
