#!/usr/bin/env python3
"""
GUI launcher for Android ADB Forensic Collector.
Run this file to open the graphical interface.
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path(__file__).resolve().parent
COLLECTOR = APP_DIR / "android_forensic_adb_tool.py"
WINDOWS_COLLECTOR = APP_DIR / "windows_forensic_collector.py"


class ForensicGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Android Forensic Collector")
        self.geometry("980x760")
        self.minsize(860, 650)
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.last_report: Path | None = None
        self.current_case_dir: Path | None = None
        self.process: subprocess.Popen[str] | None = None
        self.case_id = tk.StringVar(value="CASE001")
        self.target_platform = tk.StringVar(value="android")
        self.evidence_id = tk.StringVar()
        self.examiner = tk.StringVar()
        self.owner = tk.StringVar()
        self.notes = tk.StringVar()
        self.scan_mode = tk.StringVar(value="standard")
        self.capture_screenshot = tk.BooleanVar(value=True)
        self.collect_personal = tk.BooleanVar(value=False)
        self.recovery_attempt = tk.BooleanVar(value=False)
        self.search_keyword = tk.StringVar()
        self.status = tk.StringVar(value="Ready")
        self.configure(bg="#f6f8fb")
        self.create_widgets()
        self.after(150, self.drain_output_queue)

    def create_widgets(self) -> None:
        header = tk.Frame(self, bg="#17324d", padx=22, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="Android Forensic Collector", bg="#17324d", fg="white",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="Read-only ADB collection with detailed report, CSV exports, screenshot, and hash manifest",
                 bg="#17324d", fg="#d7e2ea", font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))
        body = tk.Frame(self, bg="#f6f8fb", padx=22, pady=18)
        body.pack(fill="both", expand=True)
        controls = tk.LabelFrame(body, text="Collection Setup", bg="white", fg="#202124",
                                  padx=14, pady=12, font=("Segoe UI", 10, "bold"))
        controls.pack(fill="x")
        platform_frame = tk.Frame(controls, bg="white")
        platform_frame.grid(row=0, column=2, sticky="w", padx=(28, 0), pady=(0, 10))
        tk.Label(platform_frame, text="Target", bg="white", font=("Segoe UI", 10)).pack(anchor="w")
        ttk.Radiobutton(platform_frame, text="Android phone", variable=self.target_platform, value="android").pack(anchor="w")
        ttk.Radiobutton(platform_frame, text="Windows PC", variable=self.target_platform, value="windows").pack(anchor="w")
        self.add_labeled_entry(controls, "Case ID", self.case_id, 0, 0, 34)
        self.add_labeled_entry(controls, "Evidence ID", self.evidence_id, 2, 0, 34)
        self.add_labeled_entry(controls, "Examiner", self.examiner, 0, 1, 30, padx=(24, 0))
        self.add_labeled_entry(controls, "Device owner / subject", self.owner, 2, 1, 30, padx=(24, 0))
        tk.Label(controls, text="Notes", bg="white", font=("Segoe UI", 10)).grid(row=4, column=0, sticky="w")
        tk.Entry(controls, textvariable=self.notes, width=68, font=("Segoe UI", 10)).grid(
            row=5, column=0, columnspan=2, sticky="we", pady=(3, 8))
        mode_frame = tk.Frame(controls, bg="white")
        mode_frame.grid(row=2, column=2, sticky="w", padx=(28, 0), pady=(0, 10))
        ttk.Radiobutton(mode_frame, text="Standard scan", variable=self.scan_mode, value="standard").pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Media scan", variable=self.scan_mode, value="media").pack(anchor="w")
        ttk.Checkbutton(mode_frame, text="Capture screenshot", variable=self.capture_screenshot).pack(anchor="w")
        ttk.Checkbutton(mode_frame, text="Collect SMS/calls/contacts if allowed", variable=self.collect_personal).pack(anchor="w")
        ttk.Checkbutton(mode_frame, text="Attempt deleted photo recovery", variable=self.recovery_attempt).pack(anchor="w")
        button_frame = tk.Frame(controls, bg="white")
        button_frame.grid(row=4, column=2, rowspan=3, sticky="ne", padx=(28, 0), pady=(0, 10))
        self.device_button = ttk.Button(button_frame, text="Check Device", command=self.check_device)
        self.device_button.pack(fill="x", pady=(0, 7))
        self.start_button = ttk.Button(button_frame, text="Start Collection", command=self.start_collection)
        self.start_button.pack(fill="x", pady=(0, 7))
        self.report_button = ttk.Button(button_frame, text="Open Last Report", command=self.open_last_report)
        self.report_button.pack(fill="x", pady=(0, 7))
        self.case_button = ttk.Button(button_frame, text="Open Case Folder", command=self.open_case_folder)
        self.case_button.pack(fill="x", pady=(0, 7))
        self.regen_button = ttk.Button(button_frame, text="Regenerate Report", command=self.regenerate_report)
        self.regen_button.pack(fill="x", pady=(0, 7))
        self.zip_button = ttk.Button(button_frame, text="Create / Open ZIP Export", command=self.open_zip_export)
        self.zip_button.pack(fill="x")
        controls.columnconfigure(1, weight=1)
        note = tk.Label(body, text="Use only on devices you own or have explicit authorization to examine.",
                        bg="#fff7e6", fg="#513c06", padx=12, pady=8, anchor="w", justify="left")
        note.pack(fill="x", pady=(14, 12))
        search_frame = tk.LabelFrame(body, text="Search Existing Case", bg="white", padx=10, pady=10,
                                      font=("Segoe UI", 10, "bold"))
        search_frame.pack(fill="x", pady=(0, 12))
        ttk.Button(search_frame, text="Select Case", command=self.select_case_folder).pack(side="left", padx=(0, 8))
        tk.Entry(search_frame, textvariable=self.search_keyword, width=42, font=("Segoe UI", 10)).pack(side="left", padx=(0, 8))
        ttk.Button(search_frame, text="Search", command=self.search_case).pack(side="left", padx=(0, 8))
        ttk.Button(search_frame, text="Open Case Folder", command=self.open_case_folder).pack(side="left")
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 10))
        output_frame = tk.LabelFrame(body, text="Tool Output", bg="white", padx=10, pady=10,
                                      font=("Segoe UI", 10, "bold"))
        output_frame.pack(fill="both", expand=True)
        self.output = tk.Text(output_frame, height=18, wrap="word", bg="#0f1720", fg="#e6edf3",
                               insertbackground="#e6edf3", font=("Consolas", 10))
        self.output.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output.yview)
        scrollbar.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=scrollbar.set)
        footer = tk.Frame(self, bg="#e9eef4", padx=14, pady=8)
        footer.pack(fill="x")
        tk.Label(footer, textvariable=self.status, bg="#e9eef4", fg="#202124", font=("Segoe UI", 9)).pack(anchor="w")

    def add_labeled_entry(self, parent, label, variable, row, column, width, padx=(0, 0)):
        tk.Label(parent, text=label, bg="white", font=("Segoe UI", 10)).grid(row=row, column=column, sticky="w", padx=padx)
        tk.Entry(parent, textvariable=variable, width=width, font=("Segoe UI", 10)).grid(
            row=row + 1, column=column, sticky="w", padx=padx, pady=(3, 10))

    def log(self, text):
        self.output.insert("end", text)
        self.output.see("end")

    def drain_output_queue(self):
        try:
            while True:
                self.log(self.output_queue.get_nowait())
        except queue.Empty:
            pass
        self.after(150, self.drain_output_queue)

    def adb_env(self):
        env = os.environ.copy()
        if shutil.which("adb", path=env.get("PATH")):
            return env
        for candidate in [
            Path.home() / "Downloads" / "platform-tools-latest-windows" / "platform-tools",
            Path.home() / "Downloads" / "platform-tools",
            Path("C:/platform-tools"),
        ]:
            if (candidate / "adb.exe").exists():
                env["PATH"] = str(candidate) + os.pathsep + env.get("PATH", "")
                break
        return env

    def adb_command(self):
        env = self.adb_env()
        found = shutil.which("adb", path=env.get("PATH"))
        if found:
            return found
        for c in [
            Path.home() / "Downloads" / "platform-tools-latest-windows" / "platform-tools" / "adb.exe",
            Path.home() / "Downloads" / "platform-tools" / "adb.exe",
            Path("C:/platform-tools/adb.exe"),
        ]:
            if c.exists():
                return str(c)
        return "adb"

    def run_background(self, args, done_message):
        self.set_busy(True)
        self.output_queue.put("\n> " + " ".join(args) + "\n\n")
        def worker():
            try:
                self.process = subprocess.Popen(args, cwd=str(APP_DIR), env=self.adb_env(),
                                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                 text=True, errors="replace")
                for line in self.process.stdout:
                    self.output_queue.put(line)
                    if line.startswith("Open report:"):
                        self.last_report = Path(line.split(":", 1)[1].strip())
                        self.current_case_dir = self.last_report.parent
                    elif "report.html" in line and "updated:" in line:
                        self.last_report = Path(line.split("updated:", 1)[1].strip())
                        self.current_case_dir = self.last_report.parent
                code = self.process.wait()
                self.status.set(done_message if code == 0 else f"Finished with exit code {code}")
                if code == 0 and self.last_report:
                    self.output_queue.put(f"\nReport ready: {self.last_report}\n")
            except Exception as exc:
                self.output_queue.put(f"\nError: {exc}\n")
                self.status.set("Error")
            finally:
                self.process = None
                self.set_busy(False)
        threading.Thread(target=worker, daemon=True).start()

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        for btn in [self.start_button, self.device_button, self.report_button,
                    self.case_button, self.regen_button, self.zip_button]:
            btn.configure(state=state)
        if busy:
            self.status.set("Running...")
            self.progress.start(12)
        else:
            self.progress.stop()

    def check_device(self):
        if self.target_platform.get() == "windows":
            self.run_background(["python", str(WINDOWS_COLLECTOR), "--check"], "Windows check completed")
        else:
            self.run_background([self.adb_command(), "devices", "-l"], "Device check completed")

    def start_collection(self):
        case_id = self.case_id.get().strip()
        if not case_id:
            messagebox.showwarning("Case ID required", "Please enter a Case ID.")
            return
        if self.target_platform.get() == "windows":
            args = ["python", str(WINDOWS_COLLECTOR), "--case-id", case_id]
        else:
            args = ["python", str(COLLECTOR), "--case-id", case_id]
        if self.evidence_id.get().strip():
            args.extend(["--evidence-id", self.evidence_id.get().strip()])
        if self.examiner.get().strip():
            args.extend(["--examiner", self.examiner.get().strip()])
        if self.owner.get().strip():
            args.extend(["--owner", self.owner.get().strip()])
        if self.notes.get().strip():
            args.extend(["--notes", self.notes.get().strip()])
        if self.scan_mode.get() == "media":
            args.append("--pull-media" if self.target_platform.get() == "android" else "--copy-user-media")
        if self.capture_screenshot.get() and self.target_platform.get() == "android":
            args.append("--screenshot")
        if self.collect_personal.get() and self.target_platform.get() == "android":
            args.append("--collect-personal")
        if self.recovery_attempt.get() and self.target_platform.get() == "android":
            args.append("--recovery-attempt")
        self.run_background(args, "Collection completed")

    def open_last_report(self):
        if not self.last_report or not self.last_report.exists():
            messagebox.showinfo("No report yet", "Run a collection first.")
            return
        os.startfile(self.last_report)

    def open_case_folder(self):
        case_dir = self.current_case_dir or (self.last_report.parent if self.last_report else None)
        if not case_dir or not case_dir.exists():
            messagebox.showinfo("No case selected", "Run a collection or select a case folder first.")
            return
        os.startfile(case_dir)

    def open_zip_export(self):
        case_dir = self.current_case_dir or (self.last_report.parent if self.last_report else None)
        if not case_dir or not case_dir.exists():
            messagebox.showinfo("No case selected", "Run a collection or select a case folder first.")
            return
        zips = sorted(case_dir.glob("*_evidence.zip"))
        if zips:
            os.startfile(zips[-1])
            return
        self.run_background(["python", str(COLLECTOR), "--make-zip", str(case_dir)], "ZIP export created")

    def select_case_folder(self):
        selected = filedialog.askdirectory(title="Select forensic case folder")
        if selected:
            self.current_case_dir = Path(selected)
            report = self.current_case_dir / "report.html"
            if report.exists():
                self.last_report = report
            self.status.set(f"Selected case: {self.current_case_dir.name}")
            self.output_queue.put(f"\nSelected case: {self.current_case_dir}\n")

    def regenerate_report(self):
        case_dir = self.current_case_dir or (self.last_report.parent if self.last_report else None)
        if not case_dir or not case_dir.exists():
            messagebox.showinfo("No case selected", "Run a collection or select a case folder first.")
            return
        self.last_report = case_dir / "report.html"
        self.run_background(["python", str(COLLECTOR), "--rewrite-report", str(case_dir)], "Report regenerated")

    def search_case(self):
        case_dir = self.current_case_dir or (self.last_report.parent if self.last_report else None)
        keyword = self.search_keyword.get().strip()
        if not case_dir or not case_dir.exists():
            messagebox.showinfo("No case selected", "Run a collection or select a case folder first.")
            return
        if not keyword:
            messagebox.showinfo("Keyword required", "Enter a keyword to search.")
            return
        matches = []
        for path in case_dir.rglob("*.txt"):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                if keyword.lower() in line.lower():
                    matches.append(f"{path.relative_to(case_dir)}:{i}: {line.strip()}")
                if len(matches) >= 200:
                    break
            if len(matches) >= 200:
                break
        result_path = case_dir / "exports" / "search_results.txt"
        result_path.parent.mkdir(parents=True, exist_ok=True)
        if matches:
            result_path.write_text("\n".join(matches) + "\n", encoding="utf-8")
            self.output_queue.put(f"\nSearch results for '{keyword}' ({len(matches)} shown):\n")
            self.output_queue.put("\n".join(matches[:40]) + "\n")
        else:
            result_path.write_text(f"No matches found for: {keyword}\n", encoding="utf-8")
            self.output_queue.put(f"\nNo matches found for '{keyword}'.\n")


def main() -> int:
    app = ForensicGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
