"""Batman Bug Hunter X updater.

Checks the latest public GitHub Release, verifies the installer SHA-256,
then runs the Inno Setup installer in upgrade mode.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

OWNER = "athidotsathu-star"
REPO = "Batmans-projects"
API = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
PRODUCT = "Batman Bug Hunter X"
APP_ID = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7C69A8A-27A2-4F21-A9A7-8E41E1A4B310}_is1"

def version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value)
    return tuple(int(x) for x in nums[:4]) if nums else (0,)

def installed_version() -> str:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_ID)
        value, _ = winreg.QueryValueEx(key, "DisplayVersion")
        return str(value)
    except Exception:
        return "0.0.0"

def request_bytes(url: str, limit: int = 512 * 1024 * 1024) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "BatmanBugHunter-Updater/1.0", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("Downloaded file exceeded the allowed size.")
    return data

def find_asset(release: dict, name: str) -> str:
    for asset in release.get("assets", []):
        if asset.get("name") == name and asset.get("browser_download_url"):
            return asset["browser_download_url"]
    raise RuntimeError(f"Release asset is missing: {name}")

class Updater:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Batman Bug Hunter X — Updater")
        root.geometry("470x230")
        root.resizable(False, False)
        self.status = tk.StringVar(value="Ready to check for updates.")
        ttk.Label(root, text="BATMAN BUG HUNTER X", font=("Segoe UI", 16, "bold")).pack(pady=(20, 4))
        ttk.Label(root, text="SECURITY CONSOLE  •  OFFICIAL RELEASE UPDATER").pack()
        self.progress = ttk.Progressbar(root, mode="indeterminate", length=390)
        self.progress.pack(pady=18)
        ttk.Label(root, textvariable=self.status, wraplength=410).pack(pady=4)
        self.button = ttk.Button(root, text="CHECK FOR UPDATES", command=self.start)
        self.button.pack(pady=12)
        ttk.Label(root, text="Downloads are verified before installation.", foreground="#777").pack()

    def set_status(self, text: str):
        self.root.after(0, self.status.set, text)

    def start(self):
        self.button.config(state="disabled")
        self.progress.start(12)
        threading.Thread(target=self.run, daemon=True).start()

    def finish(self, message: str, error: bool = False):
        def done():
            self.progress.stop()
            self.status.set(message)
            self.button.config(state="normal", text="CLOSE")
            self.button.config(command=self.root.destroy)
            if error:
                messagebox.showerror("Updater", message)
            else:
                messagebox.showinfo("Updater", message)
        self.root.after(0, done)

    def run(self):
        try:
            self.set_status("Checking official GitHub release…")
            release = json.loads(request_bytes(API, 2 * 1024 * 1024).decode("utf-8"))
            latest = str(release.get("tag_name", "")).lstrip("v")
            if not latest:
                raise RuntimeError("Latest release has no version tag.")
            current = installed_version()
            if version_tuple(latest) <= version_tuple(current):
                self.finish(f"You already have the latest version ({current}).")
                return
            if not messagebox.askyesno("Update available", f"Installed: {current}\nLatest: {latest}\n\nDownload and install the update now?"):
                self.finish("Update cancelled.")
                return
            self.set_status(f"Downloading version {latest}…")
            setup_url = find_asset(release, "BatmanBugHunter-Setup.exe")
            sums_url = find_asset(release, "SHA256SUMS.txt")
            setup = request_bytes(setup_url)
            sums = request_bytes(sums_url, 100_000).decode("utf-8")
            expected = None
            for line in sums.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[-1].lstrip("*") == "BatmanBugHunter-Setup.exe":
                    expected = parts[0].lower()
                    break
            if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise RuntimeError("Release checksum file is missing or invalid.")
            actual = hashlib.sha256(setup).hexdigest()
            if actual != expected:
                raise RuntimeError("Installer SHA-256 verification failed. Installation was blocked.")
            with tempfile.TemporaryDirectory(prefix="BatmanBugHunterUpdate-") as temp:
                installer = Path(temp) / "BatmanBugHunter-Setup.exe"
                installer.write_bytes(setup)
                self.set_status("Checksum verified. Installing update…")
                result = subprocess.run([str(installer), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"], check=False)
                if result.returncode != 0:
                    raise RuntimeError(f"Installer exited with code {result.returncode}.")
            self.finish(f"Batman Bug Hunter X {latest} was installed. Launch it from your Start menu.")
        except Exception as exc:
            self.finish(f"Update failed: {exc}", error=True)

def main():
    root = tk.Tk()
    Updater(root)
    root.mainloop()

if __name__ == "__main__":
    main()
