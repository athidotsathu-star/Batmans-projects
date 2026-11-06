"""Batman Bug Hunter X updater.

Checks the latest GitHub Release, verifies its SHA-256 checksum, and launches
the per-user Inno Setup installer. All Tk operations run on the UI thread.
"""
from __future__ import annotations

import hashlib
import json
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
APP_ID = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7C69A8A-27A2-4F21-A9A7-8E41E1A4B310}_is1"
INSTALLER_NAME = "BatmanBugHunter-Setup.exe"
CHECKSUM_NAME = "SHA256SUMS.txt"


def version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", value)
    return tuple(int(part) for part in numbers[:4]) if numbers else (0,)


def installed_version() -> str:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_ID) as key:
            value, _ = winreg.QueryValueEx(key, "DisplayVersion")
            return str(value)
    except OSError:
        return "0.0.0"


def request_bytes(url: str, limit: int = 512 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "BatmanBugHunter-Updater/3.2",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("Downloaded file exceeded the allowed size.")
    return data


def find_asset(release: dict, name: str) -> str:
    for asset in release.get("assets", []):
        if asset.get("name") == name and asset.get("browser_download_url"):
            return str(asset["browser_download_url"])
    raise RuntimeError(f"Official release is missing required asset: {name}")


def expected_checksum(checksum_text: str, filename: str) -> str:
    for line in checksum_text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == filename:
            digest = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    raise RuntimeError(f"Valid SHA-256 entry for {filename} was not found.")


class Updater:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Batman Bug Hunter X — Updater")
        root.geometry("470x230")
        root.resizable(False, False)
        self.status = tk.StringVar(value="Ready to check for updates.")
        ttk.Label(root, text="BATMAN BUG HUNTER X", font=("Segoe UI", 16, "bold")).pack(pady=(20, 4))
        ttk.Label(root, text="OFFICIAL RELEASE UPDATER").pack()
        self.progress = ttk.Progressbar(root, mode="indeterminate", length=390)
        self.progress.pack(pady=18)
        ttk.Label(root, textvariable=self.status, wraplength=410).pack(pady=4)
        self.button = ttk.Button(root, text="CHECK FOR UPDATES", command=self.check)
        self.button.pack(pady=12)
        ttk.Label(root, text="Downloads are verified before installation.", foreground="#777").pack()

    def set_busy(self, message: str):
        self.status.set(message)
        self.button.config(state="disabled")
        self.progress.start(12)

    def finish(self, message: str, error: bool = False):
        self.progress.stop()
        self.status.set(message)
        self.button.config(state="normal", text="CLOSE", command=self.root.destroy)
        if error:
            messagebox.showerror("Updater", message)
        else:
            messagebox.showinfo("Updater", message)

    def check(self):
        self.set_busy("Checking official GitHub release…")
        threading.Thread(target=self._check_release, daemon=True).start()

    def _check_release(self):
        try:
            release = json.loads(request_bytes(API, 2 * 1024 * 1024).decode("utf-8"))
            latest = str(release.get("tag_name", "")).strip().lstrip("v")
            if not latest:
                raise RuntimeError("Latest GitHub release has no version tag.")
            current = installed_version()
            if version_tuple(latest) <= version_tuple(current):
                self.root.after(0, self.finish, f"You already have the latest version ({current}).")
                return
            self.root.after(0, self._confirm_update, current, latest, release)
        except Exception as exc:
            self.root.after(0, self.finish, f"Update check failed: {exc}", True)

    def _confirm_update(self, current: str, latest: str, release: dict):
        self.progress.stop()
        self.status.set(f"Version {latest} is available (installed: {current}).")
        accepted = messagebox.askyesno(
            "Update available",
            f"Installed: {current}\nLatest: {latest}\n\nDownload and install the verified update now?",
        )
        if not accepted:
            self.finish("Update cancelled.")
            return
        self.set_busy(f"Downloading version {latest}…")
        threading.Thread(target=self._download_and_install, args=(latest, release), daemon=True).start()

    def _download_and_install(self, latest: str, release: dict):
        try:
            installer_url = find_asset(release, INSTALLER_NAME)
            checksum_url = find_asset(release, CHECKSUM_NAME)
            installer_bytes = request_bytes(installer_url)
            checksum_text = request_bytes(checksum_url, 100_000).decode("utf-8")
            expected = expected_checksum(checksum_text, INSTALLER_NAME)
            actual = hashlib.sha256(installer_bytes).hexdigest()
            if actual != expected:
                raise RuntimeError("Installer SHA-256 verification failed. Installation was blocked.")

            # Keep the temporary installer until its process exits.
            with tempfile.TemporaryDirectory(prefix="BatmanBugHunterUpdate-") as temp_dir:
                installer_path = Path(temp_dir) / INSTALLER_NAME
                installer_path.write_bytes(installer_bytes)
                self.root.after(0, self.status.set, "Checksum verified. Installing update…")
                completed = subprocess.run(
                    [
                        str(installer_path),
                        "/VERYSILENT",
                        "/SUPPRESSMSGBOXES",
                        "/NORESTART",
                        "/CLOSEAPPLICATIONS",
                    ],
                    check=False,
                )
                if completed.returncode != 0:
                    raise RuntimeError(f"Installer exited with code {completed.returncode}.")
            self.root.after(
                0,
                self.finish,
                f"Batman Bug Hunter X {latest} was installed. Launch it from the Start menu.",
            )
        except Exception as exc:
            self.root.after(0, self.finish, f"Update failed: {exc}", True)


def main():
    root = tk.Tk()
    Updater(root)
    root.mainloop()


if __name__ == "__main__":
    main()
