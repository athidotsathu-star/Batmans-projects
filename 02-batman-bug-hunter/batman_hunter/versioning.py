"""Application version and latest-release metadata."""
from __future__ import annotations
import json, urllib.request
from . import __version__
OWNER="athidotsathu-star"; REPO="Batmans-projects"
def version_info() -> dict:
    return {"name":"Batman Bug Hunter X","version":__version__,"channel":"stable","release_api":f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest",
        "releases_url":f"https://github.com/{OWNER}/{REPO}/releases"}
def check_latest(timeout: int=5) -> dict:
    info=version_info(); req=urllib.request.Request(info["release_api"],headers={"User-Agent":"BatmanBugHunter-VersionCheck/3.0","Accept":"application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as response: release=json.loads(response.read(1_000_000).decode("utf-8"))
        latest=str(release.get("tag_name","")).lstrip("v")
        info.update({"latest_version":latest,"release_url":release.get("html_url",info["releases_url"]),
            "update_available":latest!=__version__ and bool(latest),"status":"checked"})
    except Exception as exc:
        info.update({"status":"offline_or_unavailable","message":type(exc).__name__})
    return info
