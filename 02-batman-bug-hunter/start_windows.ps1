Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python launcher 'py' not found. Install Python 3.10+ and enable PATH."
}
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}
$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt
Write-Host "Starting Batman Bug Hunter at http://127.0.0.1:5000"
& $Python -m batman_hunter.web
