@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher "py" was not found. Install Python 3.10+ and enable PATH.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto :error
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :error
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :error
echo Starting Batman Bug Hunter at http://127.0.0.1:5000
".venv\Scripts\python.exe" -m batman_hunter.web
goto :eof
:error
echo Setup failed. Check Python 3.10+ and internet access.
pause
exit /b 1
