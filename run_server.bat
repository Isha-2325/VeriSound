@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

echo ========================================================
echo Starting Audio Forensic Suite Server...
echo Project Directory: %~dp0
echo Access URL: http://127.0.0.1:8000
echo ========================================================

".\venv\Scripts\python.exe" run.py
pause
