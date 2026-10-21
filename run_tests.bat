@echo off
echo ========================================================
echo Running Audio Forensic Suite Test Suite...
echo ========================================================
cd /d %~dp0
call .\venv\Scripts\activate.bat
python -m pytest -v
pause
