@echo off
echo.
echo   CIPHER - Starting Backend Server
echo   ==================================
echo.
cd /d "%~dp0backend"
python server.py
pause
