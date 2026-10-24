@echo off
setlocal
cd /d "%~dp0"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title WinAdBlock DNS Sinkhole Server
cls
echo ==============================================================
echo    WinAdBlock - Windows Native 40-bit DNS Sinkhole
echo ==============================================================
echo.
echo [*] Starting WinAdBlock DNS Server...
echo [*] DNS Port: UDP 53 (0.0.0.0)
echo [*] Web Dashboard: http://127.0.0.1:8080
echo [*] Press Ctrl+C in this window to stop.
echo.

"%~dp0win-adblock.exe" -listen 0.0.0.0 -port 53 -web 127.0.0.1:8080 -update-interval 24

if %errorlevel% neq 0 (
    echo.
    echo [!] Server exited with error code: %errorlevel%
    echo [*] If port 53 is occupied by Windows ICS or Hyper-V, you can run:
    echo     win-adblock.exe -listen 127.0.0.1 -port 1053 -web 127.0.0.1:8080
    echo.
    pause
)
