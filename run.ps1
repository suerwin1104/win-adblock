# run.ps1 - WinAdBlock DNS Sinkhole Launcher
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Set-Location $PSScriptRoot

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "   WinAdBlock - Windows Native 40-bit DNS Sinkhole" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Starting WinAdBlock DNS Server..." -ForegroundColor Green
Write-Host "[*] DNS Port: UDP 53" -ForegroundColor Green
Write-Host "[*] Web Dashboard: http://127.0.0.1:8080" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C in this window to stop." -ForegroundColor DarkGray
Write-Host ""

& "$PSScriptRoot\win-adblock.exe" -listen 0.0.0.0 -port 53 -web 127.0.0.1:8080 -update-interval 24
