@echo off
title PolinRider Malware Scanner

echo ================================================
echo   PolinRider Malware Scanner - Windows Quick Start
echo   https://opensourcemalware.com
echo ================================================
echo.

echo Downloading latest scanner...
powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/branch8/PolinRiderScanner/main/polinrider-scan-local-windows.ps1' -OutFile '%~dp0polinrider-scan-local-windows.ps1' -UseBasicParsing" 2>nul
if errorlevel 1 (
    echo.
    echo ERROR: Download failed. Please check your internet connection and try again.
    echo.
    pause
    exit /b 1
)
echo Download complete.
echo.
echo Starting full system scan. This may take a few minutes...
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0polinrider-scan-local-windows.ps1" -FullSystem

echo.
pause
