@echo off
title CIPHERLINE Local TLS Grader
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_local.ps1"
if errorlevel 1 (
  echo.
  echo Startup failed. Read README.md or run the VS Code task for details.
  pause
)

