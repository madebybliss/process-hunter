@echo off
REM Remove Process Hunter from Windows logon startup.

net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

schtasks /Delete /TN "ProcessHunter" /F
if %ERRORLEVEL% neq 0 (
  echo Could not delete task ProcessHunter (it may not exist).
  pause
  exit /b 1
)

echo Startup task removed.
pause
