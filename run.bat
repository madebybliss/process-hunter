@echo off
REM Launch Process Hunter elevated (Administrator), no console window.

net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"

where pyw >nul 2>&1
if %ERRORLEVEL%==0 (
  start "" pyw -3.12 -m process_hunter
  exit /b 0
)

where py >nul 2>&1
if %ERRORLEVEL%==0 (
  start "" py -3.12 -m process_hunter
  exit /b 0
)

where pythonw >nul 2>&1
if %ERRORLEVEL%==0 (
  start "" pythonw -m process_hunter
  exit /b 0
)

start "" python -m process_hunter
