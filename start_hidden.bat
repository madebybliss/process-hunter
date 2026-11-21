@echo off
REM Launch Process Hunter with no console window.
REM Used by the logon scheduled task (already elevated) and can be used manually.

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
