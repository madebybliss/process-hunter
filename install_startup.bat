@echo off
REM Register Process Hunter to start elevated at user logon (Task Scheduler).
REM Approve the UAC prompt once. After that, logon starts it as Admin with no prompt.

net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
set "LAUNCHER=%~dp0start_hidden.bat"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$action = New-ScheduledTaskAction -Execute '%LAUNCHER%';" ^
  "$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME;" ^
  "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero);" ^
  "$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest;" ^
  "Unregister-ScheduledTask -TaskName 'ProcessHunter' -Confirm:$false -ErrorAction SilentlyContinue;" ^
  "Register-ScheduledTask -TaskName 'ProcessHunter' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null;" ^
  "$t = Get-ScheduledTask -TaskName 'ProcessHunter';" ^
  "Write-Host ('Registered: ' + $t.TaskName + ' | RunLevel=' + $t.Principal.RunLevel + ' | State=' + $t.State)"

if %ERRORLEVEL% neq 0 (
  echo Failed to create scheduled task ProcessHunter.
  pause
  exit /b 1
)

echo.
echo Process Hunter will start at logon as Administrator.
pause
