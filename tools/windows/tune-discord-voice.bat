@echo off
setlocal
chcp 65001 >nul
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3 not found in PATH.
  pause
  exit /b 1
)

set /p "CLIENT_IP=LAN IPv4 of this PC (example 192.168.2.147): "
if "%CLIENT_IP%"=="" (
  echo Client IP is required.
  pause
  exit /b 2
)

python "%~dp0zapret_tuner.py" discord-voice ^
  --router 192.168.2.1 ^
  --user root ^
  --client-ip "%CLIENT_IP%" ^
  --voice-duration 25 ^
  --mix-level extended ^
  --max-candidates 16 ^
  --report "%~dp0reports\discord-voice-latest.json" ^
  %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
