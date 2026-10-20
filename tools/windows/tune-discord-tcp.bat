@echo off
setlocal
chcp 65001 >nul
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3 not found in PATH.
  pause
  exit /b 1
)

python "%~dp0zapret_tuner.py" discord-tcp ^
  --router 192.168.2.1 ^
  --user root ^
  --mix-level extended ^
  --max-candidates 40 ^
  --http-timeout 6 ^
  --report "%~dp0reports\discord-tcp-latest.json" ^
  %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
