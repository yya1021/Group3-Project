@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo.
echo ============================================================
echo   Group3-Project  -  Week 7 Security Scan
echo   SAST  /  DAST  /  Dependency Scan
echo ============================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js not found in PATH.
  echo         Please install Node.js first: https://nodejs.org
  echo.
  pause
  exit /b 1
)
for /f "delims=" %%v in ('node --version 2^>nul') do echo   Node.js %%v
echo   Working dir: %~dp0
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0security\run-scan.ps1" %*
set "RC=%ERRORLEVEL%"

echo.
echo ------------------------------------------------------------
echo   Reports written to:
echo     %~dp0security\reports\
echo       baseline-report.md      ^<- baseline report
echo       vulnerability-list.md   ^<- vulnerability list
echo       scan-summary.json       ^<- raw summary (JSON)
echo ------------------------------------------------------------
echo.
echo   Press any key to open the reports folder ...
pause >nul
start "" "%~dp0security\reports"

exit /b %RC%
