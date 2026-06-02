@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ======================================================
echo   Malware Unified Analyzer - Deploy (Windows)
echo ======================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "IMAGES_DIR=%SCRIPT_DIR%\images"

where docker >nul 2>&1
if errorlevel 1 (
  echo [!] ERROR: docker not found.
  exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
  echo [!] ERROR: Docker Desktop not running.
  exit /b 1
)

echo [Step 1/3] Loading images...
for %%f in ("%IMAGES_DIR%\*.tar.gz") do (
  echo   Loading: %%~nxf...
  docker load -i "%%f"
)
for %%f in ("%IMAGES_DIR%\*.tar") do (
  echo   Loading: %%~nxf...
  docker load -i "%%f"
)

echo [Step 2/3] Creating directories...
mkdir "%SCRIPT_DIR%\samples" 2>nul
mkdir "%SCRIPT_DIR%\results\surface" 2>nul
mkdir "%SCRIPT_DIR%\results\network" 2>nul
mkdir "%SCRIPT_DIR%\results\static" 2>nul
mkdir "%SCRIPT_DIR%\results\reports" 2>nul

echo [Step 3/3] Writing compose\.env.runtime...
(
  echo PROJECT_ROOT=%SCRIPT_DIR%
  echo SAMPLES_DIR=%SCRIPT_DIR%\samples
  echo RESULTS_DIR=%SCRIPT_DIR%\results
  echo SCRIPTS_DIR=%SCRIPT_DIR%\scripts
  echo RULES_DIR=%SCRIPT_DIR%\rules
  echo CONFIG_DIR=%SCRIPT_DIR%\compose\config
) > "%SCRIPT_DIR%\compose\.env.runtime"

echo.
echo [+] Starting containers with docker-compose.usb.yml...
cd /d "%SCRIPT_DIR%"
docker compose -f docker-compose.usb.yml --env-file compose\.env.runtime up -d

echo.
echo ======================================================
echo [+] Deploy complete.
echo ======================================================
echo   Web UI: http://127.0.0.1:8080
echo   Run analysis: docker exec orchestrator python -m mau.main YOUR_SAMPLE.exe
echo   Results: %SCRIPT_DIR%\results\reports\
echo.
pause
