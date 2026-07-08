@echo off
setlocal
cd /d "%~dp0"

set PROFILE=%1
if "%PROFILE%"=="" set PROFILE=default

echo === AURORA C2 Teamserver ===
echo   Profile: %PROFILE%
echo.

where python >nul 2>&1
if errorlevel 1 (
    where python3 >nul 2>&1
    if errorlevel 1 (
        echo Python not found. Please install Python 3.
        exit /b 1
    )
    set PY=python3
) else (
    set PY=python
)

if not exist "teamserver\venv\Scripts\python.exe" (
    echo Creating Python venv...
    %PY% -m venv teamserver\venv
    if errorlevel 1 (
        echo Failed to create venv.
        exit /b 1
    )
)

echo Installing dependencies...
teamserver\venv\Scripts\pip install -q --disable-pip-version-check -r teamserver\requirements.txt

echo Starting teamserver with profile '%PROFILE%'...
teamserver\venv\Scripts\python teamserver\server.py -profile "%PROFILE%"
