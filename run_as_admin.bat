@echo off
REM Auroch launcher. Self-elevates, then runs main.py.
REM Uses python.exe (not pythonw.exe) and pauses on failure, so a first-run
REM error is visible instead of the window vanishing silently.
setlocal
cd /d "%~dp0"

REM --- Already elevated? "net session" only succeeds with admin rights. -----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

REM --- Find Python -----------------------------------------------------------
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)
if not defined PY (
    echo.
    echo Python was not found on PATH.
    echo Install it from https://python.org and tick "Add python.exe to PATH",
    echo or run Auroch from PyCharm instead.
    echo.
    pause
    exit /b 1
)

REM --- Check dependencies ----------------------------------------------------
%PY% -c "import PySide6, psutil" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies, one moment...
    %PY% -m pip install -r "%~dp0requirements.txt"
    if %errorlevel% neq 0 (
        echo.
        echo Dependency install failed. Try manually:  pip install -r requirements.txt
        pause
        exit /b 1
    )
)

REM --- Go --------------------------------------------------------------------
%PY% "%~dp0main.py"
if %errorlevel% neq 0 (
    echo.
    echo Auroch exited with an error ^(code %errorlevel%^).
    pause
)
endlocal
