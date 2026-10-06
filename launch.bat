@echo off
REM Peek-a-Boo OSINT Dashboard Launcher
REM Starts the Flask web UI in the background and opens the browser

setlocal
set "REPO_DIR=C:\Users\HarpStar\peek-a-boo"
set "PORT=5000"

echo [*] Checking if peek-a-boo is already running...
netstat -an 2>nul | find "LISTENING" | find ":%PORT%" >nul 2>&1
if %errorlevel%==0 (
    echo [*] Already running on port %PORT%.
    start http://127.0.0.1:%PORT%
    goto :done
)

echo [*] Starting Peek-a-Boo OSINT Dashboard...
cd /d "%REPO_DIR%"

REM Start Flask in background (no terminal window)
start /B "" "%REPO_DIR%\venv\Scripts\pythonw" -c "import sys, os; sys.path.insert(0, '%REPO_DIR%'); from peekaboo.app import app; app.run(host='127.0.0.1', port=%PORT%, debug=False)"

REM Wait for server to be ready
echo [*] Waiting for server...
:waitloop
timeout /t 2 /nobreak >nul
netstat -an 2>nul | find "LISTENING" | find ":%PORT%" >nul 2>&1
if %errorlevel% neq 0 goto waitloop

echo [+] Server is ready on http://127.0.0.1:%PORT%
start http://127.0.0.1:%PORT%

:done
echo.
echo Peek-a-Boo dashboard is running.
echo Close this window to stop the server.
pause