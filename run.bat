@echo off
title NetTransfer - FTP File Transfer System Launcher
echo =======================================================================
echo          NetTransfer - FTP File Transfer System
echo   Course: Computer Networks and Ethical Hacking Laboratory
echo   Project: Implementation of Application Layer Protocols (FTP RFC 959)
echo =======================================================================
echo.

:: Detect Python
set PYTHON_CMD=python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
        set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    ) else (
        echo [ERROR] Python not found in PATH or standard directory.
        pause
        exit /b 1
    )
)

echo [1/3] Starting Local Demo FTP Server on port 2121 in background...
start "NetTransfer - Demo FTP Server" %PYTHON_CMD% run_demo_ftp_server.py

echo [2/3] Waiting 2 seconds for FTP server initialization...
timeout /t 2 /nobreak >nul

echo [3/3] Starting NetTransfer Flask Web Server...
echo.
echo =======================================================================
echo Web Application will run at: http://127.0.0.1:5000
echo Demo FTP Server runs at:     127.0.0.1:2121
echo =======================================================================
echo.

:: Launch default browser
start http://127.0.0.1:5000

:: Run Flask App
%PYTHON_CMD% app.py

pause
