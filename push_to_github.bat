@echo off
title Push NetTransfer to GitHub (Kalyan-Reddy-Git/FTPServer)
echo =======================================================
echo   Pushing to https://github.com/Kalyan-Reddy-Git/FTPServer
echo =======================================================
echo.

git push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Code successfully pushed to GitHub!
    echo Visit: https://github.com/Kalyan-Reddy-Git/FTPServer
) else (
    echo.
    echo [NOTE] If you saw 'Repository not found', please make sure
    echo the repository exists at: https://github.com/new?name=FTPServer
)

pause
