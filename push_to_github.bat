@echo off
title Push NetTransfer to GitHub (Kalyan-Reddy-Git)
echo =======================================================
echo   Pushing NetTransfer to https://github.com/Kalyan-Reddy-Git/NetTransfer
echo =======================================================
echo.

git push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Code successfully pushed to GitHub!
    echo Visit: https://github.com/Kalyan-Reddy-Git/NetTransfer
) else (
    echo.
    echo [NOTE] If you saw 'Repository not found', please make sure
    echo you created the repository at: https://github.com/new?name=NetTransfer
)

pause
