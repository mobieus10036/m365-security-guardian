@echo off
REM ============================================================================
REM  M365 Security Guardian - Launcher
REM  Double-click this file to run the assessment from any Windows environment.
REM  This handles execution policy and locates PowerShell 7 automatically.
REM ============================================================================

title M365 Security Guardian

REM Set console to UTF-8 for proper Unicode rendering.
chcp 65001 >nul 2>&1

echo.
echo  M365 Security Guardian
echo  ======================
echo.

REM PowerShell 7 (pwsh) is required
where /q pwsh 2>nul
if %ERRORLEVEL% equ 0 (
    echo  Using PowerShell 7+
    echo.
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-M365Assessment.ps1" %*
) else (
    echo  ERROR: PowerShell 7+ is required but 'pwsh' was not found.
    echo.
    echo  Install PowerShell 7:
    echo    winget install Microsoft.PowerShell
    echo    -- or --
    echo    https://aka.ms/powershell
    echo.
    echo  After installing, close this window and try again.
    echo.
    pause
    exit /b 1
)

echo.
echo  Assessment complete. Press any key to close...
pause >nul
