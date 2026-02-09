@echo off
REM ============================================================================
REM  M365 Security Guardian - Launcher
REM  Double-click this file to run the assessment from any Windows environment.
REM  This handles execution policy and locates PowerShell automatically.
REM ============================================================================

title M365 Security Guardian

echo.
echo  M365 Security Guardian
echo  ======================
echo.

REM Check for PowerShell 7 first, fall back to Windows PowerShell 5.1
where /q pwsh 2>nul
if %ERRORLEVEL% equ 0 (
    echo  Using PowerShell 7+
    echo.
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-M365Assessment.ps1" %*
) else (
    echo  Using Windows PowerShell 5.1
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-M365Assessment.ps1" %*
)

echo.
echo  Assessment complete. Press any key to close...
pause >nul
