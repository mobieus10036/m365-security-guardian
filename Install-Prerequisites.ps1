<#
.SYNOPSIS
    Installs required PowerShell modules for M365 Tenant Assessment Toolkit.

.DESCRIPTION
    This script checks for and installs all PowerShell modules required to run
    the Microsoft 365 tenant assessment. It handles both Windows PowerShell 5.1
    and PowerShell 7+ environments.

.PARAMETER Scope
    Specifies the installation scope. Valid values are 'CurrentUser' (default) 
    or 'AllUsers'. AllUsers requires administrative privileges.

.PARAMETER Force
    Forces installation even if modules are already present (useful for updates).

.EXAMPLE
    .\Install-Prerequisites.ps1
    Installs modules for the current user.

.EXAMPLE
    .\Install-Prerequisites.ps1 -Scope AllUsers
    Installs modules for all users (requires admin rights).

.EXAMPLE
    .\Install-Prerequisites.ps1 -Force
    Reinstalls/updates all modules.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
    Requires: PowerShell 5.1 or later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Required modules with minimum versions
$requiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Users'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Groups'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Reports'; MinVersion = '2.0.0' }
    @{ Name = 'ExchangeOnlineManagement'; MinVersion = '3.0.0' }
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    # Using Write-Information for better pipeline compatibility
    Write-Information $Message -InformationAction Continue
}

function Test-AdminPrivileges {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # PowerShell 7+
        if ($IsWindows) {
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        return $true # Non-Windows systems
    }
    else {
        # Windows PowerShell 5.1
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

# Banner
Write-ColorOutput "`n╔════════════════════════════════════════════════════════════╗" -Color Cyan
Write-ColorOutput "║   M365 Tenant Assessment Toolkit - Prerequisites Setup    ║" -Color Cyan
Write-ColorOutput "╚════════════════════════════════════════════════════════════╝`n" -Color Cyan

# Check PowerShell version
Write-ColorOutput "Checking PowerShell version..." -Color Yellow
$psVersion = $PSVersionTable.PSVersion
Write-ColorOutput "  ✓ PowerShell $($psVersion.Major).$($psVersion.Minor).$($psVersion.Patch)" -Color Green

if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
    Write-ColorOutput "`n  ✗ ERROR: PowerShell 5.1 or later is required!" -Color Red
    Write-ColorOutput "    Please upgrade PowerShell: https://aka.ms/powershell" -Color Red
    exit 1
}

# Check admin privileges if AllUsers scope
if ($Scope -eq 'AllUsers') {
    if (-not (Test-AdminPrivileges)) {
        Write-ColorOutput "`n  ✗ ERROR: AllUsers scope requires administrative privileges!" -Color Red
        Write-ColorOutput "    Run PowerShell as Administrator or use -Scope CurrentUser" -Color Red
        exit 1
    }
}

# Set TLS 1.2 for secure downloads
Write-ColorOutput "`nConfiguring secure connection..." -Color Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-ColorOutput "  ✓ TLS 1.2 enabled" -Color Green

# Check for PowerShellGet and update if needed
Write-ColorOutput "`nChecking PowerShellGet module..." -Color Yellow
$psGet = Get-Module -Name PowerShellGet -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

if ($null -eq $psGet -or $psGet.Version -lt [Version]'2.2.5') {
    Write-ColorOutput "  → Updating PowerShellGet to latest version..." -Color Yellow
    try {
        Install-Module -Name PowerShellGet -Force -Scope $Scope -AllowClobber -ErrorAction Stop
        Write-ColorOutput "  ✓ PowerShellGet updated successfully" -Color Green
        Write-ColorOutput "`n  ⚠ IMPORTANT: Please restart PowerShell and run this script again!" -Color Magenta
        exit 0
    }
    catch {
        Write-ColorOutput "  ✗ Failed to update PowerShellGet: $_" -Color Red
        exit 1
    }
}
else {
    Write-ColorOutput "  ✓ PowerShellGet $($psGet.Version) is installed" -Color Green
}

# Install/Update required modules
Write-ColorOutput "`nInstalling required modules..." -Color Yellow
Write-ColorOutput "  Installation scope: $Scope`n" -Color Cyan

$installCount = 0
$updateCount = 0
$skipCount = 0

foreach ($module in $requiredModules) {
    $moduleName = $module.Name
    $minVersion = [Version]$module.MinVersion

    Write-ColorOutput "Checking $moduleName..." -Color White

    # Check if module is already installed
    $installedModule = Get-Module -Name $moduleName -ListAvailable | 
                       Sort-Object Version -Descending | 
                       Select-Object -First 1

    if ($null -eq $installedModule) {
        # Module not installed
        Write-ColorOutput "  → Installing $moduleName (minimum version: $minVersion)..." -Color Yellow
        try {
            Install-Module -Name $moduleName -Scope $Scope -Force -AllowClobber -ErrorAction Stop
            Write-ColorOutput "  ✓ Successfully installed $moduleName" -Color Green
            $installCount++
        }
        catch {
            Write-ColorOutput "  ✗ Failed to install $moduleName : $_" -Color Red
        }
    }
    elseif ($installedModule.Version -lt $minVersion -or $Force) {
        # Module needs update or Force flag is set
        Write-ColorOutput "  → Updating $moduleName from $($installedModule.Version) to latest..." -Color Yellow
        try {
            Update-Module -Name $moduleName -Force -ErrorAction Stop
            Write-ColorOutput "  ✓ Successfully updated $moduleName" -Color Green
            $updateCount++
        }
        catch {
            Write-ColorOutput "  ⚠ Failed to update $moduleName : $_" -Color Magenta
            Write-ColorOutput "    Attempting fresh install..." -Color Yellow
            try {
                Install-Module -Name $moduleName -Scope $Scope -Force -AllowClobber -ErrorAction Stop
                Write-ColorOutput "  ✓ Successfully installed $moduleName" -Color Green
                $installCount++
            }
            catch {
                Write-ColorOutput "  ✗ Failed to install $moduleName : $_" -Color Red
            }
        }
    }
    else {
        # Module is up to date
        Write-ColorOutput "  ✓ $moduleName $($installedModule.Version) is already installed" -Color Green
        $skipCount++
    }
}

# Summary
Write-ColorOutput "`n╔════════════════════════════════════════════════════════════╗" -Color Cyan
Write-ColorOutput "║                    Installation Summary                    ║" -Color Cyan
Write-ColorOutput "╚════════════════════════════════════════════════════════════╝" -Color Cyan
Write-ColorOutput "  Newly installed: $installCount" -Color Green
Write-ColorOutput "  Updated: $updateCount" -Color Yellow
Write-ColorOutput "  Already current: $skipCount" -Color Cyan
Write-ColorOutput "  Total modules: $($requiredModules.Count)`n" -Color White

# Verify all modules are available
Write-ColorOutput "Verifying module availability..." -Color Yellow
$allModulesOk = $true

foreach ($module in $requiredModules) {
    $check = Get-Module -Name $module.Name -ListAvailable
    if ($null -eq $check) {
        Write-ColorOutput "  ✗ $($module.Name) is NOT available!" -Color Red
        $allModulesOk = $false
    }
}

if ($allModulesOk) {
    Write-ColorOutput "  ✓ All required modules are available!`n" -Color Green
    Write-ColorOutput "╔════════════════════════════════════════════════════════════╗" -Color Green
    Write-ColorOutput "║                   Setup Complete! ✓                        ║" -Color Green
    Write-ColorOutput "╚════════════════════════════════════════════════════════════╝" -Color Green
    Write-ColorOutput "`nYou can now run the assessment:" -Color White
    Write-ColorOutput "  .\Start-M365Assessment.ps1`n" -Color Cyan
}
else {
    Write-ColorOutput "`n  ✗ Some modules failed to install. Please review errors above." -Color Red
    Write-ColorOutput "    Try running as Administrator or check network connectivity.`n" -Color Red
    exit 1
}
