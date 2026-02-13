# Save this as Get-EnvDiagnostics.ps1 and run on both machines
Write-Host "=== M365 Security Guardian Diagnostics ===" -ForegroundColor Cyan
Write-Host "Generated on: $(Get-Date)" 
Write-Host "Machine Name: $env:COMPUTERNAME"

Write-Host "`n[1] Environment Info" -ForegroundColor Green
$PSVersionTable | Format-List | Out-String | Write-Host
Write-Host "Host Name: $($Host.Name)"
Write-Host "Host Version: $($Host.Version)"
Write-Host "Culture: $((Get-Culture).Name)"
Write-Host "IsAdmin: $([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).Owner -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().User))" # Rough check

Write-Host "`n[2] Console & Encoding" -ForegroundColor Green
try {
    Write-Host "Console Output Encoding: $([Console]::OutputEncoding.EncodingName)"
    Write-Host "Console Input Encoding: $([Console]::InputEncoding.EncodingName)"
} catch {
    Write-Host "Console encoding not accessible: $_" -ForegroundColor Yellow
}
Write-Host "Preference OutputEncoding: $($OutputEncoding.EncodingName)"

if ($Host.UI.RawUI) {
    try {
        Write-Host "Buffer Width: $($Host.UI.RawUI.BufferSize.Width)"
        Write-Host "Window Width: $($Host.UI.RawUI.WindowSize.Width)"
    } catch {
        Write-Host "RawUI properties not accessible" -ForegroundColor Gray
    }
} else {
    Write-Host "RawUI not available"
}

Write-Host "`n[3] Relevant Env Vars" -ForegroundColor Green
Get-ChildItem env: | Where-Object { $_.Name -match '^(AZURE|VSCODE|TERM|WT_|ConEmu|POWERSHELL)' } | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "`n[4] User Settings" -ForegroundColor Green
Write-Host "Execution Policy: $(Get-ExecutionPolicy)"
Write-Host "Profile Path: $PROFILE"
Write-Host "Profile Exists: $(Test-Path $PROFILE)"

Write-Host "`n[5] Module Versions (Top 3)" -ForegroundColor Green
$modules = @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement', 'PSReadLine', 'Pester')
foreach ($m in $modules) {
    $vers = Get-Module $m -ListAvailable | Sort-Object Version -Descending | Select-Object -First 3
    if ($vers) {
        foreach ($v in $vers) {
            Write-Host "$m : $($v.Version) [$($v.Path)]"
        }
    } else {
        Write-Host "$m : NOT INSTALLED" -ForegroundColor Red
    }
}

Write-Host "`n[6] M365 Guardian Specific Checks" -ForegroundColor Green
$guardianRoot = Split-Path -Parent $PSScriptRoot
Write-Host "Guardian Root: $guardianRoot"

# Check for retry module (v3.1.1+)
$retryModulePath = Join-Path $guardianRoot "modules\Core\Invoke-MgGraphWithRetry.ps1"
if (Test-Path $retryModulePath) {
    Write-Host "✓ Graph Retry Module: PRESENT (v3.1.1+ feature)" -ForegroundColor Green
} else {
    Write-Host "✗ Graph Retry Module: MISSING (upgrade to v3.1.1+)" -ForegroundColor Red
    Write-Host "  This may cause PowerShell termination on large tenants" -ForegroundColor Yellow
}

# Check Graph connection if already authenticated
try {
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($context) {
        Write-Host "✓ Graph Connection: ACTIVE" -ForegroundColor Green
        Write-Host "  Tenant: $($context.TenantId)"
        Write-Host "  Account: $($context.Account)"
        Write-Host "  Scopes: $($context.Scopes -join ', ')"
        
        # Test simple query
        Write-Host "  Testing Graph API performance..."
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $userCount = (Get-MgUser -Top 10 -ErrorAction SilentlyContinue | Measure-Object).Count
        $sw.Stop()
        Write-Host "  → Retrieved 10 users in $($sw.ElapsedMilliseconds)ms"
        
        if ($sw.ElapsedMilliseconds -gt 2000) {
            Write-Host "  WARNING: Graph API response is slow (>2s)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "○ Graph Connection: Not authenticated" -ForegroundColor Gray
    }
} catch {
    Write-Host "✗ Graph Connection Error: $_" -ForegroundColor Red
}

Write-Host "`n[6] Authentication Cache Check" -ForegroundColor Green
$cachePath = Join-Path $env:LOCALAPPDATA ".IdentityService"
if (Test-Path $cachePath) {
    Write-Host ".IdentityService exists"
    Get-ChildItem $cachePath | Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host ".IdentityService NOT found" -ForegroundColor Yellow
}

Write-Host "`n=== End Diagnostics ===" -ForegroundColor Cyan