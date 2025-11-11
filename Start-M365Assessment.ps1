<#
.SYNOPSIS
    Main orchestrator for Microsoft 365 Tenant Assessment Toolkit.

.DESCRIPTION
    Executes comprehensive security, compliance, and configuration assessments
    across your Microsoft 365 tenant. Generates detailed reports in multiple formats
    with remediation guidance based on Microsoft best practices.

.PARAMETER Modules
    Specifies which assessment modules to run. Valid values:
    - Security (MFA, Conditional Access, Privileged Accounts)
    - Compliance (DLP, Retention, Sensitivity Labels) [Disabled in v3.0]
    - Exchange (Email security, SPF/DKIM/DMARC)
    - Licensing (License optimization)
    - All (default - runs all modules)

.PARAMETER OutputFormat
    Specifies report output format. Valid values:
    - All (default - generates HTML, JSON, and CSV)
    - HTML
    - JSON
    - CSV

.PARAMETER OutputPath
    Specifies the folder path for generated reports. 
    Default: .\reports\

.PARAMETER ConfigPath
    Path to custom configuration file.
    Default: .\config\assessment-config.json

.PARAMETER TenantId
    Optionally specify the tenant ID to assess.
    If not provided, will use the authenticated user's tenant.

.PARAMETER NoAuth
    Skip authentication (useful if already connected in the same session).

.EXAMPLE
    .\Start-M365Assessment.ps1
    Runs full assessment with default settings.

.EXAMPLE
    .\Start-M365Assessment.ps1 -Modules Security,Exchange -OutputFormat HTML
    Runs only Security and Exchange assessments, outputs HTML only.

.EXAMPLE
    .\Start-M365Assessment.ps1 -OutputPath C:\Reports\
    Runs full assessment with custom output location.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/M365Assessment
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
    Requires: PowerShell 5.1+, Microsoft Graph, Exchange Online modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'Security', 'Exchange', 'Licensing')]
    [string[]]$Modules = @('All'),

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'HTML', 'JSON', 'CSV')]
    [string]$OutputFormat = 'All',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'reports'),

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\assessment-config.json'),

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$NoAuth
)

#Requires -Version 5.1

# Script variables
$script:StartTime = Get-Date
$script:AssessmentResults = @()
$script:Config = $null
$script:TenantInfo = $null

#region Helper Functions

function Write-Banner {
    $banner = @"

╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║          Microsoft 365 Tenant Assessment Toolkit v3.0.0              ║
║                                                                      ║
║          Comprehensive Security & Best Practice Assessment           ║
║                    Created with GitHub Copilot                       ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

"@
    Write-Information $banner -InformationAction Continue
}

function Write-Step {
    param([string]$Message)
    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Information "`n[$timestamp] $Message" -InformationAction Continue
}

function Write-Success {
    param([string]$Message)
    Write-Information "  ✓ $Message" -InformationAction Continue
}

function Write-Failure {
    param([string]$Message)
    Write-Warning "  ✗ $Message"
}

function Write-Info {
    param([string]$Message)
    Write-Information "  ℹ $Message" -InformationAction Continue
}

function Load-Configuration {
    Write-Step "Loading configuration..."
    
    if (Test-Path $ConfigPath) {
        try {
            $script:Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            Write-Success "Configuration loaded from: $ConfigPath"
        }
        catch {
            Write-Failure "Failed to load configuration: $_"
            Write-Info "Using default configuration"
            $script:Config = Get-DefaultConfiguration
        }
    }
    else {
        Write-Info "Config file not found, using defaults"
        $script:Config = Get-DefaultConfiguration
    }
}

function Get-DefaultConfiguration {
    return [PSCustomObject]@{
        Security = @{
            MFAEnforcementThreshold = 95
            PrivilegedAccountMFARequired = $true
            LegacyAuthAllowed = $false
            MinConditionalAccessPolicies = 1
        }
        Compliance = @{
            DLPPoliciesRequired = $true
            RetentionPoliciesRequired = $true
            SensitivityLabelsRequired = $true
        }
        Exchange = @{
            SPFRecordRequired = $true
            DKIMEnabled = $true
            DMARCPolicyRequired = $true
            MailboxAuditingEnabled = $true
        }
        Licensing = @{
            InactiveDaysThreshold = 90
            MinimumLicenseUtilization = 85
        }
    }
}

function Connect-M365Services {
    if ($NoAuth) {
        Write-Step "Skipping authentication (NoAuth specified)"
        return
    }

    Write-Step "Connecting to Microsoft 365 services..."

    # Microsoft Graph
    try {
        Write-Information "  → Connecting to Microsoft Graph..." -InformationAction Continue
        $graphScopes = @(
            'User.Read.All',
            'Directory.Read.All',
            'Policy.Read.All',
            'Organization.Read.All',
            'AuditLog.Read.All',
            'UserAuthenticationMethod.Read.All'
        )
        
        if ($TenantId) {
            Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        }
        
        Write-Success "Connected to Microsoft Graph"
        
        # Get tenant info
        $script:TenantInfo = Get-MgOrganization
        Write-Info "Tenant: $($script:TenantInfo.DisplayName)"
        
    }
    catch {
        Write-Failure "Failed to connect to Microsoft Graph: $_"
        throw
    }

    # Exchange Online (optional - some checks)
    try {
        Write-Information "  → Connecting to Exchange Online..." -InformationAction Continue
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Success "Connected to Exchange Online"
    }
    catch {
        Write-Failure "Failed to connect to Exchange Online: $_"
        Write-Info "Some Exchange checks may be skipped"
    }
}

function Get-ModulesToRun {
    if ($Modules -contains 'All') {
        return @('Security', 'Exchange', 'Licensing')
    }
    return $Modules
}function Invoke-AssessmentModules {
    $modulesToRun = Get-ModulesToRun
    
    Write-Step "Running assessment modules: $($modulesToRun -join ', ')"
    
    $moduleScripts = @{
        'Security' = @(
            'Security\Test-MFAConfiguration.ps1',
            'Security\Test-ConditionalAccess.ps1',
            'Security\Test-PrivilegedAccounts.ps1',
            'Security\Test-LegacyAuth.ps1'
        )
        'Exchange' = @(
            'Exchange\Test-EmailSecurity.ps1',
            'Exchange\Test-SPFDKIMDmarc.ps1',
            'Exchange\Test-MailboxAuditing.ps1'
        )
        'Licensing' = @(
            'Licensing\Test-LicenseOptimization.ps1'
        )
    }

    foreach ($module in $modulesToRun) {
        $separator = "─" * (50 - $module.Length)
        Write-Information "`n  ┌─ $module Assessment $separator" -InformationAction Continue

        if ($moduleScripts.ContainsKey($module)) {
            foreach ($scriptFile in $moduleScripts[$module]) {
                $scriptPath = Join-Path $PSScriptRoot "modules\$scriptFile"
                
                if (Test-Path $scriptPath) {
                    try {
                        $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)
                        Write-Information "    → Running $scriptName..." -InformationAction Continue
                        . $scriptPath
                        $functionName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)
                        $result = & $functionName -Config $script:Config
                        $script:AssessmentResults += $result
                        
                        # Display result
                        $statusMessage = "      [$($result.Status)] $($result.Message)"
                        if ($result.Status -eq 'Fail') {
                            Write-Warning $statusMessage
                        } else {
                            Write-Information $statusMessage -InformationAction Continue
                        }
                    }
                    catch {
                        Write-Failure "Error running $scriptFile : $_"
                    }
                }
            }
        }
        
        Write-Information "  $('─' * 67)" -InformationAction Continue
    }
}

function Export-Results {
    Write-Step "Generating assessment reports..."

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseFileName = "M365Assessment_$timestamp"

    # JSON Export
    if ($OutputFormat -in @('All', 'JSON')) {
        $jsonPath = Join-Path $OutputPath "$baseFileName.json"
        $script:AssessmentResults | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
        Write-Success "JSON report: $jsonPath"
    }

    # CSV Export
    if ($OutputFormat -in @('All', 'CSV')) {
        $csvPath = Join-Path $OutputPath "$baseFileName.csv"
        $script:AssessmentResults | Select-Object CheckName, Category, Status, Severity, Message, Recommendation | 
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Success "CSV report: $csvPath"
        
        # Export detailed non-compliant mailboxes to separate CSV
        $mailboxAuditResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Mailbox Auditing" -and $_.NonCompliantMailboxes }
        if ($mailboxAuditResult -and $mailboxAuditResult.NonCompliantMailboxes.Count -gt 0) {
            $mailboxCsvPath = Join-Path $OutputPath "$($baseFileName)_NonCompliantMailboxes.csv"
            $mailboxAuditResult.NonCompliantMailboxes | 
                Export-Csv -Path $mailboxCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Non-compliant mailboxes CSV: $mailboxCsvPath"
            Write-Info "  → $($mailboxAuditResult.NonCompliantMailboxes.Count) mailbox(es) without auditing exported"
        }

        # Export inactive mailboxes to separate CSV
        $licenseOptResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "License Optimization" -and $_.InactiveMailboxes }
        if ($licenseOptResult -and $licenseOptResult.InactiveMailboxes.Count -gt 0) {
            $inactiveCsvPath = Join-Path $OutputPath "$($baseFileName)_InactiveMailboxes.csv"
            $licenseOptResult.InactiveMailboxes | 
                Export-Csv -Path $inactiveCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Inactive mailboxes CSV: $inactiveCsvPath"
            Write-Info "  → $($licenseOptResult.InactiveMailboxes.Count) inactive licensed user(s) exported"
        }

        # Export domain email authentication details to separate CSV
        $emailAuthResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Email Authentication (SPF/DKIM/DMARC)" -and $_.DomainDetails }
        if ($emailAuthResult -and $emailAuthResult.DomainDetails.Count -gt 0) {
            $domainsCsvPath = Join-Path $OutputPath "$($baseFileName)_DomainEmailAuth.csv"
            $emailAuthResult.DomainDetails | 
                Export-Csv -Path $domainsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Domain email authentication CSV: $domainsCsvPath"
            Write-Info "  → $($emailAuthResult.DomainDetails.Count) domain(s) with SPF/DKIM/DMARC details exported"
        }

        # Export privileged accounts to separate CSV
        $privAccountResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Privileged Account Security" -and $_.PrivilegedAccounts }
        if ($privAccountResult -and $privAccountResult.PrivilegedAccounts.Count -gt 0) {
            $privAccountsCsvPath = Join-Path $OutputPath "$($baseFileName)_PrivilegedAccounts.csv"
            # Flatten the roles array for CSV export
            $privAccountResult.PrivilegedAccounts | Select-Object UserPrincipalName, @{Name='Roles';Expression={$_.Roles -join '; '}}, @{Name='HasMFA';Expression={if($_.HasMFA){'Yes'}else{'No'}}} | 
                Export-Csv -Path $privAccountsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Privileged accounts CSV: $privAccountsCsvPath"
            Write-Info "  → $($privAccountResult.PrivilegedAccounts.Count) privileged account(s) exported"
        }

        # Export enabled Conditional Access policies to separate CSV
        $caResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Conditional Access Policies" -and $_.EnabledPolicies }
        if ($caResult -and $caResult.EnabledPolicies.Count -gt 0) {
            $caPoliciesCsvPath = Join-Path $OutputPath "$($baseFileName)_ConditionalAccessPolicies.csv"
            $caResult.EnabledPolicies | Select-Object DisplayName, State, Id | 
                Export-Csv -Path $caPoliciesCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Conditional Access policies CSV: $caPoliciesCsvPath"
            Write-Info "  → $($caResult.EnabledPolicies.Count) policy/policies exported"
        }

        # Export users without MFA to separate CSV
        $mfaResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "MFA Enforcement" -and $_.UsersWithoutMFA }
        if ($mfaResult -and $mfaResult.UsersWithoutMFA.Count -gt 0) {
            $usersWithoutMFACsvPath = Join-Path $OutputPath "$($baseFileName)_UsersWithoutMFA.csv"
            $mfaResult.UsersWithoutMFA | 
                Export-Csv -Path $usersWithoutMFACsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Users without MFA CSV: $usersWithoutMFACsvPath"
            Write-Info "  → $($mfaResult.UsersWithoutMFA.Count) user(s) without MFA exported"
        }
    }

    # HTML Export
    if ($OutputFormat -in @('All', 'HTML')) {
        $htmlPath = Join-Path $OutputPath "$baseFileName.html"
        Export-HTMLReport -Results $script:AssessmentResults -OutputPath $htmlPath
        Write-Success "HTML report: $htmlPath"
    }
}

function Export-HTMLReport {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $html = Get-HTMLTemplate
    
    # Calculate statistics
    $totalChecks = $Results.Count
    $passCount = ($Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = ($Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = ($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $infoCount = ($Results | Where-Object { $_.Status -eq 'Info' }).Count
    $passPercentage = if ($totalChecks -gt 0) { [math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }

    # Build results table
    $resultsHtml = ""
    foreach ($result in $Results) {
        $statusClass = $result.Status.ToLower()
        $severityClass = $result.Severity.ToLower()
        
        # Check for detailed non-compliant mailboxes
        $detailsCell = $result.Message
        
        # Handle inactive mailboxes from License Optimization
        if ($result.InactiveMailboxes -and $result.InactiveMailboxes.Count -gt 0) {
            $detailsCell += "<br><br><strong>⚠️ Inactive Licensed Users ($($result.InactiveMailboxes.Count)):</strong><br>"
            $detailsCell += "<ul style='margin-top: 5px; padding-left: 20px; font-size: 0.9em;'>"
            $displayCount = [Math]::Min(20, $result.InactiveMailboxes.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $mailbox = $result.InactiveMailboxes[$i]
                $lastSignIn = if ($mailbox.LastSignInDate -eq 'Never') { 
                    '<span style="color: #d13438; font-weight: bold;">Never</span>' 
                } else { 
                    $mailbox.LastSignInDate 
                }
                $detailsCell += "<li><code>$($mailbox.UserPrincipalName)</code> - $($mailbox.DisplayName) | Last: $lastSignIn ($($mailbox.DaysSinceLastSignIn) days ago)</li>"
            }
            if ($result.InactiveMailboxes.Count -gt 20) {
                $detailsCell += "<li><em>...and $($result.InactiveMailboxes.Count - 20) more users (see CSV export)</em></li>"
            }
            $detailsCell += "</ul>"
        }
        
        # Handle non-compliant mailboxes from Mailbox Auditing
        if ($result.NonCompliantMailboxes -and $result.NonCompliantMailboxes.Count -gt 0) {
            $detailsCell += "<br><br><strong>🚨 Non-Compliant Mailboxes ($($result.NonCompliantMailboxes.Count)):</strong><br>"
            $detailsCell += "<ul style='margin-top: 5px; padding-left: 20px; font-size: 0.9em;'>"
            $displayCount = [Math]::Min(20, $result.NonCompliantMailboxes.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $mailbox = $result.NonCompliantMailboxes[$i]
                $detailsCell += "<li><code>$($mailbox.UserPrincipalName)</code> - $($mailbox.DisplayName)</li>"
            }
            if ($result.NonCompliantMailboxes.Count -gt 20) {
                $detailsCell += "<li><em>...and $($result.NonCompliantMailboxes.Count - 20) more mailboxes (see CSV export)</em></li>"
            }
            $detailsCell += "</ul>"
        }
        
        # Handle domain details from Email Authentication
        if ($result.DomainDetails -and $result.DomainDetails.Count -gt 0) {
            $detailsCell += "<br><br><strong>📧 Domain Email Authentication Details:</strong><br>"
            $detailsCell += "<table style='width: 100%; margin-top: 5px; font-size: 0.85em; border-collapse: collapse;'>"
            $detailsCell += "<tr style='background: #f0f0f0; font-weight: bold;'><td style='padding: 5px; border: 1px solid #ddd;'>Domain</td><td style='padding: 5px; border: 1px solid #ddd;'>SPF</td><td style='padding: 5px; border: 1px solid #ddd;'>DKIM</td><td style='padding: 5px; border: 1px solid #ddd;'>DMARC</td></tr>"
            foreach ($domain in $result.DomainDetails) {
                $spfIcon = switch -Regex ($domain.SPF) {
                    "^Valid" { "✅" }
                    "^Missing" { "❌" }
                    "^Invalid" { "⚠️" }
                    default { "❓" }
                }
                $dkimIcon = if ($domain.DKIM -eq "Enabled") { "✅" } else { "❌" }
                $dmarcIcon = switch -Regex ($domain.DMARC) {
                    "^Valid" { "✅" }
                    "^Missing" { "❌" }
                    "^Weak" { "⚠️" }
                    default { "❓" }
                }
                $detailsCell += "<tr><td style='padding: 5px; border: 1px solid #ddd;'><code>$($domain.Domain)</code></td>"
                $detailsCell += "<td style='padding: 5px; border: 1px solid #ddd;'>$spfIcon $($domain.SPF)</td>"
                $detailsCell += "<td style='padding: 5px; border: 1px solid #ddd;'>$dkimIcon $($domain.DKIM)</td>"
                $detailsCell += "<td style='padding: 5px; border: 1px solid #ddd;'>$dmarcIcon $($domain.DMARC)</td></tr>"
            }
            $detailsCell += "</table>"
        }
        
        # Handle enabled Conditional Access policies
        if ($result.EnabledPolicies -and $result.EnabledPolicies.Count -gt 0) {
            $detailsCell += "<br><br><strong>✅ Enabled Conditional Access Policies ($($result.EnabledPolicies.Count)):</strong><br>"
            $detailsCell += "<ul style='margin-top: 5px; padding-left: 20px; font-size: 0.9em;'>"
            foreach ($policy in $result.EnabledPolicies) {
                $detailsCell += "<li><code>$($policy.DisplayName)</code>"
                if ($policy.State) {
                    $stateColor = if ($policy.State -eq 'enabled') { '#107c10' } else { '#ff8c00' }
                    $detailsCell += " - <span style='color: $stateColor; font-weight: bold;'>$($policy.State)</span>"
                }
                $detailsCell += "</li>"
            }
            $detailsCell += "</ul>"
        }
        
        # Handle privileged accounts from Privileged Account Security
        if ($result.PrivilegedAccounts -and $result.PrivilegedAccounts.Count -gt 0) {
            $detailsCell += "<br><br><strong>👤 Privileged Accounts ($($result.PrivilegedAccounts.Count)):</strong><br>"
            $detailsCell += "<table style='width: 100%; margin-top: 5px; font-size: 0.85em; border-collapse: collapse;'>"
            $detailsCell += "<tr style='background: #f0f0f0; font-weight: bold;'><td style='padding: 5px; border: 1px solid #ddd;'>User Principal Name</td><td style='padding: 5px; border: 1px solid #ddd;'>Roles</td><td style='padding: 5px; border: 1px solid #ddd;'>MFA Status</td></tr>"
            foreach ($account in $result.PrivilegedAccounts) {
                $mfaIcon = if ($account.HasMFA) { "✅ Enabled" } else { "❌ Not Enabled" }
                $mfaColor = if ($account.HasMFA) { '#107c10' } else { '#d13438' }
                $rolesDisplay = ($account.Roles | ForEach-Object { $_ }) -join ', '
                $detailsCell += "<tr><td style='padding: 5px; border: 1px solid #ddd;'><code>$($account.UserPrincipalName)</code></td>"
                $detailsCell += "<td style='padding: 5px; border: 1px solid #ddd; font-size: 0.8em;'>$rolesDisplay</td>"
                $detailsCell += "<td style='padding: 5px; border: 1px solid #ddd; color: $mfaColor; font-weight: bold;'>$mfaIcon</td></tr>"
            }
            $detailsCell += "</table>"
        }
        
        $resultsHtml += @"
        <tr class="$statusClass">
            <td>$($result.CheckName)</td>
            <td><span class="category">$($result.Category)</span></td>
            <td><span class="status status-$statusClass">$($result.Status)</span></td>
            <td><span class="severity severity-$severityClass">$($result.Severity)</span></td>
            <td>$detailsCell</td>
            <td>$($result.Recommendation)</td>
            <td><a href="$($result.DocumentationUrl)" target="_blank">📘 Docs</a></td>
        </tr>
"@
    }

    # Replace placeholders
    $tenantName = if ($script:TenantInfo) { $script:TenantInfo.DisplayName } else { "Not Connected" }
    
    $html = $html -replace '{{TENANT_NAME}}', $tenantName
    $html = $html -replace '{{ASSESSMENT_DATE}}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $html = $html -replace '{{TOTAL_CHECKS}}', $totalChecks
    $html = $html -replace '{{PASS_COUNT}}', $passCount
    $html = $html -replace '{{FAIL_COUNT}}', $failCount
    $html = $html -replace '{{WARN_COUNT}}', $warnCount
    $html = $html -replace '{{INFO_COUNT}}', $infoCount
    $html = $html -replace '{{PASS_PERCENTAGE}}', $passPercentage
    $html = $html -replace '{{RESULTS_TABLE}}', $resultsHtml

    $html | Out-File $OutputPath -Encoding UTF8
}

function Get-HTMLTemplate {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Assessment Report - {{TENANT_NAME}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; }
        .header { background: linear-gradient(135deg, #0078d4 0%, #00bcf2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #fafafa; }
        .summary-card { background: white; padding: 20px; border-radius: 6px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .summary-card h3 { color: #666; font-size: 14px; margin-bottom: 10px; }
        .summary-card .number { font-size: 36px; font-weight: bold; }
        .summary-card.pass .number { color: #107c10; }
        .summary-card.fail .number { color: #d13438; }
        .summary-card.warn .number { color: #ff8c00; }
        .summary-card.info .number { color: #0078d4; }
        .results { padding: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #f0f0f0; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #ddd; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .status { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; }
        .status-pass { background: #dff6dd; color: #107c10; }
        .status-fail { background: #fde7e9; color: #d13438; }
        .status-warning { background: #fff4ce; color: #ff8c00; }
        .status-info { background: #e1f5fe; color: #0078d4; }
        .severity { padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        .severity-critical { background: #d13438; color: white; }
        .severity-high { background: #ff8c00; color: white; }
        .severity-medium { background: #ffd700; color: #333; }
        .severity-low { background: #90ee90; color: #333; }
        .severity-info { background: #e1f5fe; color: #0078d4; }
        .category { background: #0078d4; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        a { color: #0078d4; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; font-size: 0.9em; color: #d13438; }
        ul { margin: 0; }
        ul li { margin: 3px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Microsoft 365 Tenant Assessment Report</h1>
            <p><strong>Tenant:</strong> {{TENANT_NAME}} | <strong>Assessment Date:</strong> {{ASSESSMENT_DATE}}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Checks</h3>
                <div class="number">{{TOTAL_CHECKS}}</div>
            </div>
            <div class="summary-card pass">
                <h3>Passed</h3>
                <div class="number">{{PASS_COUNT}}</div>
            </div>
            <div class="summary-card fail">
                <h3>Failed</h3>
                <div class="number">{{FAIL_COUNT}}</div>
            </div>
            <div class="summary-card warn">
                <h3>Warnings</h3>
                <div class="number">{{WARN_COUNT}}</div>
            </div>
            <div class="summary-card info">
                <h3>Informational</h3>
                <div class="number">{{INFO_COUNT}}</div>
            </div>
            <div class="summary-card">
                <h3>Compliance Score</h3>
                <div class="number" style="color: #0078d4;">{{PASS_PERCENTAGE}}%</div>
            </div>
        </div>
        
        <div class="results">
            <h2>Assessment Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Check Name</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Recommendation</th>
                        <th>Docs</th>
                    </tr>
                </thead>
                <tbody>
                    {{RESULTS_TABLE}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
'@
}

function Disconnect-M365Services {
    Write-Step "Disconnecting from Microsoft 365 services..."
    
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Success "Disconnected from all services"
    }
    catch {
        # Silently continue if disconnect fails
    }
}

function Show-Summary {
    $duration = (Get-Date) - $script:StartTime
    
    $summary = @"

╔══════════════════════════════════════════════════════════════════════╗
║                    Assessment Complete! ✓                            ║
╚══════════════════════════════════════════════════════════════════════╝

Execution Time: $($duration.Minutes)m $($duration.Seconds)s
Total Checks: $($script:AssessmentResults.Count)

"@
    Write-Information $summary -InformationAction Continue
}

#endregion

#region Main Execution

try {
    Write-Banner
    Load-Configuration
    Connect-M365Services
    Invoke-AssessmentModules
    Export-Results
    Show-Summary
}
catch {
    Write-Error "`n✗ FATAL ERROR: Unable to complete assessment"
    Write-Error "Error Details: $($_.Exception.Message)"
    Write-Verbose $_.ScriptStackTrace
    Write-Information "`nFor troubleshooting help, visit: https://github.com/mobieus10036/M365Assessment/issues" -InformationAction Continue
    exit 1
}
finally {
    Disconnect-M365Services
}

#endregion
