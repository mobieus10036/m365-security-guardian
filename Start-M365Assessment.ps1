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
    Repository: https://github.com/mobieus10036/m365-security-guardian
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

# Import required modules
Write-Verbose "Loading Microsoft Graph modules..."
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
}
catch {
    Write-Error "Failed to load Microsoft Graph modules. Please run .\Install-Prerequisites.ps1"
    Write-Error $_.Exception.Message
    exit 1
}

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
║           Microsoft 365 Assessment Toolkit v3.0.1                    ║
║                                                                      ║
║              Security & Best Practice Assessment                     ║
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

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        HTML-encodes a string to prevent XSS attacks.
    .DESCRIPTION
        Converts special characters to HTML entities to safely display
        user-provided or dynamic content in HTML reports.
    #>
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )
    
    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }
    
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

function Get-AuthRegistrationDetails {
    $cmdOptions = @(
        'Get-MgReportAuthenticationMethodUserRegistrationDetail',
        'Get-MgReportAuthenticationMethodsUserRegistrationDetail',
        'Get-MgReportCredentialUserRegistrationDetail'
    )

    foreach ($cmd in $cmdOptions) {
        $command = Get-Command -Name $cmd -ErrorAction SilentlyContinue
        if ($command) {
            return & $cmd -All -ErrorAction Stop
        }
    }

    throw "Authentication registration detail cmdlet not available. Install or update Microsoft.Graph.Reports."
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
            MaxPrivilegedAccounts = 3
            LegacyAuthAllowed = $false
            MinConditionalAccessPolicies = 1
            ReportOnlyStaleDays = 30
            LongStaleReportOnlyDays = 90
            MaxConditionalAccessExclusions = $null
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
            'UserAuthenticationMethod.Read.All',
            'SecurityEvents.Read.All',           # For Secure Score
            'Application.Read.All',              # For App Permissions audit
            'DelegatedPermissionGrant.Read.All', # For OAuth2 permission grants
            'SharePointTenantSettings.Read.All', # For External Sharing settings
            'RoleManagement.Read.All',           # For PIM role assignments
            'RoleManagement.Read.Directory',     # For PIM directory roles
            'AccessReview.Read.All'              # For PIM access reviews
        )
        
        if ($TenantId) {
            Connect-MgGraph -Scopes $graphScopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
        }
        
        Write-Success "Connected to Microsoft Graph"
        
        # Show connection context so user knows which identity/tenant is being used
        $mgContext = Get-MgContext
        Write-Info "Connected as: $($mgContext.Account)"
        Write-Info "Tenant ID: $($mgContext.TenantId)"
        
        # Validate that requested scopes were granted (helps troubleshooting)
        $grantedScopes = $mgContext.Scopes
        $missingScopes = $graphScopes | Where-Object { $grantedScopes -notcontains $_ }
        if ($missingScopes.Count -gt 0) {
            Write-Warning "  ⚠ Some permissions were not granted: $($missingScopes -join ', ')"
            Write-Warning "  ⚠ Certain checks may fail or return incomplete data"
            Write-Warning "  ⚠ Re-consent may be required if checks fail unexpectedly"
        }
        
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
        # Use -Organization for multi-tenant scenarios (e.g., assessing client tenants)
        if ($TenantId) {
            Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
        }
        else {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
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

    $cachedAuthDetails = $null
    $cachedCaPolicies = $null

    if ($modulesToRun -contains 'Security') {
        try {
            $preloadTimer = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Information "  -> Preloading Conditional Access policies..." -InformationAction Continue
            $cachedCaPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            $preloadTimer.Stop()
            $elapsed = '{0:mm\:ss\.fff}' -f $preloadTimer.Elapsed
            Write-Information "  -> Cached $($cachedCaPolicies.Count) Conditional Access policies in $elapsed" -InformationAction Continue
        }
        catch {
            Write-Warning "  Could not preload Conditional Access policies: $_"
        }

        try {
            $preloadTimer = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Information "  -> Preloading authentication registration details..." -InformationAction Continue
            $cachedAuthDetails = Get-AuthRegistrationDetails
            $preloadTimer.Stop()
            $elapsed = '{0:mm\:ss\.fff}' -f $preloadTimer.Elapsed
            Write-Information "  -> Cached $($cachedAuthDetails.Count) authentication registrations in $elapsed" -InformationAction Continue
        }
        catch {
            Write-Warning "  Could not preload authentication registration details: $_"
        }
    }
    
    Write-Step "Running assessment modules: $($modulesToRun -join ', ')"
    
    $moduleScripts = @{
        'Security' = @(
            'Security\Test-SecureScore.ps1',
            'Security\Test-MFAConfiguration.ps1',
            'Security\Test-ConditionalAccess.ps1',
            'Security\Test-PrivilegedAccounts.ps1',
            'Security\Test-PIMConfiguration.ps1',
            'Security\Test-LegacyAuth.ps1',
            'Security\Test-AppPermissions.ps1',
            'Security\Test-ExternalSharing.ps1'
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
        $moduleTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $separator = '------' * [math]::Max(1, [math]::Ceiling((50 - $module.Length) / 6))
        Write-Information "`n  -- $module Assessment $separator" -InformationAction Continue

        if ($moduleScripts.ContainsKey($module)) {
            foreach ($scriptFile in $moduleScripts[$module]) {
                $scriptPath = Join-Path $PSScriptRoot "modules\$scriptFile"
                
                if (Test-Path $scriptPath) {
                    try {
                        $scriptTimer = [System.Diagnostics.Stopwatch]::StartNew()
                        $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)
                        Write-Information "    -> Running $scriptName..." -InformationAction Continue
                        . $scriptPath
                        $functionName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)

                        $scriptParams = @{ Config = $script:Config }
                        if ($functionName -in @('Test-MFAConfiguration','Test-PrivilegedAccounts')) {
                            $scriptParams['AuthRegistrationDetails'] = $cachedAuthDetails
                        }
                        if ($functionName -in @('Test-ConditionalAccess','Test-LegacyAuth')) {
                            $scriptParams['ConditionalAccessPolicies'] = $cachedCaPolicies
                        }

                        $result = & $functionName @scriptParams
                        $script:AssessmentResults += $result
                        $scriptTimer.Stop()
                        $scriptElapsed = '{0:mm\:ss\.fff}' -f $scriptTimer.Elapsed
                        
                        # Display result
                        $statusMessage = "      [$($result.Status)] $($result.Message)"
                        if ($result.Status -in @('Fail', 'Warning')) {
                            Write-Warning $statusMessage
                        } else {
                            Write-Information $statusMessage -InformationAction Continue
                        }
                        Write-Information "      $scriptName completed in $scriptElapsed" -InformationAction Continue
                    }
                    catch {
                        Write-Failure "Error running $scriptFile : $_"
                    }
                }
            }
        }
        
        $moduleTimer.Stop()
        $elapsed = '{0:mm\:ss\.fff}' -f $moduleTimer.Elapsed
        Write-Information "  Module $module completed in $elapsed" -InformationAction Continue
        Write-Information "  $(('-' * 6) * 11)" -InformationAction Continue
    }
}

function Export-Results {
    Write-Step "Generating assessment reports..."

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseFileName = "M365Guardian_$timestamp"

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

        # Export Conditional Access per-policy findings to separate CSV
        if ($caResult -and $caResult.PolicyFindings -and $caResult.PolicyFindings.Count -gt 0) {
            $caFindingsCsvPath = Join-Path $OutputPath "$($baseFileName)_ConditionalAccessPolicyFindings.csv"
            $flattened = @()
            foreach ($pf in $caResult.PolicyFindings) {
                $riskMessages = ""
                $riskSeverities = ""
                $oppMessages = ""
                $oppSeverities = ""
                if ($pf.Risks -and $pf.Risks.Count -gt 0) {
                    $riskMessages = ($pf.Risks | ForEach-Object { $_.Message }) -join '; '
                    $riskSeverities = ($pf.Risks | ForEach-Object { $_.Severity }) -join '; '
                }
                if ($pf.Opportunities -and $pf.Opportunities.Count -gt 0) {
                    $oppMessages = ($pf.Opportunities | ForEach-Object { $_.Message }) -join '; '
                    $oppSeverities = ($pf.Opportunities | ForEach-Object { $_.Severity }) -join '; '
                }
                $flattened += [PSCustomObject]@{
                    DisplayName = $pf.DisplayName
                    State = $pf.State
                    Id = $pf.Id
                    RiskMessages = $riskMessages
                    RiskSeverities = $riskSeverities
                    OpportunityMessages = $oppMessages
                    OpportunitySeverities = $oppSeverities
                }
            }
            $flattened | Export-Csv -Path $caFindingsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Conditional Access policy findings CSV: $caFindingsCsvPath"
            Write-Info "  � $($flattened.Count) policy finding record(s) exported"
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

        # Export risky applications to separate CSV
        $appResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Application Permission Audit" -and $_.RiskyApps }
        if ($appResult -and $appResult.RiskyApps.Count -gt 0) {
            $riskyAppsCsvPath = Join-Path $OutputPath "$($baseFileName)_RiskyApplications.csv"
            $appResult.RiskyApps | Select-Object DisplayName, AppId, Type, @{Name='RiskReasons';Expression={$_.RiskReasons -join '; '}}, @{Name='HighRiskPermissions';Expression={$_.HighRiskPermissions -join '; '}}, LastSignIn | 
                Export-Csv -Path $riskyAppsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Risky applications CSV: $riskyAppsCsvPath"
            Write-Info "  → $($appResult.RiskyApps.Count) risky application(s) exported"
        }

        # Export Secure Score improvement actions to separate CSV
        $secureScoreResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Microsoft Secure Score" -and $_.TopActions }
        if ($secureScoreResult -and $secureScoreResult.TopActions.Count -gt 0) {
            $secureScoreCsvPath = Join-Path $OutputPath "$($baseFileName)_SecureScoreActions.csv"
            $secureScoreResult.TopActions | Select-Object Title, Category, ScoreInPercentage, ImplementationStatus | 
                Export-Csv -Path $secureScoreCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Secure Score actions CSV: $secureScoreCsvPath"
            Write-Info "  → $($secureScoreResult.TopActions.Count) improvement action(s) exported"
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

    # Calculate severity distribution for chart
    $severityCounts = @{
        'Critical' = ($Results | Where-Object { $_.Severity -eq 'Critical' }).Count
        'High' = ($Results | Where-Object { $_.Severity -eq 'High' }).Count
        'Medium' = ($Results | Where-Object { $_.Severity -eq 'Medium' }).Count
        'Low' = ($Results | Where-Object { $_.Severity -eq 'Low' }).Count
        'Info' = ($Results | Where-Object { $_.Severity -eq 'Info' }).Count
    }
    
    # Build arrays for Chart.js (only include severities with counts > 0)
    $severityLabels = @()
    $severityValues = @()
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        if ($severityCounts[$severity] -gt 0) {
            $severityLabels += "'$severity'"
            $severityValues += $severityCounts[$severity]
        }
    }
    $severityLabelsJson = "[$($severityLabels -join ', ')]"
    $severityValuesJson = "[$($severityValues -join ', ')]"

    # Build results cards
    $resultsHtml = ""
    foreach ($result in $Results) {
        $statusClass = $result.Status.ToLower()
        $severityClass = $result.Severity.ToLower()
        
        # HTML-encode all dynamic text values for XSS protection
        $checkNameSafe = ConvertTo-HtmlSafe $result.CheckName
        $categorySafe = ConvertTo-HtmlSafe $result.Category
        $statusSafe = ConvertTo-HtmlSafe $result.Status
        $severitySafe = ConvertTo-HtmlSafe $result.Severity
        $messageSafe = ConvertTo-HtmlSafe $result.Message
        $recommendationSafe = ConvertTo-HtmlSafe $result.Recommendation
        $docUrlSafe = ConvertTo-HtmlSafe $result.DocumentationUrl
        
        # Build detailed findings content
        $findingContent = $messageSafe
        
        # Handle inactive mailboxes from License Optimization
        if ($result.InactiveMailboxes -and $result.InactiveMailboxes.Count -gt 0) {
            $findingContent += "<br><br><strong>Inactive Licensed Users ($($result.InactiveMailboxes.Count)):</strong><br>"
            $findingContent += "<ul>"
            $displayCount = [Math]::Min(10, $result.InactiveMailboxes.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $mailbox = $result.InactiveMailboxes[$i]
                $upnSafe = ConvertTo-HtmlSafe $mailbox.UserPrincipalName
                $nameSafe = ConvertTo-HtmlSafe $mailbox.DisplayName
                $lastSignIn = if ($mailbox.LastSignInDate -eq 'Never') { 
                    '<span style="color: #d13438; font-weight: 600;">Never</span>' 
                } else { 
                    ConvertTo-HtmlSafe $mailbox.LastSignInDate
                }
                $daysSafe = ConvertTo-HtmlSafe $mailbox.DaysSinceLastSignIn
                $findingContent += "<li><code>$upnSafe</code> - $nameSafe | Last: $lastSignIn ($daysSafe days ago)</li>"
            }
            if ($result.InactiveMailboxes.Count -gt 10) {
                $findingContent += "<li><em>...and $($result.InactiveMailboxes.Count - 10) more users (see CSV export)</em></li>"
            }
            $findingContent += "</ul>"
        }
        
        # Handle non-compliant mailboxes from Mailbox Auditing
        if ($result.NonCompliantMailboxes -and $result.NonCompliantMailboxes.Count -gt 0) {
            $findingContent += "<br><br><strong>Non-Compliant Mailboxes ($($result.NonCompliantMailboxes.Count)):</strong><br>"
            $findingContent += "<ul>"
            $displayCount = [Math]::Min(10, $result.NonCompliantMailboxes.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $mailbox = $result.NonCompliantMailboxes[$i]
                $upnSafe = ConvertTo-HtmlSafe $mailbox.UserPrincipalName
                $nameSafe = ConvertTo-HtmlSafe $mailbox.DisplayName
                $findingContent += "<li><code>$upnSafe</code> - $nameSafe</li>"
            }
            if ($result.NonCompliantMailboxes.Count -gt 10) {
                $findingContent += "<li><em>...and $($result.NonCompliantMailboxes.Count - 10) more mailboxes (see CSV export)</em></li>"
            }
            $findingContent += "</ul>"
        }
        
        # Handle domain details from Email Authentication
        if ($result.DomainDetails -and $result.DomainDetails.Count -gt 0) {
            $findingContent += "<br><br><strong>Domain Email Authentication Details:</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Domain</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>SPF</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>DKIM</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>DMARC</td></tr>"
            $statusDot = @{
                Green = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#107c10;'></span>"
                Amber = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#ffb900;'></span>"
                Red   = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#d13438;'></span>"
                Gray  = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#8a8886;'></span>"
            }
            foreach ($domain in $result.DomainDetails) {
                $domainSafe = ConvertTo-HtmlSafe $domain.Domain
                $spfSafe = ConvertTo-HtmlSafe $domain.SPF
                $dkimSafe = ConvertTo-HtmlSafe $domain.DKIM
                $dmarcSafe = ConvertTo-HtmlSafe $domain.DMARC
                
                $spfIcon = switch -Regex ($domain.SPF) {
                    "^Valid" { $statusDot.Green }
                    "^Missing" { $statusDot.Red }
                    "^Invalid" { $statusDot.Amber }
                    default { $statusDot.Gray }
                }
                $dkimIcon = if ($domain.DKIM -eq "Enabled") { $statusDot.Green } else { $statusDot.Red }
                $dmarcIcon = switch -Regex ($domain.DMARC) {
                    "^Valid" { $statusDot.Green }
                    "^Missing" { $statusDot.Red }
                    "^Weak" { $statusDot.Amber }
                    default { $statusDot.Gray }
                }
                
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$domainSafe</code></td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$spfIcon $spfSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$dkimIcon $dkimSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$dmarcIcon $dmarcSafe</td></tr>"
            }
            $findingContent += "</table>"
        }
        
        # Handle enabled Conditional Access policies
        if ($result.EnabledPolicies -and $result.EnabledPolicies.Count -gt 0) {
            $findingContent += "<br><br><strong>Enabled Conditional Access Policies ($($result.EnabledPolicies.Count)):</strong><br>"
            $findingContent += "<ul>"
            foreach ($policy in $result.EnabledPolicies) {
                $policyNameSafe = ConvertTo-HtmlSafe $policy.DisplayName
                $policyStateSafe = ConvertTo-HtmlSafe $policy.State
                $findingContent += "<li><code>$policyNameSafe</code>"
                if ($policy.State) {
                    $stateColor = if ($policy.State -eq 'enabled') { 'var(--success-color)' } else { 'var(--warning-color)' }
                    $findingContent += " - <span style='color: $stateColor; font-weight: 600;'>$policyStateSafe</span>"
                }
                $findingContent += "</li>"
            }
            $findingContent += "</ul>"
        }

        # Show Conditional Access posture score when available
        if ($result.CheckName -eq "Conditional Access Policies" -and $null -ne $result.ConditionalAccessScore) {
            $scoreSafe = ConvertTo-HtmlSafe $result.ConditionalAccessScore
            $findingContent += "<br><br><strong>Conditional Access Posture Score:</strong> $scoreSafe% of policies have no flagged risks"
        }

        # Handle structured Conditional Access Findings (security posture issues)
        if ($result.CheckName -eq "Conditional Access Policies" -and $result.Findings -and $result.Findings.Count -gt 0) {
            $findingContent += "<br><br><strong>Security Posture Issues ($($result.Findings.Count)):</strong>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300); width: 100px;'>Severity</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Issue</td></tr>"
            
            # Sort by severity (Critical > High > Medium > Low)
            $severityOrder = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }
            $sortedFindings = $result.Findings | Sort-Object { $severityOrder[$_.Severity] }
            
            foreach ($finding in $sortedFindings) {
                $findingMsgSafe = ConvertTo-HtmlSafe $finding.Message
                $findingSeveritySafe = ConvertTo-HtmlSafe $finding.Severity
                $severityColor = switch ($finding.Severity) {
                    'Critical' { 'var(--danger-color)' }
                    'High' { '#d13438' }
                    'Medium' { '#ffb900' }
                    'Low' { '#0078d4' }
                    default { 'var(--gray-700)' }
                }
                $severityBg = switch ($finding.Severity) {
                    'Critical' { '#fde7e9' }
                    'High' { '#fde7e9' }
                    'Medium' { '#fff4ce' }
                    'Low' { '#deecf9' }
                    default { 'var(--gray-100)' }
                }
                $findingContent += "<tr>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); background: $severityBg; color: $severityColor; font-weight: 600; text-align: center;'>$findingSeveritySafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$findingMsgSafe</td>"
                $findingContent += "</tr>"
            }
            $findingContent += "</table>"
        }

        # Handle per-policy Conditional Access analysis (risks/opportunities)
        if ($result.PolicyFindings -and $result.PolicyFindings.Count -gt 0) {
            $severityColors = @{
                critical = 'var(--danger-color)'
                high = 'var(--danger-color)'
                medium = 'var(--warning-color)'
                low = 'var(--info-color)'
                info = 'var(--info-color)'
            }
            $caPortalBase = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade/~/policyId/"
            $caSeverityRank = {
                param($sev)
                if (-not $sev) { return 0 }
                switch ($sev.ToLower()) {
                    'critical' { return 5 }
                    'high' { return 4 }
                    'medium' { return 3 }
                    'low' { return 2 }
                    default { return 1 }
                }
            }

            $findingContent += "<br><br><strong>Conditional Access Policy Analysis:</strong><br>"
            $findingContent += "<ul>"
            foreach ($analysis in $result.PolicyFindings) {
                $policyNameSafe = ConvertTo-HtmlSafe $analysis.DisplayName
                $policyStateSafe = ConvertTo-HtmlSafe $analysis.State
                $policyIdSafe = ConvertTo-HtmlSafe $analysis.Id
                $findingContent += "<li><code>$policyNameSafe</code>"
                if ($analysis.State) {
                    $stateColor = if ($analysis.State -eq 'enabled') { 'var(--success-color)' } elseif ($analysis.State -eq 'disabled') { 'var(--danger-color)' } else { 'var(--warning-color)' }
                    $findingContent += " - <span style='color: $stateColor; font-weight: 600;'>$policyStateSafe</span>"
                }
                if ($analysis.Id) {
                    $policyLink = "$caPortalBase$policyIdSafe"
                    $findingContent += " <a href='$policyLink' target='_blank' style='margin-left:6px; font-size:12px;'>Open in Entra</a> <span style='color: var(--gray-700); font-size: 12px;'>ID: <code>$policyIdSafe</code></span>"
                }

                $riskList = @()
                if ($analysis.Risks) { $riskList = $analysis.Risks | Where-Object { $_ } }
                $opportunityList = @()
                if ($analysis.Opportunities) { $opportunityList = $analysis.Opportunities | Where-Object { $_ } }

                if ($riskList.Count -gt 0 -or $opportunityList.Count -gt 0) {
                    $findingContent += "<br><div style='margin-top:6px;'>"
                    if ($riskList.Count -gt 0) {
                        $findingContent += "<div><strong>Risks:</strong><ul style='margin:4px 0 8px 16px;'>"
                        foreach ($risk in $riskList) {
                            $riskSafe = ConvertTo-HtmlSafe $risk.Message
                            $riskSeveritySafe = ConvertTo-HtmlSafe $risk.Severity
                            $riskColor = $severityColors[$riskSeveritySafe.ToLower()]
                            if (-not $riskColor) { $riskColor = 'var(--danger-color)' }
                            $findingContent += "<li style='color: $riskColor;'><strong>${riskSeveritySafe}:</strong> $riskSafe</li>"
                        }
                        $findingContent += "</ul></div>"
                    }
                    if ($opportunityList.Count -gt 0) {
                        $findingContent += "<div><strong>Opportunities:</strong><ul style='margin:4px 0 8px 16px;'>"
                        foreach ($opp in $opportunityList) {
                            $oppSafe = ConvertTo-HtmlSafe $opp.Message
                            $oppSeveritySafe = ConvertTo-HtmlSafe $opp.Severity
                            $oppColor = $severityColors[$oppSeveritySafe.ToLower()]
                            if (-not $oppColor) { $oppColor = 'var(--warning-color)' }
                            $findingContent += "<li style='color: $oppColor;'><strong>${oppSeveritySafe}:</strong> $oppSafe</li>"
                        }
                        $findingContent += "</ul></div>"
                    }
                    $findingContent += "</div>"
                }
                else {
                    $findingContent += "<br><span style='color: var(--gray-700); font-size: 13px;'>No specific risks or opportunities detected.</span>"
                }

                $findingContent += "</li>"
            }
            $findingContent += "</ul>"

            if ($result.PolicyFindingsSummary -and (($result.PolicyFindingsSummary.Risks.Count -gt 0) -or ($result.PolicyFindingsSummary.Opportunities.Count -gt 0))) {
                $findingContent += "<br><strong>Cross-policy highlights (deduped):</strong><br>"
                if ($result.PolicyFindingsSummary.Risks.Count -gt 0) {
                    $findingContent += "<div style='margin-top:4px;'><strong>Risks:</strong><ul style='margin:4px 0 8px 16px;'>"
                    foreach ($summaryRisk in ($result.PolicyFindingsSummary.Risks | Sort-Object @{Expression={& $caSeverityRank $_.Severity};Descending=$true}, @{Expression={$_.Count};Descending=$true})) {
                        $riskMsgSafe = ConvertTo-HtmlSafe $summaryRisk.Message
                        $riskSeveritySafe = ConvertTo-HtmlSafe $summaryRisk.Severity
                        $riskColor = $severityColors[$riskSeveritySafe.ToLower()]
                        if (-not $riskColor) { $riskColor = 'var(--danger-color)' }
                        $countSafe = ConvertTo-HtmlSafe $summaryRisk.Count
                        $findingContent += "<li style='color: $riskColor;'><strong>$riskSeveritySafe</strong> ($countSafe policy/policies): $riskMsgSafe</li>"
                    }
                    $findingContent += "</ul></div>"
                }
                if ($result.PolicyFindingsSummary.Opportunities.Count -gt 0) {
                    $findingContent += "<div style='margin-top:4px;'><strong>Opportunities:</strong><ul style='margin:4px 0 8px 16px;'>"
                    foreach ($summaryOpp in ($result.PolicyFindingsSummary.Opportunities | Sort-Object @{Expression={& $caSeverityRank $_.Severity};Descending=$true}, @{Expression={$_.Count};Descending=$true})) {
                        $oppMsgSafe = ConvertTo-HtmlSafe $summaryOpp.Message
                        $oppSeveritySafe = ConvertTo-HtmlSafe $summaryOpp.Severity
                        $oppColor = $severityColors[$oppSeveritySafe.ToLower()]
                        if (-not $oppColor) { $oppColor = 'var(--warning-color)' }
                        $countSafe = ConvertTo-HtmlSafe $summaryOpp.Count
                        $findingContent += "<li style='color: $oppColor;'><strong>$oppSeveritySafe</strong> ($countSafe policy/policies): $oppMsgSafe</li>"
                    }
                    $findingContent += "</ul></div>"
                }
            }
        }
        
        # Handle privileged accounts from Privileged Account Security
        if ($result.PrivilegedAccounts -and $result.PrivilegedAccounts.Count -gt 0) {
            $findingContent += "<br><br><strong>Privileged Accounts ($($result.PrivilegedAccounts.Count)):</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>User Principal Name</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Roles</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>MFA Status</td></tr>"
            foreach ($account in $result.PrivilegedAccounts) {
                $accountUpnSafe = ConvertTo-HtmlSafe $account.UserPrincipalName
                $mfaIcon = if ($account.HasMFA) { "✅ Enabled" } else { "❌ Not Enabled" }
                $mfaColor = if ($account.HasMFA) { 'var(--success-color)' } else { 'var(--danger-color)' }
                $rolesSafe = ($account.Roles | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$accountUpnSafe</code></td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); font-size: 12px;'>$rolesSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $mfaColor; font-weight: 600;'>$mfaIcon</td></tr>"
            }
            $findingContent += "</table>"
        }
        
        # Handle Microsoft Secure Score details
        if ($result.SecureScore -and $result.MaxScore) {
            $scorePercent = [math]::Round(($result.SecureScore / $result.MaxScore) * 100, 1)
            $scoreColor = if ($scorePercent -ge 80) { 'var(--success-color)' } elseif ($scorePercent -ge 60) { 'var(--warning-color)' } else { 'var(--danger-color)' }
            $findingContent += "<br><br><div style='text-align: center; padding: 20px; background: var(--gray-100); border-radius: 8px;'>"
            $findingContent += "<div style='font-size: 48px; font-weight: 700; color: $scoreColor;'>$($result.SecureScore) / $($result.MaxScore)</div>"
            $findingContent += "<div style='font-size: 18px; color: var(--gray-700); margin-top: 4px;'>Secure Score ($scorePercent%)</div>"
            $findingContent += "</div>"
            
            # Show category breakdown if available
            if ($result.CategoryBreakdown -and $result.CategoryBreakdown.Count -gt 0) {
                $findingContent += "<br><strong>Score by Category:</strong><br>"
                $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
                $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Category</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Score</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Max</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>%</td></tr>"
                foreach ($cat in $result.CategoryBreakdown) {
                    $catNameSafe = ConvertTo-HtmlSafe $cat.Category
                    $catPct = if ($cat.MaxScore -gt 0) { [math]::Round(($cat.Score / $cat.MaxScore) * 100, 0) } else { 0 }
                    $catColor = if ($catPct -ge 80) { 'var(--success-color)' } elseif ($catPct -ge 60) { 'var(--warning-color)' } else { 'var(--danger-color)' }
                    $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$catNameSafe</td>"
                    $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$($cat.Score)</td>"
                    $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$($cat.MaxScore)</td>"
                    $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $catColor; font-weight: 600;'>$catPct%</td></tr>"
                }
                $findingContent += "</table>"
            }
            
            # Show top improvement actions
            if ($result.TopActions -and $result.TopActions.Count -gt 0) {
                $findingContent += "<br><strong>Top Improvement Actions ($($result.TopActions.Count)):</strong><br>"
                $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
                $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Action</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Category</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Points</td></tr>"
                foreach ($action in $result.TopActions) {
                    $actionTitleSafe = ConvertTo-HtmlSafe $action.Title
                    $actionCatSafe = ConvertTo-HtmlSafe $action.Category
                    $actionPoints = $action.ScoreInPercentage
                    $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$actionTitleSafe</td>"
                    $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$actionCatSafe</td>"
                    $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: var(--info-color); font-weight: 600;'>+$actionPoints</td></tr>"
                }
                $findingContent += "</table>"
            }
        }
        
        # Handle Risky Apps from Application Permission Audit
        if ($result.RiskyApps -and $result.RiskyApps.Count -gt 0) {
            $findingContent += "<br><br><strong>Risky Applications ($($result.RiskyApps.Count)):</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Application</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Type</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Risk Reasons</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>High-Risk Permissions</td></tr>"
            $displayCount = [Math]::Min(15, $result.RiskyApps.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $app = $result.RiskyApps[$i]
                $appNameSafe = ConvertTo-HtmlSafe $app.DisplayName
                $appTypeSafe = ConvertTo-HtmlSafe $app.Type
                $riskReasonsSafe = ($app.RiskReasons | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join '<br>'
                $permsSafe = ($app.HighRiskPermissions | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
                if (-not $permsSafe) { $permsSafe = '-' }
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$appNameSafe</code></td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$appTypeSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: var(--danger-color);'>$riskReasonsSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); font-size: 11px;'>$permsSafe</td></tr>"
            }
            if ($result.RiskyApps.Count -gt 15) {
                $findingContent += "<tr><td colspan='4' style='padding: 8px; border: 1px solid var(--gray-300); font-style: italic; text-align: center;'>...and $($result.RiskyApps.Count - 15) more apps (see CSV export)</td></tr>"
            }
            $findingContent += "</table>"
        }
        
        # Handle External Sharing configuration details
        if ($result.SharingCapability) {
            $findingContent += "<br><br><strong>SharePoint/OneDrive External Sharing Configuration:</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Setting</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Value</td></tr>"
            
            $sharingCapSafe = ConvertTo-HtmlSafe $result.SharingCapability
            $sharingColor = switch ($result.SharingCapability) {
                'Disabled' { 'var(--success-color)' }
                'ExternalUserSharingOnly' { 'var(--warning-color)' }
                'ExternalUserAndGuestSharing' { 'var(--warning-color)' }
                'ExistingExternalUserSharingOnly' { 'var(--info-color)' }
                default { 'var(--danger-color)' }
            }
            $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Sharing Capability</td><td style='padding: 8px; border: 1px solid var(--gray-300); color: $sharingColor; font-weight: 600;'>$sharingCapSafe</td></tr>"
            
            if ($null -ne $result.AnonLinksEnabled) {
                $anonIcon = if ($result.AnonLinksEnabled) { "❌ Enabled" } else { "✅ Disabled" }
                $anonColor = if ($result.AnonLinksEnabled) { 'var(--danger-color)' } else { 'var(--success-color)' }
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Anonymous Links</td><td style='padding: 8px; border: 1px solid var(--gray-300); color: $anonColor; font-weight: 600;'>$anonIcon</td></tr>"
            }
            
            if ($result.DefaultLinkType) {
                $linkTypeSafe = ConvertTo-HtmlSafe $result.DefaultLinkType
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Default Link Type</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>$linkTypeSafe</td></tr>"
            }
            
            if ($result.DefaultLinkPermission) {
                $linkPermSafe = ConvertTo-HtmlSafe $result.DefaultLinkPermission
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Default Link Permission</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>$linkPermSafe</td></tr>"
            }
            
            if ($null -ne $result.RequireAcceptingAccount) {
                $reqAcctIcon = if ($result.RequireAcceptingAccount) { "✅ Required" } else { "⚠️ Not Required" }
                $reqAcctColor = if ($result.RequireAcceptingAccount) { 'var(--success-color)' } else { 'var(--warning-color)' }
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Require Accepting Account</td><td style='padding: 8px; border: 1px solid var(--gray-300); color: $reqAcctColor; font-weight: 600;'>$reqAcctIcon</td></tr>"
            }
            
            if ($result.AllowedDomains -and $result.AllowedDomains.Count -gt 0) {
                $domainsSafe = ($result.AllowedDomains | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Allowed Domains</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>$domainsSafe</td></tr>"
            }
            
            if ($result.BlockedDomains -and $result.BlockedDomains.Count -gt 0) {
                $blockedSafe = ($result.BlockedDomains | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>Blocked Domains</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>$blockedSafe</td></tr>"
            }
            
            $findingContent += "</table>"
        }
        
        # Build structured recommendations for Conditional Access
        $recommendationContent = $recommendationSafe
        if ($result.CheckName -eq "Conditional Access Policies" -and $result.Recommendations -and $result.Recommendations.Count -gt 0) {
            $recommendationContent = "<strong>Actionable Recommendations ($($result.Recommendations.Count)):</strong>"
            $recommendationContent += "<ol style='margin: 10px 0 0 0; padding-left: 20px;'>"
            $recNumber = 1
            foreach ($rec in $result.Recommendations) {
                $recSafe = ConvertTo-HtmlSafe $rec
                $recommendationContent += "<li style='margin-bottom: 8px; line-height: 1.5;'>$recSafe</li>"
                $recNumber++
            }
            $recommendationContent += "</ol>"
        }
        
        # Build finding card HTML
        $resultsHtml += @"
<div class="finding-card" data-status="$statusClass">
    <div class="finding-header">
        <div class="finding-title-group">
            <div class="finding-name">$checkNameSafe</div>
            <div class="finding-badges">
                <span class="badge badge-category">$categorySafe</span>
                <span class="badge badge-status-$statusClass">$statusSafe</span>
                <span class="badge badge-severity-$severityClass">$severitySafe</span>
            </div>
        </div>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <div class="finding-label">Finding</div>
            <div class="finding-content">$findingContent</div>
        </div>
        <div class="finding-section">
            <div class="finding-label">Recommendation</div>
            <div class="finding-content">$recommendationContent</div>
        </div>
        <div class="finding-section">
            <a href="$docUrlSafe" target="_blank" class="doc-link">
                <span>📘</span>
                <span>View Documentation</span>
            </a>
        </div>
    </div>
</div>

"@
    }
    
    # Add empty state if no results
    if ($Results.Count -eq 0) {
        $resultsHtml = @"
<div class="empty-state">
    <div class="empty-state-icon">📋</div>
    <div class="empty-state-text">No assessment results found</div>
</div>
"@
    }

    # Replace placeholders (encode tenant name for safety)
    $tenantName = if ($script:TenantInfo) { $script:TenantInfo.DisplayName } else { "Not Connected" }
    $tenantNameSafe = ConvertTo-HtmlSafe $tenantName
    
    $html = $html -replace '{{TENANT_NAME}}', $tenantNameSafe
    $html = $html -replace '{{ASSESSMENT_DATE}}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $html = $html -replace '{{TOTAL_CHECKS}}', $totalChecks
    $html = $html -replace '{{PASS_COUNT}}', $passCount
    $html = $html -replace '{{FAIL_COUNT}}', $failCount
    $html = $html -replace '{{WARN_COUNT}}', $warnCount
    $html = $html -replace '{{INFO_COUNT}}', $infoCount
    $html = $html -replace '{{PASS_PERCENTAGE}}', $passPercentage
    $html = $html -replace '{{SEVERITY_LABELS}}', $severityLabelsJson
    $html = $html -replace '{{SEVERITY_COUNTS}}', $severityValuesJson
    $html = $html -replace '{{RESULTS_CARDS}}', $resultsHtml

    $html | Out-File $OutputPath -Encoding UTF8
}

function Get-HTMLTemplate {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M365 Security Assessment Report - {{TENANT_NAME}}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --primary-color: #0078d4;
            --primary-dark: #005a9e;
            --success-color: #107c10;
            --danger-color: #d13438;
            --warning-color: #ff8c00;
            --info-color: #0078d4;
            --gray-50: #fafafa;
            --gray-100: #f5f5f5;
            --gray-200: #e5e5e5;
            --gray-300: #d4d4d4;
            --gray-700: #424242;
            --gray-900: #1a1a1a;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.1);
            --radius-sm: 4px;
            --radius-md: 8px;
            --radius-lg: 12px;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: var(--gray-100);
            color: var(--gray-900);
            line-height: 1.6;
            padding: 20px;
        }
        
        .container { 
            max-width: 1600px;
            margin: 0 auto;
            background: white;
            box-shadow: var(--shadow-lg);
            border-radius: var(--radius-lg);
            overflow: hidden;
        }
        
        .header { 
            background: linear-gradient(135deg, #0078d4 0%, #005a9e 50%, #004578 100%);
            color: white;
            padding: 40px;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            border-radius: 50%;
            transform: translate(30%, -30%);
        }
        
        .header-content { position: relative; z-index: 1; }
        
        .header h1 { 
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .header-meta { 
            display: flex;
            gap: 30px;
            margin-top: 15px;
            font-size: 14px;
            opacity: 0.95;
        }
        
        .header-meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .header-meta-label { 
            font-weight: 600;
            opacity: 0.8;
        }
        
        .executive-summary {
            padding: 40px;
            background: var(--gray-50);
            border-bottom: 1px solid var(--gray-200);
        }
        
        .summary-title {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 25px;
            color: var(--gray-900);
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .metric-card {
            background: white;
            padding: 24px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--gray-200);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .metric-card-header {
            font-size: 13px;
            font-weight: 600;
            color: var(--gray-700);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }
        
        .metric-card-value {
            font-size: 42px;
            font-weight: 700;
            line-height: 1;
        }
        
        .metric-card.total .metric-card-value { color: var(--gray-900); }
        .metric-card.pass .metric-card-value { color: var(--success-color); }
        .metric-card.fail .metric-card-value { color: var(--danger-color); }
        .metric-card.warn .metric-card-value { color: var(--warning-color); }
        .metric-card.info .metric-card-value { color: var(--info-color); }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .chart-container {
            background: white;
            padding: 24px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--gray-200);
        }
        
        .chart-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--gray-900);
        }
        
        .chart-wrapper {
            position: relative;
            height: 250px;
        }
        
        .controls {
            padding: 30px 40px;
            background: white;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
            position: relative;
        }
        
        .search-box input {
            width: 100%;
            padding: 12px 40px 12px 16px;
            border: 2px solid var(--gray-300);
            border-radius: var(--radius-md);
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .search-icon {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--gray-700);
        }
        
        .filter-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid var(--gray-300);
            background: white;
            border-radius: var(--radius-md);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .filter-btn:hover {
            border-color: var(--primary-color);
            color: var(--primary-color);
        }
        
        .filter-btn.active {
            background: var(--primary-color);
            border-color: var(--primary-color);
            color: white;
        }
        
        .results-section {
            padding: 40px;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .results-title {
            font-size: 24px;
            font-weight: 700;
            color: var(--gray-900);
        }
        
        .results-count {
            font-size: 14px;
            color: var(--gray-700);
            background: var(--gray-100);
            padding: 8px 16px;
            border-radius: var(--radius-md);
        }
        
        .findings-grid {
            display: grid;
            gap: 20px;
        }
        
        .finding-card {
            background: white;
            border: 1px solid var(--gray-200);
            border-radius: var(--radius-md);
            padding: 24px;
            box-shadow: var(--shadow-sm);
            transition: all 0.2s;
        }
        
        .finding-card:hover {
            box-shadow: var(--shadow-md);
            border-color: var(--gray-300);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
            gap: 20px;
        }
        
        .finding-title-group {
            flex: 1;
        }
        
        .finding-name {
            font-size: 18px;
            font-weight: 600;
            color: var(--gray-900);
            margin-bottom: 8px;
        }
        
        .finding-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: var(--radius-sm);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        
        .badge-status-pass { background: #dff6dd; color: #107c10; }
        .badge-status-fail { background: #fde7e9; color: #d13438; }
        .badge-status-warning { background: #fff4ce; color: #8a4600; }
        .badge-status-info { background: #e1f5fe; color: #0078d4; }
        
        .badge-severity-critical { background: #d13438; color: white; }
        .badge-severity-high { background: #ff8c00; color: white; }
        .badge-severity-medium { background: #ffd700; color: #333; }
        .badge-severity-low { background: #90ee90; color: #333; }
        .badge-severity-info { background: #e1f5fe; color: #0078d4; }
        
        .badge-category {
            background: var(--primary-color);
            color: white;
        }
        
        .finding-body {
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--gray-200);
        }
        
        .finding-section {
            margin-bottom: 16px;
        }
        
        .finding-section:last-child {
            margin-bottom: 0;
        }
        
        .finding-label {
            font-size: 13px;
            font-weight: 600;
            color: var(--gray-700);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        
        .finding-content {
            font-size: 14px;
            color: var(--gray-900);
            line-height: 1.6;
        }
        
        .finding-content ul {
            margin-left: 20px;
            margin-top: 8px;
        }
        
        .finding-content li {
            margin: 4px 0;
        }
        
        .finding-content code {
            background: var(--gray-100);
            padding: 2px 6px;
            border-radius: var(--radius-sm);
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            color: var(--danger-color);
        }
        
        .doc-link {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: color 0.2s;
        }
        
        .doc-link:hover {
            color: var(--primary-dark);
            text-decoration: underline;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-700);
        }
        
        .empty-state-icon {
            font-size: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .empty-state-text {
            font-size: 18px;
            font-weight: 600;
        }
        
        @media print {
            body { padding: 0; background: white; }
            .container { box-shadow: none; }
            .controls { display: none; }
            .finding-card { page-break-inside: avoid; }
            .chart-wrapper { height: 200px; }
        }
        
        @media (max-width: 768px) {
            .header { padding: 24px; }
            .header h1 { font-size: 24px; }
            .header-meta { flex-direction: column; gap: 10px; }
            .executive-summary { padding: 24px; }
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
            .charts-grid { grid-template-columns: 1fr; }
            .results-section { padding: 24px; }
            .controls { padding: 20px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>Microsoft 365 Security Assessment Report</h1>
                <div class="header-meta">
                    <div class="header-meta-item">
                        <span class="header-meta-label">Tenant:</span>
                        <span>{{TENANT_NAME}}</span>
                    </div>
                    <div class="header-meta-item">
                        <span class="header-meta-label">Assessment Date:</span>
                        <span>{{ASSESSMENT_DATE}}</span>
                    </div>
                    <div class="header-meta-item">
                        <span class="header-meta-label">Compliance Score:</span>
                        <span>{{PASS_PERCENTAGE}}%</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="executive-summary">
            <h2 class="summary-title">Executive Summary</h2>
            
            <div class="metrics-grid">
                <div class="metric-card total">
                    <div class="metric-card-header">Total Checks</div>
                    <div class="metric-card-value">{{TOTAL_CHECKS}}</div>
                </div>
                <div class="metric-card pass">
                    <div class="metric-card-header">Passed</div>
                    <div class="metric-card-value">{{PASS_COUNT}}</div>
                </div>
                <div class="metric-card fail">
                    <div class="metric-card-header">Failed</div>
                    <div class="metric-card-value">{{FAIL_COUNT}}</div>
                </div>
                <div class="metric-card warn">
                    <div class="metric-card-header">Warnings</div>
                    <div class="metric-card-value">{{WARN_COUNT}}</div>
                </div>
                <div class="metric-card info">
                    <div class="metric-card-header">Informational</div>
                    <div class="metric-card-value">{{INFO_COUNT}}</div>
                </div>
            </div>
            
            <div class="charts-grid">
                <div class="chart-container">
                    <div class="chart-title">Status Distribution</div>
                    <div class="chart-wrapper">
                        <canvas id="statusChart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <div class="chart-title">Findings by Severity</div>
                    <div class="chart-wrapper">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search findings...">
                <span class="search-icon">🔍</span>
            </div>
            <div class="filter-group">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="fail">Failed</button>
                <button class="filter-btn" data-filter="warning">Warnings</button>
                <button class="filter-btn" data-filter="pass">Passed</button>
                <button class="filter-btn" data-filter="info">Info</button>
            </div>
        </div>
        
        <div class="results-section">
            <div class="results-header">
                <h2 class="results-title">Detailed Findings</h2>
                <div class="results-count"><span id="visibleCount">{{TOTAL_CHECKS}}</span> of {{TOTAL_CHECKS}} findings</div>
            </div>
            
            <div class="findings-grid" id="findingsGrid">
                {{RESULTS_CARDS}}
            </div>
        </div>
    </div>
    
    <script>
        // Chart.js configuration
        const statusData = {
            labels: ['Passed', 'Failed', 'Warning', 'Info'],
            datasets: [{
                data: [{{PASS_COUNT}}, {{FAIL_COUNT}}, {{WARN_COUNT}}, {{INFO_COUNT}}],
                backgroundColor: ['#107c10', '#d13438', '#ff8c00', '#0078d4'],
                borderWidth: 0
            }]
        };
        
        const severityData = {
            labels: {{SEVERITY_LABELS}},
            datasets: [{
                label: 'Findings',
                data: {{SEVERITY_COUNTS}},
                backgroundColor: ['#d13438', '#ff8c00', '#ffd700', '#90ee90', '#e1f5fe'],
                borderWidth: 0
            }]
        };
        
        new Chart(document.getElementById('statusChart'), {
            type: 'doughnut',
            data: statusData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
        
        new Chart(document.getElementById('severityChart'), {
            type: 'bar',
            data: severityData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });
        
        // Search and filter functionality
        const searchInput = document.getElementById('searchInput');
        const filterBtns = document.querySelectorAll('.filter-btn');
        const findingCards = document.querySelectorAll('.finding-card');
        const visibleCount = document.getElementById('visibleCount');
        
        let currentFilter = 'all';
        
        function updateVisibleCount() {
            const visible = document.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            visibleCount.textContent = visible;
        }
        
        function filterFindings() {
            const searchTerm = searchInput.value.toLowerCase();
            
            findingCards.forEach(card => {
                const text = card.textContent.toLowerCase();
                const matchesSearch = text.includes(searchTerm);
                const status = card.dataset.status;
                const matchesFilter = currentFilter === 'all' || status === currentFilter;
                
                card.style.display = matchesSearch && matchesFilter ? 'block' : 'none';
            });
            
            updateVisibleCount();
        }
        
        searchInput.addEventListener('input', filterFindings);
        
        filterBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                filterBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.filter;
                filterFindings();
            });
        });
    </script>
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
    Write-Information "`nFor troubleshooting help, visit: https://github.com/mobieus10036/m365-security-guardian/issues" -InformationAction Continue
    exit 1
}
finally {
    Disconnect-M365Services
}

#endregion
