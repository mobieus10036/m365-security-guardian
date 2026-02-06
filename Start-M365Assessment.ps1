<#
.SYNOPSIS
    Main orchestrator for M365 Security Guardian.

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

.PARAMETER AuthMethod
    Authentication method to use. Valid values:
    - DeviceCode (default) - Best for terminal/console use, shows code to enter at microsoft.com/devicelogin
    - Interactive - Opens browser window (may have WAM issues on Windows)
    - Certificate - For automation with app registration and certificate
    - ClientSecret - For automation with app registration and client secret
    - ManagedIdentity - For Azure-hosted automation (Azure VMs, Functions, etc.)

.PARAMETER ClientId
    Application (client) ID for Certificate, ClientSecret, or ManagedIdentity auth.
    Required for non-interactive authentication methods.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for Certificate-based authentication.
    Certificate must be installed in CurrentUser\My store.

.PARAMETER ClientSecret
    Client secret as SecureString for ClientSecret authentication.
    Use: -ClientSecret (ConvertTo-SecureString 'secret' -AsPlainText -Force)

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

.EXAMPLE
    .\Start-M365Assessment.ps1 -AuthMethod DeviceCode -TenantId "contoso.onmicrosoft.com"
    Uses device code flow to assess a specific tenant.

.EXAMPLE
    .\Start-M365Assessment.ps1 -AuthMethod Certificate -ClientId "app-id" -TenantId "tenant-id" -CertificateThumbprint "thumbprint"
    Uses certificate-based auth for automated/scheduled assessments.

.EXAMPLE
    .\Start-M365Assessment.ps1 -AuthMethod ManagedIdentity -ClientId "managed-identity-client-id"
    Uses managed identity when running from Azure VM or Azure Functions.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.1.0
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
    [ValidateSet('Interactive', 'DeviceCode', 'Certificate', 'ClientSecret', 'ManagedIdentity')]
    [string]$AuthMethod = 'DeviceCode',

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [securestring]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [switch]$NoAuth,

    # Baseline comparison parameters
    [Parameter(Mandatory = $false)]
    [switch]$SaveBaseline,

    [Parameter(Mandatory = $false)]
    [string]$BaselineName = "Baseline",

    [Parameter(Mandatory = $false)]
    [string]$CompareToBaseline,

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath = (Join-Path $PSScriptRoot 'baselines')
)

#Requires -Version 5.1

# Disable WAM broker BEFORE loading modules to prevent token caching issues
# This fixes "Object reference not set" errors in embedded terminals (VS Code, etc.)
$env:AZURE_IDENTITY_DISABLE_BROKER = "true"

# Import required modules
Write-Verbose "Loading Microsoft Graph modules..."
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
    Import-Module Microsoft.Graph.Security -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
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
$script:SecurityScore = $null

# Resolve authentication configuration (priority order):
# 1. Explicit parameters (detected via $PSBoundParameters)
# 2. .auth-config.json auto-load (only if no explicit auth params given)
$hasExplicitAuth = $PSBoundParameters.ContainsKey('TenantId') -or
                   $PSBoundParameters.ContainsKey('AuthMethod') -or
                   $PSBoundParameters.ContainsKey('ClientId') -or
                   $PSBoundParameters.ContainsKey('CertificateThumbprint') -or
                   $PSBoundParameters.ContainsKey('ClientSecret')

if (-not $hasExplicitAuth) {
    # Auto-load .auth-config.json only when no explicit auth params were given
    $authConfigPath = Join-Path $PSScriptRoot ".auth-config.json"
    $legacyAuthConfigPath = Join-Path $PSScriptRoot ".auth-config.ps1"
    if (Test-Path $authConfigPath) {
        Write-Verbose "Loading saved authentication configuration from JSON..."
        try {
            $AuthConfig = Get-Content -Path $authConfigPath -Raw | ConvertFrom-Json
            $AuthMethod = $AuthConfig.AuthMethod
            $ClientId = $AuthConfig.ClientId
            $TenantId = $AuthConfig.TenantId
            $CertificateThumbprint = $AuthConfig.CertificateThumbprint
            Write-Verbose "Using saved auth: $AuthMethod"
        }
        catch {
            Write-Warning "Failed to load auth config: $_"
        }
    }
    elseif (Test-Path $legacyAuthConfigPath) {
        Write-Warning "Legacy .auth-config.ps1 detected. Please re-run Setup-AppRegistration to generate the safer .auth-config.json format."
        Write-Warning "Dot-sourcing .ps1 config files is deprecated due to code injection risk."
    }
}

#region Helper Functions

function Write-Banner {
    $banner = @"

╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              M365 Security Guardian v3.1.0                           ║
║                                                                      ║
║         Security & Best Practice Assessment for Microsoft 365        ║
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
        Uses System.Net.WebUtility which is available in both .NET Framework and .NET Core.
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
    
    return [System.Net.WebUtility]::HtmlEncode($Text)
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
    <#
    .SYNOPSIS
        Connects to Microsoft 365 services using the connection module.
    .DESCRIPTION
        Loads the Connect-Services module and orchestrates connection to
        Microsoft Graph and Exchange Online.
    #>
    
    # Load connection module
    $connectionModulePath = Join-Path $PSScriptRoot "modules\Core\Connect-Services.ps1"
    if (Test-Path $connectionModulePath) {
        . $connectionModulePath
    } else {
        Write-Warning "Connection module not found at: $connectionModulePath"
        throw "Required module not found: Connect-Services.ps1"
    }
    
    $script:TenantInfo = Connect-AllM365Services `
        -AuthMethod $AuthMethod `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -CertificateThumbprint $CertificateThumbprint `
        -ClientSecret $ClientSecret `
        -NoAuth:$NoAuth
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
    <#
    .SYNOPSIS
        Orchestrates export of assessment results to all configured formats.
    
    .DESCRIPTION
        Generates JSON, CSV, and HTML reports using the Export-Reports module.
        Handles all export operations including detailed CSV reports and CIS compliance exports.
    #>
    Write-Step "Generating assessment reports..."
    
    # Load export module
    $exportModulePath = Join-Path $PSScriptRoot "modules\Core\Export-Reports.ps1"
    if (Test-Path $exportModulePath) {
        . $exportModulePath
    } else {
        Write-Warning "Export module not found at: $exportModulePath"
        return
    }
    
    # Load CIS compliance module for export functions
    $cisModulePath = Join-Path $PSScriptRoot "modules\Core\Get-CISCompliance.ps1"
    if (Test-Path $cisModulePath) {
        . $cisModulePath
    }

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $basePath = Join-Path $OutputPath "M365Guardian_$timestamp"

    # JSON Export
    if ($OutputFormat -in @('All', 'JSON')) {
        $jsonPath = Export-JsonReport -Results $script:AssessmentResults `
            -OutputPath $basePath `
            -TenantInfo $script:TenantInfo `
            -SecurityScore $script:SecurityScore
        Write-Success "JSON report: $jsonPath"
        
        # Export security score details separately
        if ($script:SecurityScore) {
            $scorePath = Export-SecurityScoreJson -SecurityScore $script:SecurityScore -OutputPath $basePath
            Write-Success "Security Score details: $scorePath"
        }
    }

    # CSV Export
    if ($OutputFormat -in @('All', 'CSV')) {
        $csvPath = Export-CsvReport -Results $script:AssessmentResults -OutputPath $basePath
        Write-Success "CSV report: $csvPath"
        
        # Export detailed CSVs
        $detailedExports = Export-DetailedCsvReports -Results $script:AssessmentResults -OutputPath $basePath
        
        foreach ($exportType in $detailedExports.Keys) {
            $export = $detailedExports[$exportType]
            Write-Success "$($exportType -replace '([A-Z])', ' $1'.Trim()) CSV: $($export.Path)"
            Write-Info "  → $($export.Count) record(s) exported"
        }
        
        # Export CIS Compliance reports
        if ($script:CISCompliance) {
            Export-CISComplianceReport -ComplianceSummary $script:CISCompliance -OutputPath $basePath -Format @('JSON', 'CSV')
            Write-Info "  → $($script:CISCompliance.TotalControls) CIS controls assessed"
        }
    }

    # HTML Export
    if ($OutputFormat -in @('All', 'HTML')) {
        $templatePath = Join-Path $PSScriptRoot "templates\report-template.html"
        $htmlPath = "${basePath}.html"
        
        Export-HtmlReport -Results $script:AssessmentResults `
            -OutputPath $htmlPath `
            -TenantInfo $script:TenantInfo `
            -SecurityScore $script:SecurityScore `
            -BaselineComparison $script:BaselineComparison `
            -TemplatePath $templatePath
        
        Write-Success "HTML report: $htmlPath"
    }

    # Restrict file permissions on generated reports
    Protect-ReportFiles -Path $OutputPath -Recurse
    Write-Verbose "Report file permissions restricted to current user and Administrators"
}

#endregion

#region Helper Functions

function Get-HTMLTemplate {
    <#
    .SYNOPSIS
        Loads the HTML report template from an external file.
    
    .DESCRIPTION
        Retrieves the HTML template used for generating security assessment reports.
        The template is loaded from templates/report-template.html for easier maintenance.
        Falls back to an error message if the template file is not found.
    
    .OUTPUTS
        String containing the HTML template with placeholders for report data.
    #>
    
    $templatePath = Join-Path $PSScriptRoot "templates\report-template.html"
    
    if (Test-Path $templatePath) {
        return Get-Content -Path $templatePath -Raw -Encoding UTF8
    }
    else {
        Write-Warning "HTML template not found at: $templatePath"
        # Return a minimal fallback template
        return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>M365 Security Guardian Report - {{TENANT_NAME}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 40px; }
        .error { color: #d13438; background: #fde7e9; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="error">
        <h1>Template Not Found</h1>
        <p>The HTML report template file was not found at: templates/report-template.html</p>
        <p>Please ensure the template file exists in the correct location.</p>
    </div>
</body>
</html>
'@
    }
}

#endregion

#region Post-Assessment Functions

function Disconnect-M365Services {
    # Delegates to module function (loaded during Connect-M365Services)
    if (Get-Command Disconnect-AllM365Services -ErrorAction SilentlyContinue) {
        Disconnect-AllM365Services
    } else {
        # Fallback if module wasn't loaded (e.g., connection failed early)
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }
}

function Invoke-SecurityScoring {
    Write-Step "Calculating Tenant Security Score..."
    
    # Load the scoring module
    $scoringModulePath = Join-Path $PSScriptRoot "modules\Core\Get-TenantSecurityScore.ps1"
    
    if (Test-Path $scoringModulePath) {
        try {
            . $scoringModulePath
            
            $script:SecurityScore = Get-TenantSecurityScore -AssessmentResults $script:AssessmentResults -Config $script:Config
            
            # Display score in console if enabled
            $displayScore = if ($null -ne $script:Config.Scoring.DisplayInConsole) { 
                $script:Config.Scoring.DisplayInConsole 
            } else { $true }
            
            if ($displayScore) {
                Format-SecurityScoreDisplay -ScoreData $script:SecurityScore
            }
            
            Write-Success "Security Score calculated: $($script:SecurityScore.OverallScore)% (Grade: $($script:SecurityScore.LetterGrade))"
        }
        catch {
            Write-Warning "Could not calculate security score: $_"
        }
    }
    else {
        Write-Info "Security scoring module not found. Skipping score calculation."
    }
}

function Invoke-CISCompliance {
    Write-Step "Mapping findings to CIS Microsoft 365 Benchmark..."
    
    # Load the CIS compliance module
    $cisModulePath = Join-Path $PSScriptRoot "modules\Core\Get-CISCompliance.ps1"
    
    if (Test-Path $cisModulePath) {
        try {
            . $cisModulePath
            
            # Initialize the benchmark mapping
            $cisConfigPath = Join-Path $PSScriptRoot "config\cis-benchmark-mapping.json"
            Initialize-CISBenchmark -ConfigPath $cisConfigPath | Out-Null
            
            # Generate compliance summary
            $script:CISCompliance = Get-CISComplianceSummary -AssessmentResults $script:AssessmentResults
            
            if ($script:CISCompliance) {
                # Display compliance summary in console
                $displayCIS = if ($null -ne $script:Config.CISBenchmark.DisplayInConsole) { 
                    $script:Config.CISBenchmark.DisplayInConsole 
                } else { $true }
                
                if ($displayCIS) {
                    $complianceDisplay = Format-CISComplianceReport -ComplianceSummary $script:CISCompliance
                    Write-Information $complianceDisplay -InformationAction Continue
                }
                
                Write-Success "CIS Compliance: Level 1 = $($script:CISCompliance.Level1.Percentage)%, Level 2 = $($script:CISCompliance.Level2.Percentage)%"
            }
        }
        catch {
            Write-Warning "Could not generate CIS compliance mapping: $_"
            Write-Verbose $_.ScriptStackTrace
        }
    }
    else {
        Write-Info "CIS compliance module not found. Skipping benchmark mapping."
    }
}

function Invoke-BaselineComparison {
    # Load the baseline comparison module
    $baselineModulePath = Join-Path $PSScriptRoot "modules\Core\Compare-Baseline.ps1"
    
    if (-not (Test-Path $baselineModulePath)) {
        Write-Info "Baseline comparison module not found."
        return
    }
    
    try {
        . $baselineModulePath
        
        # Ensure baselines directory exists
        if (-not (Test-Path $BaselinePath)) {
            New-Item -ItemType Directory -Path $BaselinePath -Force | Out-Null
        }
        
        # Save baseline if requested
        if ($SaveBaseline) {
            Write-Step "Saving assessment as baseline..."
            
            $baselineFilePath = Join-Path $BaselinePath "$($BaselineName -replace '[^\w\-]', '_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            
            # Build CIS compliance object for baseline
            $cisForBaseline = $null
            if ($script:CISCompliance) {
                $cisForBaseline = [PSCustomObject]@{
                    Level1Percentage = $script:CISCompliance.Level1.Percentage
                    Level2Percentage = $script:CISCompliance.Level2.Percentage
                    Level1Compliant = $script:CISCompliance.Level1.Compliant
                    Level1Total = $script:CISCompliance.Level1.Total
                    Level2Compliant = $script:CISCompliance.Level2.Compliant
                    Level2Total = $script:CISCompliance.Level2.Total
                }
            }
            
            # Build security score object for baseline
            $scoreForBaseline = $null
            if ($script:SecurityScore) {
                $scoreForBaseline = [PSCustomObject]@{
                    Score = $script:SecurityScore.OverallScore
                    Grade = $script:SecurityScore.LetterGrade
                    CategoryScores = $script:SecurityScore.CategoryDetails | ForEach-Object {
                        [PSCustomObject]@{
                            Category = $_.Category
                            Score = $_.Score
                            Weight = $_.Weight
                        }
                    }
                }
            }
            
            $saveResult = Save-AssessmentBaseline `
                -Results $script:AssessmentResults `
                -SecurityScore $scoreForBaseline `
                -CISCompliance $cisForBaseline `
                -BaselinePath $baselineFilePath `
                -BaselineName $BaselineName `
                -TenantId $script:TenantId
            
            if ($saveResult.Success) {
                Write-Success "Baseline saved: $($saveResult.Path)"
                Write-Info "  → $($saveResult.CheckCount) checks saved"
                $script:BaselineSaved = $true
                $script:BaselineSavePath = $saveResult.Path
            }
            else {
                Write-Warning "Failed to save baseline: $($saveResult.Error)"
            }
        }
        
        # Compare against baseline if one is specified or available
        $effectiveBaseline = if ($CompareToBaseline) { $CompareToBaseline } else { Get-LatestBaseline -BaselinePath $BaselinePath }
        
        if ($effectiveBaseline -and (Test-Path $effectiveBaseline)) {
            Write-Step "Comparing against baseline: $(Split-Path $effectiveBaseline -Leaf)"
            
            # Load the baseline data
            $baselineResult = Get-AssessmentBaseline -BaselinePath $effectiveBaseline
            if ($baselineResult.Success) {
                $script:BaselineComparison = Compare-AssessmentToBaseline `
                    -CurrentResults $script:AssessmentResults `
                    -CurrentSecurityScore $script:SecurityScore `
                    -CurrentCISCompliance $script:CISCompliance `
                    -Baseline $baselineResult.Baseline
            }
            else {
                Write-Warning "Could not load baseline: $($baselineResult.Error)"
            }
            
            if ($script:BaselineComparison) {
                # Display comparison summary
                $comparisonReport = Format-BaselineComparison -Comparison $script:BaselineComparison
                Write-Information $comparisonReport -InformationAction Continue
                
                $improved = $script:BaselineComparison.Improved.Count
                $regressed = $script:BaselineComparison.Regressed.Count
                $new = $script:BaselineComparison.NewChecks.Count
                $removed = $script:BaselineComparison.RemovedChecks.Count
                
                $summaryParts = @()
                if ($improved -gt 0) { $summaryParts += "$improved improved" }
                if ($regressed -gt 0) { $summaryParts += "$regressed regressed" }
                if ($new -gt 0) { $summaryParts += "$new new" }
                if ($removed -gt 0) { $summaryParts += "$removed removed" }
                
                $summaryText = $summaryParts -join ', '
                if ($summaryText) {
                    if ($regressed -gt $improved) {
                        Write-Warning "Baseline comparison: $summaryText"
                    } else {
                        Write-Success "Baseline comparison: $summaryText"
                    }
                } else {
                    Write-Info "No significant changes from baseline"
                }
            }
        }
    }
    catch {
        Write-Warning "Baseline comparison failed: $_"
        Write-Verbose $_.ScriptStackTrace
    }
}

function Show-Summary {
    $duration = (Get-Date) - $script:StartTime
    
    # Build score summary if available
    $scoreInfo = ""
    if ($script:SecurityScore) {
        $scoreInfo = @"

Security Score: $($script:SecurityScore.OverallScore)% | Grade: $($script:SecurityScore.LetterGrade)
$($script:SecurityScore.GradeDescription)
"@
    }
    
    # Build CIS compliance summary if available
    $cisInfo = ""
    if ($script:CISCompliance) {
        $cisInfo = @"

CIS Benchmark: Level 1 = $($script:CISCompliance.Level1.Percentage)% | Level 2 = $($script:CISCompliance.Level2.Percentage)%
"@
    }
    
    $summary = @"

╔══════════════════════════════════════════════════════════════════════╗
║                    Assessment Complete! ✓                            ║
╚══════════════════════════════════════════════════════════════════════╝

Execution Time: $($duration.Minutes)m $($duration.Seconds)s
Total Checks: $($script:AssessmentResults.Count)$scoreInfo$cisInfo

"@
    Write-Information $summary -InformationAction Continue
}

#endregion

#region Main Execution

# Load connection module and clean up any existing connections
$connectionModulePath = Join-Path $PSScriptRoot "modules\Core\Connect-Services.ps1"
if (Test-Path $connectionModulePath) {
    . $connectionModulePath
}
Clear-ExistingM365Connections

try {
    Write-Banner
    Load-Configuration
    Connect-M365Services
    Invoke-AssessmentModules
    Invoke-SecurityScoring
    Invoke-CISCompliance
    Invoke-BaselineComparison
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
    # Clean up WAM broker override so it doesn't affect other processes
    Remove-Item env:AZURE_IDENTITY_DISABLE_BROKER -ErrorAction SilentlyContinue
}

#endregion
