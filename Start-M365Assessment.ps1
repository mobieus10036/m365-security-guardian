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
    Uses device code flow for multi-tenant assessment (recommended for consultants).

.EXAMPLE
    .\Start-M365Assessment.ps1 -AuthMethod Certificate -ClientId "app-id" -TenantId "tenant-id" -CertificateThumbprint "thumbprint"
    Uses certificate-based auth for automated/scheduled assessments.

.EXAMPLE
    .\Start-M365Assessment.ps1 -AuthMethod ManagedIdentity -ClientId "managed-identity-client-id"
    Uses managed identity when running from Azure VM or Azure Functions.

.NOTES
    Project: M365 Assessment Toolkit
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

# Auto-load auth config if exists and no auth method specified
$authConfigPath = Join-Path $PSScriptRoot ".auth-config.ps1"
if ((Test-Path $authConfigPath) -and ($AuthMethod -eq 'DeviceCode') -and (-not $ClientId)) {
    Write-Verbose "Loading saved authentication configuration..."
    . $authConfigPath
    if ($AuthConfig) {
        $AuthMethod = $AuthConfig.AuthMethod
        $ClientId = $AuthConfig.ClientId
        $TenantId = $AuthConfig.TenantId
        $CertificateThumbprint = $AuthConfig.CertificateThumbprint
        Write-Verbose "Using saved auth: $AuthMethod"
    }
}

#region Helper Functions

function Write-Banner {
    $banner = @"

╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║           Microsoft 365 Assessment Toolkit v3.1.0                    ║
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
    Write-Info "Authentication method: $AuthMethod"

    # Microsoft Graph
    try {
        Write-Information "  → Connecting to Microsoft Graph..." -InformationAction Continue
        
        # Scopes for delegated (user) authentication
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
        
        # Build connection parameters based on auth method
        $connectParams = @{
            NoWelcome = $true
            ErrorAction = 'Stop'
        }
        
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        
        switch ($AuthMethod) {
            'DeviceCode' {
                # Device code flow - best for terminal/console use
                # User sees a code and URL, authenticates in any browser
                Write-Info "Using Device Code flow - follow the prompts below"
                $connectParams['UseDeviceCode'] = $true
                $connectParams['Scopes'] = $graphScopes
            }
            
            'Interactive' {
                # Interactive browser - may trigger WAM on Windows
                Write-Info "Using Interactive browser authentication"
                $connectParams['Scopes'] = $graphScopes
            }
            
            'Certificate' {
                # Certificate-based auth for automation
                if (-not $ClientId) {
                    throw "ClientId is required for Certificate authentication"
                }
                if (-not $CertificateThumbprint) {
                    throw "CertificateThumbprint is required for Certificate authentication"
                }
                if (-not $TenantId) {
                    throw "TenantId is required for Certificate authentication"
                }
                Write-Info "Using Certificate-based authentication (App-only)"
                $connectParams['ClientId'] = $ClientId
                $connectParams['CertificateThumbprint'] = $CertificateThumbprint
            }
            
            'ClientSecret' {
                # Client secret auth for automation
                if (-not $ClientId) {
                    throw "ClientId is required for ClientSecret authentication"
                }
                if (-not $ClientSecret) {
                    throw "ClientSecret is required for ClientSecret authentication"
                }
                if (-not $TenantId) {
                    throw "TenantId is required for ClientSecret authentication"
                }
                Write-Info "Using Client Secret authentication (App-only)"
                $connectParams['ClientId'] = $ClientId
                $connectParams['ClientSecretCredential'] = (New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret))
            }
            
            'ManagedIdentity' {
                # Managed Identity for Azure-hosted workloads
                Write-Info "Using Managed Identity authentication"
                $connectParams['Identity'] = $true
                if ($ClientId) {
                    # User-assigned managed identity
                    $connectParams['ClientId'] = $ClientId
                    Write-Info "Using User-Assigned Managed Identity: $ClientId"
                } else {
                    Write-Info "Using System-Assigned Managed Identity"
                }
            }
        }
        
        Connect-MgGraph @connectParams
        
        # Validate connection by attempting to get context
        $mgContext = Get-MgContext
        if (-not $mgContext) {
            throw "Failed to establish Microsoft Graph connection - no context returned"
        }
        
        # Validate the connection is actually working by making a simple API call
        # This catches cases where Connect-MgGraph appears to succeed but token is invalid
        try {
            $null = Get-MgOrganization -ErrorAction Stop
        }
        catch {
            # If the first call fails, the token might be stale - try reconnecting once
            Write-Warning "  ⚠ Initial connection validation failed, retrying..."
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 2
            Connect-MgGraph @connectParams
            $mgContext = Get-MgContext
        }
        
        Write-Success "Connected to Microsoft Graph"
        
        # Show connection context so user knows which identity/tenant is being used
        Write-Info "Connected as: $($mgContext.Account)"
        Write-Info "Tenant ID: $($mgContext.TenantId)"
        Write-Info "Auth Type: $($mgContext.AuthType)"
        
        # Validate that requested scopes were granted (for delegated auth only)
        if ($AuthMethod -in @('DeviceCode', 'Interactive')) {
            $grantedScopes = $mgContext.Scopes
            $missingScopes = $graphScopes | Where-Object { $grantedScopes -notcontains $_ }
            if ($missingScopes.Count -gt 0) {
                Write-Warning "  ⚠ Some permissions were not granted: $($missingScopes -join ', ')"
                Write-Warning "  ⚠ Certain checks may fail or return incomplete data"
                Write-Warning "  ⚠ Re-consent may be required if checks fail unexpectedly"
            }
        } elseif ($AuthMethod -in @('Certificate', 'ClientSecret', 'ManagedIdentity')) {
            Write-Info "App-only auth: Ensure the app registration has required API permissions with admin consent"
        }
        
        # Get tenant info (already validated during connection check above)
        $script:TenantInfo = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($script:TenantInfo) {
            Write-Info "Tenant: $($script:TenantInfo.DisplayName)"
        }
        
    }
    catch {
        Write-Failure "Failed to connect to Microsoft Graph: $_"
        throw
    }

    # Exchange Online (optional - some checks)
    try {
        Write-Information "  → Connecting to Exchange Online..." -InformationAction Continue
        
        # Check if already connected to Exchange Online
        try {
            $exoTest = Get-OrganizationConfig -ErrorAction Stop
            Write-Success "Already connected to Exchange Online"
            return  # Skip connection if already connected
        } catch {
            # Not connected, proceed with connection
        }
        
        # Note: Exchange Online requires separate authentication from Microsoft Graph
        # This is by design - the services use different auth libraries
        if ($AuthMethod -eq 'DeviceCode') {
            Write-Info "Exchange Online requires a separate device code (Microsoft limitation)"
        }
        
        # Build Exchange connection parameters
        $exoParams = @{
            ShowBanner = $false
            ErrorAction = 'Stop'
        }
        
        if ($TenantId) {
            $exoParams['Organization'] = $TenantId
        }
        
        # Always use device authentication to avoid WAM broker issues in VS Code/terminal
        # WAM broker can fail in non-standard terminal environments
        # For ManagedIdentity, use the -ManagedIdentity flag instead
        if ($AuthMethod -eq 'ManagedIdentity') {
            $exoParams['ManagedIdentity'] = $true
            if ($ClientId) {
                $exoParams['ManagedIdentityAccountId'] = $ClientId
            }
        } else {
            # Device code works reliably in all terminal environments
            $exoParams['Device'] = $true
        }
        
        Connect-ExchangeOnline @exoParams
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
    $baseFileName = "M365Guardian_$timestamp"

    # JSON Export (includes security score)
    if ($OutputFormat -in @('All', 'JSON')) {
        $jsonPath = Join-Path $OutputPath "$baseFileName.json"
        
        # Build comprehensive export object with score
        $exportData = @{
            AssessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            TenantId = if ($script:TenantInfo) { $script:TenantInfo.Id } else { (Get-MgContext).TenantId }
            TenantName = if ($script:TenantInfo) { $script:TenantInfo.DisplayName } else { "Unknown" }
            SecurityScore = if ($script:SecurityScore) {
                @{
                    OverallScore = $script:SecurityScore.OverallScore
                    LetterGrade = $script:SecurityScore.LetterGrade
                    GradeDescription = $script:SecurityScore.GradeDescription
                    PotentialScore = $script:SecurityScore.PotentialScore
                    CategoryBreakdown = $script:SecurityScore.CategoryBreakdown
                    TopPriorities = $script:SecurityScore.TopPriorities
                    QuickWins = $script:SecurityScore.QuickWins
                    Summary = $script:SecurityScore.Summary
                }
            } else { $null }
            Findings = $script:AssessmentResults
        }
        
        $exportData | ConvertTo-Json -Depth 15 | Out-File $jsonPath -Encoding UTF8
        Write-Success "JSON report: $jsonPath"
        
        # Export security score summary to separate file
        if ($script:SecurityScore) {
            $scorePath = Join-Path $OutputPath "$($baseFileName)_SecurityScore.json"
            $script:SecurityScore | ConvertTo-Json -Depth 10 | Out-File $scorePath -Encoding UTF8
            Write-Success "Security Score details: $scorePath"
        }
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

        # Export privileged accounts to separate CSV with full risk context
        $privAccountResult = $script:AssessmentResults | Where-Object { $_.CheckName -eq "Privileged Account Security" -and $_.PrivilegedAccounts }
        if ($privAccountResult -and $privAccountResult.PrivilegedAccounts.Count -gt 0) {
            $privAccountsCsvPath = Join-Path $OutputPath "$($baseFileName)_PrivilegedAccounts.csv"
            # Export with all risk context fields
            $privAccountResult.PrivilegedAccounts | Select-Object `
                UserPrincipalName, `
                DisplayName, `
                RiskLevel, `
                RiskScore, `
                HighestRiskRole, `
                Roles, `
                RoleCount, `
                @{Name='HasMFA';Expression={if($_.HasMFA){'Yes'}else{'No'}}}, `
                LastSignIn, `
                LastSignInDaysAgo, `
                @{Name='IsStale';Expression={if($_.IsStale){'Yes'}else{'No'}}}, `
                AccountType, `
                RiskFactors, `
                RiskFactorCount | 
                Export-Csv -Path $privAccountsCsvPath -NoTypeInformation -Encoding UTF8
            Write-Success "Privileged accounts CSV: $privAccountsCsvPath"
            Write-Info "  → $($privAccountResult.PrivilegedAccounts.Count) privileged account(s) with risk context exported"
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
        
        # Export CIS Compliance reports
        if ($script:CISCompliance) {
            $cisBasePath = Join-Path $OutputPath $baseFileName
            Export-CISComplianceReport -ComplianceSummary $script:CISCompliance -OutputPath $cisBasePath -Format @('JSON', 'CSV')
            Write-Info "  → $($script:CISCompliance.TotalControls) CIS controls assessed"
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
        
        # For Conditional Access, show the issues table at the top before policy list
        if ($result.CheckName -eq "Conditional Access Policies" -and $result.Findings -and $result.Findings.Count -gt 0) {
            # Override the message with a cleaner summary
            $findingContent = "<strong>$($result.Details.EnabledPolicies) enabled policies analyzed.</strong>"
            
            # Show posture score if available
            if ($null -ne $result.ConditionalAccessScore) {
                $findingContent += " CA Posture Score: <strong>$($result.ConditionalAccessScore)%</strong> of policies have no flagged risks."
            }
            
            # Count by severity
            $criticalCount = ($result.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highCount = ($result.Findings | Where-Object { $_.Severity -eq 'High' }).Count
            $mediumCount = ($result.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            
            $findingContent += "<br><br><div style='background: #fdf6ec; border-left: 4px solid #ffb900; padding: 12px; margin: 10px 0; border-radius: 4px;'>"
            $findingContent += "<strong style='font-size: 14px;'>⚠ $($result.Findings.Count) Security Gaps Identified</strong>"
            if ($criticalCount -gt 0 -or $highCount -gt 0) {
                $findingContent += "<span style='margin-left: 15px;'>"
                if ($criticalCount -gt 0) { $findingContent += "<span style='color: #a4262c; font-weight: 600;'>$criticalCount Critical</span> " }
                if ($highCount -gt 0) { $findingContent += "<span style='color: #d13438; font-weight: 600;'>$highCount High</span> " }
                if ($mediumCount -gt 0) { $findingContent += "<span style='color: #8a6b0f; font-weight: 600;'>$mediumCount Medium</span>" }
                $findingContent += "</span>"
            }
            $findingContent += "</div>"
            
            # Issues table
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300); width: 90px;'>Severity</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Security Gap</td></tr>"
            
            # Sort by severity (Critical > High > Medium > Low)
            $severityOrder = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }
            $sortedFindings = $result.Findings | Sort-Object { $severityOrder[$_.Severity] }
            
            foreach ($finding in $sortedFindings) {
                $findingMsgSafe = ConvertTo-HtmlSafe $finding.Message
                $findingSeveritySafe = ConvertTo-HtmlSafe $finding.Severity
                $severityColor = switch ($finding.Severity) {
                    'Critical' { '#a4262c' }
                    'High' { '#d13438' }
                    'Medium' { '#8a6b0f' }
                    'Low' { '#0078d4' }
                    default { 'var(--gray-700)' }
                }
                $severityBg = switch ($finding.Severity) {
                    'Critical' { '#fde7e9' }
                    'High' { '#fed9cc' }
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
        
        # Handle Legacy Auth block policies (with links)
        if ($result.BlockPolicies -and $result.BlockPolicies.Count -gt 0) {
            $caPortalBase = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade/~/policyId/"
            $findingContent += "<br><br><strong>Legacy Auth Block Policies ($($result.BlockPolicies.Count)):</strong><br>"
            $findingContent += "<ul>"
            foreach ($policy in $result.BlockPolicies) {
                $policyNameSafe = ConvertTo-HtmlSafe $policy.DisplayName
                $policyIdSafe = ConvertTo-HtmlSafe $policy.Id
                $policyLink = "$caPortalBase$policyIdSafe"
                $findingContent += "<li><code>$policyNameSafe</code>"
                $findingContent += " <a href='$policyLink' target='_blank' style='margin-left:6px; font-size:12px;'>Open in Entra</a>"
                $findingContent += " <span style='color: var(--gray-700); font-size: 12px;'>ID: <code>$policyIdSafe</code></span>"
                $findingContent += "</li>"
            }
            $findingContent += "</ul>"
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

        # Handle per-policy Conditional Access analysis (risks/opportunities)
        # Note: Security gaps table is already shown at the top for CA findings
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
        
        # Handle Email Security Configuration details
        if ($result.CheckName -eq "Email Security Configuration" -and $result.Findings -and $result.Findings.Count -gt 0) {
            $findingContent += "<br><br><strong>Email Security Settings:</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Protection Layer</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Status</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Risk Level</td></tr>"
            
            foreach ($finding in $result.Findings) {
                $settingSafe = ConvertTo-HtmlSafe $finding.Setting
                $valueSafe = ConvertTo-HtmlSafe $finding.Value
                $riskSafe = ConvertTo-HtmlSafe $finding.Risk
                $riskColor = switch ($finding.Risk) {
                    'High' { 'var(--danger-color)' }
                    'Medium' { 'var(--warning-color)' }
                    'Low' { 'var(--success-color)' }
                    default { 'var(--gray-700)' }
                }
                $statusIcon = switch ($finding.Value) {
                    { $_ -like 'Enabled*' } { '✅' }
                    'Not Configured' { '❌' }
                    default { '⚪' }
                }
                $riskIcon = switch ($finding.Risk) {
                    'High' { '🔴' }
                    'Medium' { '🟡' }
                    'Low' { '🟢' }
                    default { '⚪' }
                }
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$settingSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$statusIcon <code>$valueSafe</code></td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $riskColor; font-weight: 600;'>$riskIcon $riskSafe</td></tr>"
            }
            $findingContent += "</table>"
            
            # Display issues as a bulleted list
            if ($result.Issues -and $result.Issues.Count -gt 0) {
                $findingContent += "<br><strong>Issues Identified ($($result.Issues.Count)):</strong><br>"
                $findingContent += "<ul style='margin: 8px 0 0 0; padding-left: 20px;'>"
                foreach ($issue in $result.Issues) {
                    $issueSafe = ConvertTo-HtmlSafe $issue
                    $findingContent += "<li style='color: var(--warning-color); margin-bottom: 4px;'>$issueSafe</li>"
                }
                $findingContent += "</ul>"
            }
        }
        
        # Handle External Sharing configuration details
        if ($result.CheckName -eq "External Sharing Configuration" -and $result.Findings -and $result.Findings.Count -gt 0) {
            $findingContent += "<br><br><strong>External Sharing Settings Analysis:</strong><br>"
            $findingContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
            $findingContent += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Setting</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Current Value</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Risk Level</td></tr>"
            
            foreach ($finding in $result.Findings) {
                $settingSafe = ConvertTo-HtmlSafe $finding.Setting
                $valueSafe = ConvertTo-HtmlSafe $finding.Value
                $riskSafe = ConvertTo-HtmlSafe $finding.Risk
                $riskColor = switch ($finding.Risk) {
                    'High' { 'var(--danger-color)' }
                    'Medium' { 'var(--warning-color)' }
                    'Low' { 'var(--success-color)' }
                    default { 'var(--gray-700)' }
                }
                $riskIcon = switch ($finding.Risk) {
                    'High' { '🔴' }
                    'Medium' { '🟡' }
                    'Low' { '🟢' }
                    default { '⚪' }
                }
                $findingContent += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$settingSafe</td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$valueSafe</code></td>"
                $findingContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $riskColor; font-weight: 600;'>$riskIcon $riskSafe</td></tr>"
            }
            $findingContent += "</table>"
            
            # Display issues as a bulleted list
            if ($result.Issues -and $result.Issues.Count -gt 0) {
                $findingContent += "<br><strong>Issues Identified ($($result.Issues.Count)):</strong><br>"
                $findingContent += "<ul style='margin: 8px 0 0 0; padding-left: 20px;'>"
                foreach ($issue in $result.Issues) {
                    $issueSafe = ConvertTo-HtmlSafe $issue
                    $findingContent += "<li style='color: var(--warning-color); margin-bottom: 4px;'>$issueSafe</li>"
                }
                $findingContent += "</ul>"
            }
        }
        elseif ($result.SharingCapability) {
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
    
    # Build security score HTML section
    $securityScoreHtml = ""
    if ($script:SecurityScore) {
        $score = $script:SecurityScore
        $gradeClass = switch ($score.LetterGrade) {
            "A" { "grade-a" }
            "B" { "grade-b" }
            "C" { "grade-c" }
            "D" { "grade-d" }
            default { "grade-f" }
        }
        
        # Build category breakdown
        $categoryHtml = ""
        foreach ($cat in $score.CategoryBreakdown) {
            $catGradeClass = switch ($cat.Grade) {
                "A" { "grade-a" }
                "B" { "grade-b" }
                "C" { "grade-c" }
                "D" { "grade-d" }
                default { "grade-f" }
            }
            $categoryHtml += @"
            <div class="score-category">
                <div class="score-category-name">$(ConvertTo-HtmlSafe $cat.Category)</div>
                <div class="score-category-bar">
                    <div class="score-category-fill $catGradeClass" style="width: $($cat.Score)%"></div>
                </div>
                <div class="score-category-value">$($cat.Score)%</div>
            </div>
"@
        }
        
        # Build priorities list
        $prioritiesHtml = ""
        if ($score.TopPriorities.Count -gt 0) {
            $prioritiesHtml = "<div class='priorities-section'><h4>🎯 Top Priorities</h4><ul>"
            foreach ($priority in $score.TopPriorities) {
                $prioritiesHtml += "<li><span class='priority-severity $($priority.Severity.ToLower())'>$($priority.Severity)</span> $(ConvertTo-HtmlSafe $priority.CheckName) <span class='priority-gain'>+$($priority.PotentialGain) pts</span></li>"
            }
            $prioritiesHtml += "</ul></div>"
        }
        
        # Build quick wins list
        $quickWinsHtml = ""
        if ($score.QuickWins.Count -gt 0) {
            $quickWinsHtml = "<div class='quickwins-section'><h4>⚡ Quick Wins</h4><ul>"
            foreach ($win in $score.QuickWins) {
                $quickWinsHtml += "<li>$(ConvertTo-HtmlSafe $win.CheckName) <span class='priority-gain'>+$($win.PotentialGain) pts</span></li>"
            }
            $quickWinsHtml += "</ul></div>"
        }
        
        $securityScoreHtml = @"
        <div class="security-score-dashboard">
            <h2 class="summary-title">🛡️ Tenant Security Score</h2>
            <div class="score-main-display">
                <div class="score-circle $gradeClass">
                    <div class="score-value">$($score.OverallScore)%</div>
                    <div class="score-grade">Grade: $($score.LetterGrade)</div>
                </div>
                <div class="score-details">
                    <div class="score-description">$(ConvertTo-HtmlSafe $score.GradeDescription)</div>
                    <div class="score-potential">
                        <span class="potential-label">Potential Score:</span>
                        <span class="potential-value">$($score.PotentialScore)%</span>
                        <span class="potential-gain">(+$($score.PotentialImprovement) pts available)</span>
                    </div>
                </div>
            </div>
            <div class="score-categories">
                <h3>Category Breakdown</h3>
                $categoryHtml
            </div>
            <div class="score-actions-grid">
                $prioritiesHtml
                $quickWinsHtml
            </div>
        </div>
"@
    }
    
    # Build baseline comparison HTML section
    $baselineComparisonHtml = ""
    if ($script:BaselineComparison) {
        $comparison = $script:BaselineComparison
        
        # Determine trend styling
        $trendClass = switch ($comparison.OverallTrend) {
            "Improving" { "improving" }
            "Declining" { "declining" }
            default { "stable" }
        }
        $trendIcon = switch ($comparison.OverallTrend) {
            "Improving" { "📈" }
            "Declining" { "📉" }
            default { "➡️" }
        }
        
        # Format baseline date - use correct property names from comparison object
        $baselineDate = if ($comparison.BaselineDate) {
            try { [datetime]::Parse($comparison.BaselineDate).ToString("yyyy-MM-dd HH:mm") } catch { $comparison.BaselineDate }
        } else { "Unknown" }
        $baselineName = if ($comparison.BaselineName) { ConvertTo-HtmlSafe $comparison.BaselineName } else { "Baseline" }
        
        # Score delta formatting - use SecurityScoreComparison
        $scoreDelta = if ($comparison.SecurityScoreComparison) { $comparison.SecurityScoreComparison.Delta } else { 0 }
        $scoreDeltaClass = if ($scoreDelta -gt 0) { "positive" } elseif ($scoreDelta -lt 0) { "negative" } else { "neutral" }
        $scoreDeltaSign = if ($scoreDelta -gt 0) { "+" } else { "" }
        
        $currentScore = if ($comparison.SecurityScoreComparison -and $null -ne $comparison.SecurityScoreComparison.CurrentScore) { "$($comparison.SecurityScoreComparison.CurrentScore)%" } else { "N/A" }
        $baselineScore = if ($comparison.SecurityScoreComparison -and $null -ne $comparison.SecurityScoreComparison.BaselineScore) { "$($comparison.SecurityScoreComparison.BaselineScore)%" } else { "N/A" }
        
        # CIS compliance deltas - use CISComplianceComparison
        $cisL1Delta = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level1) { $comparison.CISComplianceComparison.Level1.Delta } else { 0 }
        $cisL2Delta = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level2) { $comparison.CISComplianceComparison.Level2.Delta } else { 0 }
        $cisL1DeltaClass = if ($cisL1Delta -gt 0) { "positive" } elseif ($cisL1Delta -lt 0) { "negative" } else { "neutral" }
        $cisL2DeltaClass = if ($cisL2Delta -gt 0) { "positive" } elseif ($cisL2Delta -lt 0) { "negative" } else { "neutral" }
        $cisL1DeltaSign = if ($cisL1Delta -gt 0) { "+" } else { "" }
        $cisL2DeltaSign = if ($cisL2Delta -gt 0) { "+" } else { "" }
        
        $currentL1 = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level1 -and $null -ne $comparison.CISComplianceComparison.Level1.Current) { "$($comparison.CISComplianceComparison.Level1.Current)%" } else { "N/A" }
        $currentL2 = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level2 -and $null -ne $comparison.CISComplianceComparison.Level2.Current) { "$($comparison.CISComplianceComparison.Level2.Current)%" } else { "N/A" }
        
        # Build improvements list - use PreviousStatus instead of BaselineStatus
        $improvementsHtml = ""
        if ($comparison.Improvements -and $comparison.Improvements.Count -gt 0) {
            $improvementsHtml = "<ul class='baseline-change-list'>"
            foreach ($imp in $comparison.Improvements) {
                $checkNameSafe = ConvertTo-HtmlSafe $imp.CheckName
                $improvementsHtml += @"
                <li class='baseline-change-item'>
                    <span class='baseline-change-name'>$checkNameSafe</span>
                    <span class='baseline-change-status'>
                        <span style='color: #d13438;'>$($imp.PreviousStatus)</span>
                        →
                        <span style='color: #107c10;'>$($imp.CurrentStatus)</span>
                    </span>
                </li>
"@
            }
            $improvementsHtml += "</ul>"
        } else {
            $improvementsHtml = "<div class='baseline-empty'>No improvements detected</div>"
        }
        
        # Build regressions list - use PreviousStatus instead of BaselineStatus
        $regressionsHtml = ""
        if ($comparison.Regressions -and $comparison.Regressions.Count -gt 0) {
            $regressionsHtml = "<ul class='baseline-change-list'>"
            foreach ($reg in $comparison.Regressions) {
                $checkNameSafe = ConvertTo-HtmlSafe $reg.CheckName
                $regressionsHtml += @"
                <li class='baseline-change-item'>
                    <span class='baseline-change-name'>$checkNameSafe</span>
                    <span class='baseline-change-status'>
                        <span style='color: #107c10;'>$($reg.PreviousStatus)</span>
                        →
                        <span style='color: #d13438;'>$($reg.CurrentStatus)</span>
                    </span>
                </li>
"@
            }
            $regressionsHtml += "</ul>"
        } else {
            $regressionsHtml = "<div class='baseline-empty'>No regressions detected</div>"
        }
        
        $baselineComparisonHtml = @"
        <div class="baseline-comparison-section">
            <div class="baseline-header">
                <div>
                    <h2 class="baseline-title">📊 Baseline Comparison</h2>
                    <div class="baseline-meta">Comparing to: <strong>$baselineName</strong> (saved $baselineDate)</div>
                </div>
                <div class="baseline-trend $trendClass">
                    <span class="baseline-trend-icon">$trendIcon</span>
                    <span>$($comparison.OverallTrend)</span>
                </div>
            </div>
            
            <div class="baseline-score-comparison">
                <div class="baseline-score-card">
                    <div class="baseline-score-label">Security Score</div>
                    <div class="baseline-score-value">$currentScore</div>
                    <div class="baseline-score-delta $scoreDeltaClass">$scoreDeltaSign$scoreDelta pts vs baseline</div>
                </div>
                <div class="baseline-score-card">
                    <div class="baseline-score-label">CIS Level 1</div>
                    <div class="baseline-score-value">$currentL1</div>
                    <div class="baseline-score-delta $cisL1DeltaClass">$cisL1DeltaSign$cisL1Delta% vs baseline</div>
                </div>
                <div class="baseline-score-card">
                    <div class="baseline-score-label">CIS Level 2</div>
                    <div class="baseline-score-value">$currentL2</div>
                    <div class="baseline-score-delta $cisL2DeltaClass">$cisL2DeltaSign$cisL2Delta% vs baseline</div>
                </div>
                <div class="baseline-score-card">
                    <div class="baseline-score-label">Checks Changed</div>
                    <div class="baseline-score-value">$($comparison.Summary.TotalChanges)</div>
                    <div class="baseline-score-delta neutral">of $($comparison.Summary.TotalChecksCompared) total</div>
                </div>
            </div>
            
            <div class="baseline-changes-grid">
                <div class="baseline-change-card">
                    <div class="baseline-change-header improvements">
                        ✅ Improvements ($($comparison.Summary.TotalImprovements))
                    </div>
                    $improvementsHtml
                </div>
                <div class="baseline-change-card">
                    <div class="baseline-change-header regressions">
                        ❌ Regressions ($($comparison.Summary.TotalRegressions))
                    </div>
                    $regressionsHtml
                </div>
            </div>
        </div>
"@
    }
    
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
    $html = $html -replace '{{SECURITY_SCORE_SECTION}}', $securityScoreHtml
    $html = $html -replace '{{BASELINE_COMPARISON_SECTION}}', $baselineComparisonHtml
    $html = $html -replace '{{RESULTS_CARDS}}', $resultsHtml

    $html | Out-File $OutputPath -Encoding UTF8
}

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
    <title>M365 Security Assessment Report - {{TENANT_NAME}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 40px; }
        .error { color: #d13438; background: #fde7e9; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>M365 Security Assessment Report</h1>
    <div class="error">
        <h2>Template Error</h2>
        <p>The HTML report template file was not found. Please ensure the file exists at:</p>
        <code>templates/report-template.html</code>
    </div>
    <h2>Results Summary</h2>
    <p>Total Checks: {{TOTAL_CHECKS}} | Passed: {{PASS_COUNT}} | Failed: {{FAIL_COUNT}} | Warnings: {{WARN_COUNT}}</p>
    {{RESULTS_CARDS}}
</body>
</html>
'@
    }
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
                -BaselineName $BaselineName
            
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
        
        # Compare to baseline if specified
        if ($CompareToBaseline) {
            Write-Step "Comparing to baseline..."
            
            # If path is just a name, look in baselines folder
            $baselineToLoad = $CompareToBaseline
            if (-not (Test-Path $baselineToLoad)) {
                # Try to find in baselines folder
                $possiblePaths = @(
                    (Join-Path $BaselinePath $CompareToBaseline),
                    (Join-Path $BaselinePath "$CompareToBaseline.json"),
                    (Get-ChildItem -Path $BaselinePath -Filter "*$CompareToBaseline*.json" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName)
                )
                
                foreach ($path in $possiblePaths) {
                    if ($path -and (Test-Path $path)) {
                        $baselineToLoad = $path
                        break
                    }
                }
            }
            
            if (-not (Test-Path $baselineToLoad)) {
                Write-Warning "Baseline not found: $CompareToBaseline"
                Write-Info "  Available baselines:"
                Get-ChildItem -Path $BaselinePath -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Info "    → $($_.Name)"
                }
                return
            }
            
            $baselineResult = Get-AssessmentBaseline -BaselinePath $baselineToLoad
            
            if (-not $baselineResult.Success) {
                Write-Warning "Failed to load baseline: $($baselineResult.Error)"
                return
            }
            
            # Build current CIS compliance for comparison
            $currentCIS = $null
            if ($script:CISCompliance) {
                $currentCIS = [PSCustomObject]@{
                    Level1Percentage = $script:CISCompliance.Level1.Percentage
                    Level2Percentage = $script:CISCompliance.Level2.Percentage
                }
            }
            
            # Build current security score for comparison
            $currentScore = $null
            if ($script:SecurityScore) {
                $currentScore = [PSCustomObject]@{
                    Score = $script:SecurityScore.OverallScore
                    Grade = $script:SecurityScore.LetterGrade
                    CategoryScores = $script:SecurityScore.CategoryDetails | ForEach-Object {
                        [PSCustomObject]@{
                            Category = $_.Category
                            Score = $_.Score
                        }
                    }
                }
            }
            
            $script:BaselineComparison = Compare-AssessmentToBaseline `
                -CurrentResults $script:AssessmentResults `
                -CurrentSecurityScore $currentScore `
                -CurrentCISCompliance $currentCIS `
                -Baseline $baselineResult.Baseline
            
            # Display comparison
            $comparisonDisplay = Format-BaselineComparison -Comparison $script:BaselineComparison
            Write-Information $comparisonDisplay -InformationAction Continue
            
            # Summary line
            $trendIcon = switch ($script:BaselineComparison.OverallTrend) {
                "Improving" { "↑" }
                "Declining" { "↓" }
                default { "→" }
            }
            Write-Success "Baseline comparison complete: $trendIcon $($script:BaselineComparison.OverallTrend) ($($script:BaselineComparison.Summary.TotalImprovements) improvements, $($script:BaselineComparison.Summary.TotalRegressions) regressions)"
        }
    }
    catch {
        Write-Warning "Baseline comparison error: $_"
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

# Clean up any existing connections to ensure fresh start
function Clear-ExistingConnections {
    Write-Information "`n[$(Get-Date -Format 'HH:mm:ss')] Clearing existing connections..." -InformationAction Continue
    
    # Disconnect Microsoft Graph
    try {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($graphContext) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-Information "  ✓ Disconnected from Microsoft Graph ($($graphContext.Account))" -InformationAction Continue
        }
    } catch { }
    
    # Disconnect Exchange Online
    try {
        $exoSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -or $_.Name -like '*ExchangeOnline*' }
        if ($exoSession) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Information "  ✓ Disconnected from Exchange Online" -InformationAction Continue
        }
    } catch { }
    
    # Also remove any stale Exchange PS sessions
    try {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' } | Remove-PSSession -ErrorAction SilentlyContinue
    } catch { }
    
    Write-Information "  ✓ Ready for fresh connection" -InformationAction Continue
}

Clear-ExistingConnections

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
}

#endregion
