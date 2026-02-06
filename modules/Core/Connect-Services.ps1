<#
.SYNOPSIS
    Microsoft 365 service connection management module.

.DESCRIPTION
    Handles all connection lifecycle operations for Microsoft Graph and Exchange Online,
    including authentication, validation, disconnection, and pre-flight cleanup.
    Supports multiple authentication methods: DeviceCode, Interactive, Certificate,
    ClientSecret, and ManagedIdentity.

.NOTES
    This module is dot-sourced by Start-M365Assessment.ps1.
    It expects the caller to provide Write-Step, Write-Success, Write-Failure,
    and Write-Info helper functions, plus script-scoped parameters.
#>

#region Connection Functions

function Connect-GraphService {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the specified authentication method.

    .PARAMETER AuthMethod
        Authentication flow to use (DeviceCode, Interactive, Certificate, ClientSecret, ManagedIdentity).

    .PARAMETER TenantId
        Target tenant ID or domain name.

    .PARAMETER ClientId
        Application (client) ID for app-only auth methods.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for Certificate auth.

    .PARAMETER ClientSecret
        SecureString client secret for ClientSecret auth.

    .OUTPUTS
        Microsoft Graph context object on success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DeviceCode', 'Interactive', 'Certificate', 'ClientSecret', 'ManagedIdentity')]
        [string]$AuthMethod,

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $false)]
        [securestring]$ClientSecret
    )

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
        NoWelcome   = $true
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
            }
            else {
                Write-Info "Using System-Assigned Managed Identity"
            }
        }
    }

    try {
        Connect-MgGraph @connectParams
    }
    finally {
        # Clear connection params to prevent credential leakage via error traces
        if ($connectParams.ContainsKey('ClientSecretCredential')) {
            $connectParams['ClientSecretCredential'] = $null
        }
        $connectParams.Clear()
    }

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
        # Rebuild minimal params for retry (credentials already consumed by initial connect)
        $retryParams = @{ NoWelcome = $true; ErrorAction = 'Stop' }
        if ($TenantId) { $retryParams['TenantId'] = $TenantId }
        if ($AuthMethod -in @('DeviceCode', 'Interactive')) {
            if ($AuthMethod -eq 'DeviceCode') { $retryParams['UseDeviceCode'] = $true }
            $retryParams['Scopes'] = $graphScopes
        }
        elseif ($AuthMethod -eq 'ManagedIdentity') { $retryParams['Identity'] = $true }
        Connect-MgGraph @retryParams
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
    }
    elseif ($AuthMethod -in @('Certificate', 'ClientSecret', 'ManagedIdentity')) {
        Write-Info "App-only auth: Ensure the app registration has required API permissions with admin consent"
    }

    return $mgContext
}

function Connect-ExchangeService {
    <#
    .SYNOPSIS
        Connects to Exchange Online.

    .PARAMETER AuthMethod
        Authentication flow to use.

    .PARAMETER TenantId
        Target tenant ID or domain name.

    .PARAMETER ClientId
        Application (client) ID for ManagedIdentity with user-assigned identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AuthMethod,

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$ClientId
    )

    Write-Information "  → Connecting to Exchange Online..." -InformationAction Continue

    # Check if already connected to Exchange Online
    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
        Write-Success "Already connected to Exchange Online"
        return
    }
    catch {
        # Not connected, proceed with connection
    }

    # Note: Exchange Online requires separate authentication from Microsoft Graph
    # This is by design - the services use different auth libraries
    if ($AuthMethod -eq 'DeviceCode') {
        Write-Info "Exchange Online requires a separate device code (Microsoft limitation)"
    }

    # Build Exchange connection parameters
    $exoParams = @{
        ShowBanner  = $false
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
    }
    else {
        # Device code works reliably in all terminal environments
        $exoParams['Device'] = $true
    }

    Connect-ExchangeOnline @exoParams
    Write-Success "Connected to Exchange Online"
}

function Connect-AllM365Services {
    <#
    .SYNOPSIS
        Orchestrates connection to all required Microsoft 365 services.

    .DESCRIPTION
        Connects to Microsoft Graph and Exchange Online using the specified
        authentication method. Returns tenant information on success.

    .PARAMETER AuthMethod
        Authentication flow to use.

    .PARAMETER TenantId
        Target tenant ID or domain name.

    .PARAMETER ClientId
        Application (client) ID for app-only auth methods.

    .PARAMETER CertificateThumbprint
        Certificate thumbprint for Certificate auth.

    .PARAMETER ClientSecret
        SecureString client secret for ClientSecret auth.

    .PARAMETER NoAuth
        Skip authentication entirely (for pre-authenticated sessions).

    .OUTPUTS
        Tenant information object from Microsoft Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AuthMethod = 'DeviceCode',

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory = $false)]
        [securestring]$ClientSecret,

        [Parameter(Mandatory = $false)]
        [switch]$NoAuth
    )

    if ($NoAuth) {
        Write-Step "Skipping authentication (NoAuth specified)"
        return $null
    }

    Write-Step "Connecting to Microsoft 365 services..."
    Write-Info "Authentication method: $AuthMethod"

    # Connect to Microsoft Graph
    try {
        $mgContext = Connect-GraphService `
            -AuthMethod $AuthMethod `
            -TenantId $TenantId `
            -ClientId $ClientId `
            -CertificateThumbprint $CertificateThumbprint `
            -ClientSecret $ClientSecret

        # Get tenant info
        $tenantInfo = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($tenantInfo) {
            Write-Info "Tenant: $($tenantInfo.DisplayName)"
        }
    }
    catch {
        Write-Failure "Failed to connect to Microsoft Graph: $_"
        throw
    }

    # Connect to Exchange Online (optional - some checks)
    try {
        Connect-ExchangeService `
            -AuthMethod $AuthMethod `
            -TenantId $TenantId `
            -ClientId $ClientId
    }
    catch {
        Write-Failure "Failed to connect to Exchange Online: $_"
        Write-Info "Some Exchange checks may be skipped"
    }

    return $tenantInfo
}

#endregion

#region Disconnection Functions

function Clear-ExistingM365Connections {
    <#
    .SYNOPSIS
        Clears any existing Microsoft 365 connections to ensure a fresh start.

    .DESCRIPTION
        Disconnects from Microsoft Graph and Exchange Online, and removes
        any stale PowerShell sessions. Called before establishing new connections.
    #>
    [CmdletBinding()]
    param()

    Write-Information "`n[$(Get-Date -Format 'HH:mm:ss')] Clearing existing connections..." -InformationAction Continue

    # Disconnect Microsoft Graph
    try {
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($graphContext) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-Information "  ✓ Disconnected from Microsoft Graph ($($graphContext.Account))" -InformationAction Continue
        }
    }
    catch { }

    # Disconnect Exchange Online
    try {
        $exoSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -or $_.Name -like '*ExchangeOnline*' }
        if ($exoSession) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Information "  ✓ Disconnected from Exchange Online" -InformationAction Continue
        }
    }
    catch { }

    # Also remove any stale Exchange PS sessions
    try {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' } | Remove-PSSession -ErrorAction SilentlyContinue
    }
    catch { }

    Write-Information "  ✓ Ready for fresh connection" -InformationAction Continue
}

function Disconnect-AllM365Services {
    <#
    .SYNOPSIS
        Gracefully disconnects from all Microsoft 365 services.

    .DESCRIPTION
        Called during cleanup (finally block) to ensure all service
        connections are properly closed.
    #>
    [CmdletBinding()]
    param()

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

#endregion

# Note: Functions are automatically available when dot-sourced
