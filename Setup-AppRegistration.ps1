<#
.SYNOPSIS
    Creates an Entra ID App Registration with certificate authentication for M365 Security Guardian.

.DESCRIPTION
    This script sets up secure, unattended authentication for the M365 Security Guardian tool:
    1. Creates a self-signed certificate (valid for 2 years)
    2. Creates an App Registration in Entra ID
    3. Assigns required Microsoft Graph API permissions
    4. Uploads the certificate to the App Registration
    5. Grants admin consent for the permissions

    After running this script, you can use:
    .\Start-M365Assessment.ps1 -AuthMethod Certificate -ClientId "<AppId>" -TenantId "<TenantId>" -CertificateThumbprint "<Thumbprint>"

.PARAMETER AppName
    Display name for the App Registration.
    Default: "M365 Security Guardian"

.PARAMETER CertificateValidityYears
    How long the certificate should be valid.
    Default: 2 years

.PARAMETER TenantId
    The Entra ID tenant ID. If not specified, uses the connected tenant.

.EXAMPLE
    .\Setup-AppRegistration.ps1
    Creates app registration with default settings.

.EXAMPLE
    .\Setup-AppRegistration.ps1 -AppName "Contoso Security Scanner" -CertificateValidityYears 1
    Creates app with custom name and 1-year certificate.

.NOTES
    Requires: 
    - Global Administrator or Application Administrator role
    - Microsoft.Graph.Applications module
    
    Author: mobieus10036
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AppName = "M365 Security Guardian",

    [Parameter(Mandatory = $false)]
    [int]$CertificateValidityYears = 2,

    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

# Disable WAM broker
$env:AZURE_IDENTITY_DISABLE_BROKER = "true"

Write-Host "`n" -NoNewline
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║            M365 Security Guardian - App Registration Setup             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Prerequisites Check
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

# Check for required module
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "  ✗ Microsoft.Graph.Applications module not found" -ForegroundColor Red
    Write-Host "  Installing module..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
}
Write-Host "  ✓ Microsoft.Graph.Applications module available" -ForegroundColor Green

# Import modules
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Write-Host "  ✓ Modules imported" -ForegroundColor Green
#endregion

#region Connect to Graph
Write-Host "`n[2/6] Connecting to Microsoft Graph..." -ForegroundColor Yellow

# Disconnect any existing session
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

# Connect with required scopes for app registration
$scopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", 
    "Directory.Read.All"
)

$connectParams = @{
    Scopes = $scopes
    UseDeviceCode = $true
    NoWelcome = $true
}

if ($TenantId) {
    $connectParams['TenantId'] = $TenantId
}

try {
    Connect-MgGraph @connectParams
    $context = Get-MgContext
    Write-Host "  ✓ Connected as: $($context.Account)" -ForegroundColor Green
    Write-Host "  ✓ Tenant: $($context.TenantId)" -ForegroundColor Green
    $TenantId = $context.TenantId
}
catch {
    Write-Host "  ✗ Failed to connect: $_" -ForegroundColor Red
    exit 1
}
#endregion

#region Create Certificate
Write-Host "`n[3/6] Creating self-signed certificate..." -ForegroundColor Yellow

$certSubject = "CN=$AppName"
$certStorePath = "Cert:\CurrentUser\My"

# Check if certificate already exists
$existingCert = Get-ChildItem -Path $certStorePath | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1

if ($existingCert) {
    Write-Host "  ! Certificate already exists with thumbprint: $($existingCert.Thumbprint)" -ForegroundColor Yellow
    $useCert = Read-Host "  Use existing certificate? (Y/N)"
    if ($useCert -eq 'Y' -or $useCert -eq 'y') {
        $certificate = $existingCert
    }
    else {
        # Remove old cert and create new
        Remove-Item -Path "$certStorePath\$($existingCert.Thumbprint)" -Force
        $certificate = $null
    }
}

if (-not $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Subject $certSubject `
        -CertStoreLocation $certStorePath `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears($CertificateValidityYears)
    
    Write-Host "  ✓ Certificate created" -ForegroundColor Green
}

Write-Host "  ✓ Thumbprint: $($certificate.Thumbprint)" -ForegroundColor Green
Write-Host "  ✓ Expires: $($certificate.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Green

# Export certificate public key for upload to Azure
$certBase64 = [System.Convert]::ToBase64String($certificate.RawData)
#endregion

#region Create App Registration
Write-Host "`n[4/6] Creating App Registration..." -ForegroundColor Yellow

# Check if app already exists
$existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($existingApp) {
    Write-Host "  ! App '$AppName' already exists (AppId: $($existingApp.AppId))" -ForegroundColor Yellow
    $useApp = Read-Host "  Use existing app and update certificate? (Y/N)"
    if ($useApp -eq 'Y' -or $useApp -eq 'y') {
        $app = $existingApp
    }
    else {
        Write-Host "  Please choose a different -AppName or delete the existing app" -ForegroundColor Red
        exit 1
    }
}
else {
    # Define required API permissions
    # Microsoft Graph Application Permissions
    $graphAppId = "00000003-0000-0000-c000-000000000000"
    
    $requiredPermissions = @(
        @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }  # User.Read.All
        @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
        @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role" }  # Policy.Read.All
        @{ Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"; Type = "Role" }  # Organization.Read.All
        @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Type = "Role" }  # AuditLog.Read.All
        @{ Id = "38d9df27-64da-44fd-b7c5-a6fbac20248f"; Type = "Role" }  # SecurityEvents.Read.All
        @{ Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Type = "Role" }  # Application.Read.All
        @{ Id = "d5fe8ce8-684c-4c83-a52c-46e882ce4be1"; Type = "Role" }  # RoleManagement.Read.All
        @{ Id = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"; Type = "Role" }  # RoleManagement.Read.Directory
        @{ Id = "dc5007c0-2d7d-4c42-879c-2dab87571379"; Type = "Role" }  # IdentityRiskyUser.Read.All
        @{ Id = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"; Type = "Role" }  # DeviceManagementConfiguration.Read.All
        @{ Id = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"; Type = "Role" }  # ConditionalAccessPolicy.Read.All (for CA policies)
    )
    
    $resourceAccess = @{
        ResourceAppId = $graphAppId
        ResourceAccess = $requiredPermissions
    }
    
    # Create the app
    $appParams = @{
        DisplayName = $AppName
        SignInAudience = "AzureADMyOrg"
        RequiredResourceAccess = @($resourceAccess)
        Notes = "Created by M365 Security Guardian Setup Script on $(Get-Date -Format 'yyyy-MM-dd')"
    }
    
    $app = New-MgApplication @appParams
    Write-Host "  ✓ App Registration created" -ForegroundColor Green
    Write-Host "  ✓ Application (client) ID: $($app.AppId)" -ForegroundColor Green
}

# Create Service Principal if it doesn't exist
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "  ✓ Service Principal created" -ForegroundColor Green
}
#endregion

#region Upload Certificate
Write-Host "`n[5/6] Uploading certificate to App Registration..." -ForegroundColor Yellow

# Create key credential
$keyCredential = @{
    Type = "AsymmetricX509Cert"
    Usage = "Verify"
    Key = $certificate.RawData
    DisplayName = "M365 Security Guardian Certificate"
    StartDateTime = $certificate.NotBefore
    EndDateTime = $certificate.NotAfter
}

# Update app with certificate
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)
Write-Host "  ✓ Certificate uploaded to App Registration" -ForegroundColor Green
#endregion

#region Grant Admin Consent
Write-Host "`n[6/6] Granting admin consent for API permissions..." -ForegroundColor Yellow

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Grant each permission
$grantedCount = 0
foreach ($permission in $requiredPermissions) {
    try {
        $appRole = $graphSp.AppRoles | Where-Object { $_.Id -eq $permission.Id }
        
        # Check if already granted
        $existingGrant = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue | 
            Where-Object { $_.AppRoleId -eq $permission.Id }
        
        if (-not $existingGrant) {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $sp.Id `
                -PrincipalId $sp.Id `
                -ResourceId $graphSp.Id `
                -AppRoleId $permission.Id | Out-Null
            $grantedCount++
        }
    }
    catch {
        Write-Host "  ! Could not grant permission $($permission.Id): $_" -ForegroundColor Yellow
    }
}
Write-Host "  ✓ Admin consent granted for $grantedCount permissions" -ForegroundColor Green
#endregion

#region Output Summary
Write-Host "`n"
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    Setup Complete! ✓                                 ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n  Save these values - you'll need them to run the assessment:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Application (Client) ID: " -NoNewline -ForegroundColor White
Write-Host "$($app.AppId)" -ForegroundColor Cyan
Write-Host "  Tenant ID:               " -NoNewline -ForegroundColor White  
Write-Host "$TenantId" -ForegroundColor Cyan
Write-Host "  Certificate Thumbprint:  " -NoNewline -ForegroundColor White
Write-Host "$($certificate.Thumbprint)" -ForegroundColor Cyan
Write-Host ""

# Create a config snippet
$configSnippet = @"

# Run the assessment with certificate authentication:
.\Start-M365Assessment.ps1 ``
    -AuthMethod Certificate ``
    -ClientId "$($app.AppId)" ``
    -TenantId "$TenantId" ``
    -CertificateThumbprint "$($certificate.Thumbprint)"

"@

Write-Host "  Example command:" -ForegroundColor Yellow
Write-Host $configSnippet -ForegroundColor Gray

# Save to a local config file for convenience
$configPath = Join-Path $PSScriptRoot ".auth-config.ps1"
$configContent = @"
# M365 Security Guardian - Authentication Configuration
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# App Name: $AppName

`$AuthConfig = @{
    AuthMethod = 'Certificate'
    ClientId = '$($app.AppId)'
    TenantId = '$TenantId'
    CertificateThumbprint = '$($certificate.Thumbprint)'
}

# Usage: 
# . .\.auth-config.ps1
# .\Start-M365Assessment.ps1 @AuthConfig
"@

$configContent | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "  Configuration saved to: $configPath" -ForegroundColor Green
Write-Host "  You can run: " -NoNewline -ForegroundColor White
Write-Host ". .\.auth-config.ps1; .\Start-M365Assessment.ps1 @AuthConfig" -ForegroundColor Cyan
Write-Host ""

# Disconnect
Disconnect-MgGraph | Out-Null
#endregion
