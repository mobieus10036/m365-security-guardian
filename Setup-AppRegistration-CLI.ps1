<#
.SYNOPSIS
    Creates an Entra ID App Registration with certificate authentication using Azure CLI.

.DESCRIPTION
    Uses Azure CLI (no WAM broker issues) to set up secure authentication.

.EXAMPLE
    .\Setup-AppRegistration-CLI.ps1
#>

[CmdletBinding()]
param(
    [string]$AppName = "M365 Security Guardian",
    [int]$CertificateValidityYears = 2
)

$ErrorActionPreference = 'Stop'

Write-Host "`n"
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        M365 Security Guardian - App Registration Setup (Azure CLI)    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

#region Login
Write-Host "[1/6] Logging into Azure..." -ForegroundColor Yellow

# Clear any stale tokens first
az logout --output none 2>$null
az account clear --output none 2>$null

# Login with tenant-specific to satisfy Conditional Access policies
$targetTenant = "25cfe2b5-4780-4220-babb-8b90f37b2c53"
Write-Host "  Tenant: $targetTenant" -ForegroundColor Gray

az login --tenant $targetTenant --use-device-code --allow-no-subscriptions --output none
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ Login failed" -ForegroundColor Red
    exit 1
}

$account = az account show --output json | ConvertFrom-Json
$TenantId = $targetTenant
Write-Host "  ✓ Logged in as: $($account.user.name)" -ForegroundColor Green
Write-Host "  ✓ Tenant: $TenantId" -ForegroundColor Green
#endregion

#region Create Certificate
Write-Host "`n[2/6] Creating self-signed certificate..." -ForegroundColor Yellow

$certSubject = "CN=$AppName"
$certStorePath = "Cert:\CurrentUser\My"

# Check if certificate already exists
$existingCert = Get-ChildItem -Path $certStorePath | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1

if ($existingCert) {
    Write-Host "  ✓ Using existing certificate: $($existingCert.Thumbprint)" -ForegroundColor Green
    $certificate = $existingCert
}
else {
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

# Export certificate to temp PEM file for Azure CLI
$certPath = Join-Path $env:TEMP "m365-assessment-cert.pem"
$certPem = @"
-----BEGIN CERTIFICATE-----
$([System.Convert]::ToBase64String($certificate.RawData, 'InsertLineBreaks'))
-----END CERTIFICATE-----
"@
$certPem | Out-File -FilePath $certPath -Encoding ASCII -Force
#endregion

#region Create App Registration
Write-Host "`n[3/6] Creating App Registration..." -ForegroundColor Yellow

# Check if app exists
$existingApp = az ad app list --display-name $AppName --output json | ConvertFrom-Json
if ($existingApp -and $existingApp.Count -gt 0) {
    Write-Host "  ✓ Using existing app: $($existingApp[0].appId)" -ForegroundColor Green
    $appId = $existingApp[0].appId
    $appObjectId = $existingApp[0].id
}
else {
    # Create the app with certificate
    $appResult = az ad app create `
        --display-name $AppName `
        --sign-in-audience AzureADMyOrg `
        --key-type AsymmetricX509Cert `
        --key-usage Verify `
        --key-value $([System.Convert]::ToBase64String($certificate.RawData)) `
        --output json | ConvertFrom-Json
    
    $appId = $appResult.appId
    $appObjectId = $appResult.id
    Write-Host "  ✓ App created: $appId" -ForegroundColor Green
}
#endregion

#region Create Service Principal
Write-Host "`n[4/6] Creating Service Principal..." -ForegroundColor Yellow

$existingSp = az ad sp list --filter "appId eq '$appId'" --output json | ConvertFrom-Json
if ($existingSp -and $existingSp.Count -gt 0) {
    Write-Host "  ✓ Using existing Service Principal" -ForegroundColor Green
    $spId = $existingSp[0].id
}
else {
    $spResult = az ad sp create --id $appId --output json | ConvertFrom-Json
    $spId = $spResult.id
    Write-Host "  ✓ Service Principal created" -ForegroundColor Green
}
#endregion

#region Add API Permissions
Write-Host "`n[5/6] Adding Microsoft Graph API permissions..." -ForegroundColor Yellow

# Microsoft Graph App ID
$graphAppId = "00000003-0000-0000-c000-000000000000"

# Required Microsoft Graph permissions (Application permissions)
$graphPermissions = @(
    "df021288-bdef-4463-88db-98f22de89214"  # User.Read.All
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
    "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All
    "498476ce-e0fe-48b0-b801-37ba7e2685c6"  # Organization.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da"  # AuditLog.Read.All
    "38d9df27-64da-44fd-b7c5-a6fbac20248f"  # SecurityEvents.Read.All
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"  # Application.Read.All
    "d5fe8ce8-684c-4c83-a52c-46e882ce4be1"  # RoleManagement.Read.All
    "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"  # RoleManagement.Read.Directory
    "83d4163d-a2d8-4d3b-9695-4ae3ca98f888"  # SharePointTenantSettings.Read.All
)

foreach ($permId in $graphPermissions) {
    az ad app permission add --id $appId --api $graphAppId --api-permissions "$permId=Role" --output none 2>$null
}
Write-Host "  ✓ Microsoft Graph permissions added" -ForegroundColor Green
#endregion

#region Grant Admin Consent
Write-Host "`n[6/6] Granting admin consent..." -ForegroundColor Yellow

# Wait a moment for Azure AD to propagate
Start-Sleep -Seconds 3

az ad app permission admin-consent --id $appId --output none 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Admin consent granted" -ForegroundColor Green
}
else {
    Write-Host "  ! Manual admin consent may be required" -ForegroundColor Yellow
    Write-Host "    Go to: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$appId" -ForegroundColor Gray
}
#endregion

#region Cleanup and Output
# Remove temp cert file
Remove-Item -Path $certPath -Force -ErrorAction SilentlyContinue

Write-Host "`n"
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    Setup Complete! ✓                                 ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n  Your authentication configuration:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Application (Client) ID: " -NoNewline -ForegroundColor White
Write-Host "$appId" -ForegroundColor Cyan
Write-Host "  Tenant ID:               " -NoNewline -ForegroundColor White  
Write-Host "$TenantId" -ForegroundColor Cyan
Write-Host "  Certificate Thumbprint:  " -NoNewline -ForegroundColor White
Write-Host "$($certificate.Thumbprint)" -ForegroundColor Cyan
Write-Host ""

$runCommand = @"
.\Start-M365Assessment.ps1 ``
    -AuthMethod Certificate ``
    -ClientId "$appId" ``
    -TenantId "$TenantId" ``
    -CertificateThumbprint "$($certificate.Thumbprint)"
"@

Write-Host "  Run the assessment with:" -ForegroundColor Yellow
Write-Host $runCommand -ForegroundColor Gray
Write-Host ""

# Save config (JSON - safe data-only format)
$configPath = Join-Path $PSScriptRoot ".auth-config.json"
@{
    AuthMethod = 'Certificate'
    ClientId = $appId
    TenantId = $TenantId
    CertificateThumbprint = $certificate.Thumbprint
    Generated = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Depth 2 | Out-File -FilePath $configPath -Encoding UTF8

Write-Host "  Config saved to: $configPath" -ForegroundColor Green
Write-Host "  The assessment will auto-detect this config. Just run:" -ForegroundColor White
Write-Host "  .\Start-M365Assessment.ps1" -ForegroundColor Cyan
Write-Host ""

# Logout
az logout --output none 2>$null
#endregion
