<#
.SYNOPSIS
    End-to-end test for attack chain analysis with the orchestrator.

.DESCRIPTION
    Simulates a complete assessment run without requiring M365 authentication.
    Creates mock assessment results and verifies attack chains are properly
    detected, analyzed, and included in all report formats.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

param(
    [switch]$Verbose
)

#Requires -Version 7.0

# Setup
$ErrorActionPreference = 'Continue'
$script:TestResults = @()
$script:PassedTests = 0
$script:FailedTests = 0

Write-Host "`n╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          M365 Security Guardian - Attack Chain E2E Test                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

function Test-Section {
    param([string]$Title)
    Write-Host "`n━━━ $Title ━━━" -ForegroundColor Yellow
}

function Assert-Test {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$ErrorMessage
    )
    
    if ($Condition) {
        Write-Host "  ✓ $TestName" -ForegroundColor Green
        $script:PassedTests++
    } else {
        Write-Host "  ✗ $TestName" -ForegroundColor Red
        if ($ErrorMessage) {
            Write-Host "    → $ErrorMessage" -ForegroundColor Red
        }
        $script:FailedTests++
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Load Modules
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Loading Modules"

$attackChainModule = Join-Path $PSScriptRoot "modules\Core\Get-AttackChains.ps1"
$exportModule = Join-Path $PSScriptRoot "modules\Core\Export-Reports.ps1"
$validationModule = Join-Path $PSScriptRoot "modules\Core\Validate-AssessmentResult.ps1"

try {
    . $validationModule
    . $exportModule
    . $attackChainModule
    Assert-Test "Core modules loaded" $true
} catch {
    Assert-Test "Core modules loaded" $false "Error: $_"
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. Create Mock Assessment Results
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Creating Mock Assessment Results"

$mockResults = @(
    # Simulate vulnerable security posture
    [PSCustomObject]@{
        CheckName = "MFA Enforcement"
        Category = "Security"
        Status = "Fail"
        Severity = "Critical"
        Message = "Only 45% of users have MFA enabled (18/40 users)"
        Details = @{ MfaPercentage = 45; TotalUsers = 40; EnabledUsers = 18 }
        Recommendation = "Enable MFA for all users immediately"
        DocumentationUrl = "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks"
        RemediationSteps = @("1. Go to Azure AD", "2. Enable MFA", "3. Enforce MFA")
        UsersWithoutMFA = @(
            @{ UserPrincipalName = "user1@contoso.com"; DisplayName = "User One" }
            @{ UserPrincipalName = "user2@contoso.com"; DisplayName = "User Two" }
        )
    },
    [PSCustomObject]@{
        CheckName = "Privileged Account Security"
        Category = "Security"
        Status = "Warning"
        Severity = "High"
        Message = "8 global administrators found; recommend limiting count to 2-3"
        Details = @{ GlobalAdminCount = 8; RecommendedCount = 3 }
        Recommendation = "Reduce global admin count and use Privileged Identity Management"
        DocumentationUrl = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"
        RemediationSteps = @("1. Review admins", "2. Enable PIM", "3. Reduce admins")
        PrivilegedAccounts = @(
            @{ UserPrincipalName = "admin1@contoso.com"; DisplayName = "Admin One"; RiskLevel = "High" }
        )
    },
    [PSCustomObject]@{
        CheckName = "Legacy Authentication"
        Category = "Security"
        Status = "Fail"
        Severity = "High"
        Message = "Legacy authentication not blocked; 8 sign-ins detected"
        Details = @{ LegacySignIns = 8; Blocked = $false }
        Recommendation = "Block legacy authentication immediately"
        DocumentationUrl = "https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication"
        RemediationSteps = @("1. Enable CA policy", "2. Block legacy auth", "3. Test clients")
    },
    [PSCustomObject]@{
        CheckName = "Conditional Access Policies"
        Category = "Security"
        Status = "Warning"
        Severity = "High"
        Message = "Only 3 of 5 recommended CA policies enabled"
        Details = @{ EnabledCount = 3; RecommendedCount = 5 }
        Recommendation = "Enable additional CA policies for better coverage"
        DocumentationUrl = "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview"
        RemediationSteps = @("1. Review policies", "2. Create missing", "3. Test thoroughly")
        EnabledPolicies = @(
            @{ DisplayName = "Require MFA for admin"; State = "Enabled" }
        )
    },
    [PSCustomObject]@{
        CheckName = "Application Permissions Audit"
        Category = "Security"
        Status = "Fail"
        Severity = "Medium"
        Message = "User consent for apps is enabled; 15 risky apps detected"
        Details = @{ RiskyAppsCount = 15; UserConsentEnabled = $true }
        Recommendation = "Disable user consent and audit high-privilege apps"
        DocumentationUrl = "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent"
        RemediationSteps = @("1. Disable user consent", "2. Review apps", "3. Remove risky apps")
        RiskyApps = @(
            @{ DisplayName = "Suspicious App"; AppId = "xyz123" }
        )
    },
    [PSCustomObject]@{
        CheckName = "Email Authentication (SPF/DKIM/DMARC)"
        Category = "Exchange"
        Status = "Fail"
        Severity = "High"
        Message = "DMARC not enforced for domain contoso.com"
        Details = @{ Domain = "contoso.com"; SPFConfigured = $true; DKIMEnabled = $true; DMARCEnforced = $false }
        Recommendation = "Enforce DMARC policy for domain protection"
        DocumentationUrl = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-about"
        RemediationSteps = @("1. Create DMARC record", "2. Set policy to enforce", "3. Monitor reports")
        DomainDetails = @(
            @{ Domain = "contoso.com"; SPF = "Configured"; DKIM = "Enabled"; DMARC = "Not Enforced" }
        )
    },
    [PSCustomObject]@{
        CheckName = "Mailbox Auditing"
        Category = "Exchange"
        Status = "Warning"
        Severity = "Medium"
        Message = "Mailbox auditing is not enabled for all mailboxes; 12 non-compliant"
        Details = @{ TotalMailboxes = 50; AuditedMailboxes = 38; NonCompliant = 12 }
        Recommendation = "Enable mailbox auditing for all mailboxes"
        DocumentationUrl = "https://learn.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing"
        RemediationSteps = @("1. Enable auditing", "2. Monitor logs", "3. Retain records")
        NonCompliantMailboxes = @(
            @{ PrimarySmtpAddress = "user5@contoso.com"; DisplayName = "Unaudited User" }
        )
    },
    [PSCustomObject]@{
        CheckName = "External Sharing Configuration"
        Category = "Security"
        Status = "Fail"
        Severity = "High"
        Message = "External sharing is unrestricted; anyone can share"
        Details = @{ SharingRestricted = $false; GuestAccessLimited = $false }
        Recommendation = "Restrict external sharing to approved domains"
        DocumentationUrl = "https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview"
        RemediationSteps = @("1. Enable restrictions", "2. Set approved domains", "3. Monitor sharing")
    }
)

Assert-Test "Created 8 mock assessment results" ($mockResults.Count -eq 8)
$propCheckCount = $mockResults | ForEach-Object {
    $obj = $_
    $props = @('CheckName', 'Category', 'Status', 'Severity', 'Message', 'Details', 'Recommendation', 'DocumentationUrl', 'RemediationSteps')
    $missing = @($props | Where-Object { $_ -notin $obj.PSObject.Properties.Name })
    $missing.Count
} | Where-Object { $_ -gt 0 } | Measure-Object | Select-Object -ExpandProperty Count
Assert-Test "All results have required properties" ($propCheckCount -eq 0)

# ─────────────────────────────────────────────────────────────────────────────
# 3. Test Core Assessment Modules
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing Assessment Result Validation"

$validResult = $mockResults[0]
try {
    $isValid = Test-AssessmentResultSchema -Result $validResult -Strict $false
    Assert-Test "Valid result passes validation" ($isValid -eq $true)
} catch {
    Assert-Test "Valid result passes validation" $false "Error: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. Test Security Scoring
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing Security Scoring"

# Load scoring module
$scoringModule = Join-Path $PSScriptRoot "modules\Core\Get-TenantSecurityScore.ps1"
. $scoringModule

$securityScore = Get-TenantSecurityScore -AssessmentResults $mockResults

Assert-Test "Security score calculated" ($securityScore -ne $null)
$scoreInRange = ($securityScore.OverallScore -ge 0 -and $securityScore.OverallScore -le 100)
Assert-Test "Overall score is 0-100" $scoreInRange
Assert-Test "Letter grade assigned" (
    $securityScore.LetterGrade -in @('A', 'B', 'C', 'D', 'F'))
Assert-Test "Grade description present" (
    [string]::IsNullOrEmpty($securityScore.GradeDescription) -eq $false)

Write-Host "    Score: $($securityScore.OverallScore)% | Grade: $($securityScore.LetterGrade) ($($securityScore.GradeDescription))"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Test CIS Compliance Mapping
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing CIS Compliance Mapping"

$cisModule = Join-Path $PSScriptRoot "modules\Core\Get-CISCompliance.ps1"
try {
    . $cisModule
    $cisCompliance = Get-CISComplianceSummary -AssessmentResults $mockResults
    Assert-Test "CIS compliance calculated" ($cisCompliance -ne $null)
} catch {
    Write-Host "  [SKIP] CIS compliance module not available: $_" -ForegroundColor Yellow
    $cisCompliance = $null
    $script:FailedTests += 3  # Skip 3 CIS tests
}
$hasLevel1 = ($cisCompliance | Get-Member -Name "Level1" -ErrorAction SilentlyContinue) -ne $null
Assert-Test "CIS has level 1 compliance" $hasLevel1

$controlCount = @($cisCompliance.AllControls | Measure-Object | Select-Object -ExpandProperty Count)[0]
Assert-Test "CIS has control results" ($controlCount -gt 0)

# ─────────────────────────────────────────────────────────────────────────────
# 6. Test Attack Chain Analysis (Core Feature)
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing Attack Chain Analysis"

$attackChainConfigPath = Join-Path $PSScriptRoot "config\attack-chains.json"
$attackChains = Get-AttackChains `
    -AssessmentResults $mockResults `
    -CISCompliance $cisCompliance `
    -ConfigPath $attackChainConfigPath

Assert-Test "Attack chains analyzed" ($attackChains -ne $null)

$hasEnabledChains = ($attackChains.EnabledChainCount -gt 0)
Assert-Test "Found enabled attack chains" $hasEnabledChains

$totalAnalyzed = ($attackChains.TotalChainsAnalyzed -gt 0)
Assert-Test "Total chains analyzed" $totalAnalyzed

Assert-Test "Chain summary present" ($attackChains.ChainSummary -ne $null)

$validRiskLevel = $attackChains.ChainSummary.OverallRiskLevel -in @('Critical', 'High', 'Elevated', 'Low')
Assert-Test "Risk level determined" $validRiskLevel

Assert-Test "MITRE matrix generated" ($attackChains.MitreMatrix -ne $null)

$remediationCount = @($attackChains.RemediationPriorities | Measure-Object | Select-Object -ExpandProperty Count)[0]
Assert-Test "Remediation priorities calculated" ($remediationCount -gt 0)

Write-Host "    Enabled Chains: $($attackChains.EnabledChainCount) / $($attackChains.TotalChainsAnalyzed)"
Write-Host "    Critical: $($attackChains.CriticalChains) | High: $($attackChains.HighChains)"
Write-Host "    Risk Level: $($attackChains.ChainSummary.OverallRiskLevel)"

if ($attackChains.EnabledChainCount -gt 0) {
    Write-Host "    Top Threats:"
    $attackChains.EnabledChains | Select-Object -First 3 | ForEach-Object {
        Write-Host "      • [$($_.Severity)] $($_.Name) (Score: $($_.EnablementScore)%)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. Test Report HTML Generation
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing HTML Report Generation"

$testReportDir = Join-Path $PSScriptRoot "test-reports"
$null = New-Item -ItemType Directory -Path $testReportDir -Force -ErrorAction SilentlyContinue

$templatePath = Join-Path $PSScriptRoot "templates\report-template.html"
$htmlReportPath = Join-Path $testReportDir "test-report-attack-chains.html"

try {
    Export-HtmlReport `
        -Results $mockResults `
        -OutputPath $htmlReportPath `
        -TenantInfo ([PSCustomObject]@{ DisplayName = "Contoso.onmicrosoft.com" }) `
        -SecurityScore $securityScore `
        -BaselineComparison $null `
        -AttackChains $attackChains `
        -TemplatePath $templatePath
    
    $htmlExists = Test-Path $htmlReportPath
    Assert-Test "HTML report created" $htmlExists
    
    if ($htmlExists) {
        $htmlContent = Get-Content $htmlReportPath -Raw
        Assert-Test "HTML contains attack chains section" ($htmlContent -like "*attack-chains*" -or $htmlContent -like "*Attack Chain*")
        Assert-Test "HTML contains enabled chain count" ($htmlContent -like "*$($attackChains.EnabledChainCount)*")
        Assert-Test "HTML contains risk level" ($htmlContent -like "*$($attackChains.ChainSummary.OverallRiskLevel)*")
        
        Write-Host "    Path: $htmlReportPath"
        Write-Host "    Size: $(Get-Item $htmlReportPath | Select-Object -ExpandProperty Length) bytes"
    }
} catch {
    Assert-Test "HTML report created" $false "Error: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. Test Report JSON Export
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing JSON Report Export"

$jsonReportPath = Join-Path $testReportDir "test-report-attack-chains"

try {
    Export-JsonReport `
        -Results $mockResults `
        -OutputPath $jsonReportPath `
        -TenantInfo ([PSCustomObject]@{ DisplayName = "Contoso.onmicrosoft.com" }) `
        -SecurityScore $securityScore
    
    $jsonExists = Test-Path "$jsonReportPath.json"
    Assert-Test "JSON report created" $jsonExists
    
    if ($jsonExists) {
        $jsonContent = Get-Content "$jsonReportPath.json" -Raw | ConvertFrom-Json
        Assert-Test "JSON has results" ($jsonContent.Findings | Measure-Object | Select-Object -ExpandProperty Count) -gt 0
        
        Write-Host "    Path: $jsonReportPath.json"
    }
} catch {
    Assert-Test "JSON report created" $false "Error: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 9. Test CSV Report Export
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing CSV Report Export"

$csvReportPath = Join-Path $testReportDir "test-report-attack-chains"

try {
    Export-CsvReport -Results $mockResults -OutputPath $csvReportPath
    
    $csvExists = Test-Path "$csvReportPath.csv"
    Assert-Test "CSV report created" $csvExists
    
    if ($csvExists) {
        $csvContent = Get-Content "$csvReportPath.csv"
        Assert-Test "CSV has headers" ($csvContent[0] -like "*CheckName*")
        Assert-Test "CSV has data rows" ($csvContent.Count -gt 1)
        
        Write-Host "    Path: $($csvReportPath).csv"
    }
} catch {
    Assert-Test "CSV report created" $false "Error: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# 10. Test Console Output Formatting
# ─────────────────────────────────────────────────────────────────────────────

Test-Section "Testing Console Output Formatting"

try {
    $consoleOutput = Format-AttackChainConsole -AttackChainResults $attackChains
    Assert-Test "Console output generated" (
        [string]::IsNullOrEmpty($consoleOutput) -eq $false)
    Assert-Test "Output contains attack chain analysis header" (
        $consoleOutput -like "*ATTACK CHAIN ANALYSIS*")
    Assert-Test "Output contains enabled chain count" (
        $consoleOutput -like "*$($attackChains.EnabledChainCount)*")
    
    Write-Host "    Sample output:"
    $consoleOutput -split "`n" | Select-Object -First 10 | ForEach-Object {
        Write-Host "    $_"
    }
} catch {
    Assert-Test "Console output generated" $false "Error: $_"
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

$totalTests = $script:PassedTests + $script:FailedTests
$passPercentage = if ($totalTests -gt 0) { [math]::Round(($script:PassedTests / $totalTests) * 100, 1) } else { 0 }

Write-Host "`n━━━ Test Summary ━━━" -ForegroundColor Yellow
Write-Host "  Total Tests: $totalTests"
Write-Host "  Passed: $($script:PassedTests)" -ForegroundColor Green
Write-Host "  Failed: $($script:FailedTests)" -ForegroundColor $(if ($script:FailedTests -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Pass Rate: $passPercentage%"

Write-Host "`n━━━ Generated Reports ━━━" -ForegroundColor Yellow
Get-ChildItem -Path $testReportDir -File | ForEach-Object {
    Write-Host "  • $($_.Name) ($([math]::Round($_.Length / 1KB, 1)) KB)"
}

Write-Host "`n╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($script:FailedTests -eq 0) { 'Green' } else { 'Yellow' })
Write-Host "║  END-TO-END TEST $(if ($script:FailedTests -eq 0) { '✓ PASSED' } else { '⚠ COMPLETED WITH FAILURES' })                                 ║" -ForegroundColor $(if ($script:FailedTests -eq 0) { 'Green' } else { 'Yellow' })
Write-Host "╚════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $(if ($script:FailedTests -eq 0) { 'Green' } else { 'Yellow' })

if ($script:FailedTests -gt 0) {
    exit 1
}
