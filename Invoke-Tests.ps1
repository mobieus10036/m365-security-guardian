<#
.SYNOPSIS
    Runs all Pester tests for M365 Security Guardian.

.DESCRIPTION
    Discovers and executes all *.Tests.ps1 files under the tests/ directory.
    Optionally generates code-coverage and JUnit reports.

.PARAMETER Tag
    Run only tests with matching Pester tags.

.PARAMETER Coverage
    Enable code coverage reporting for modules/.

.EXAMPLE
    .\Invoke-Tests.ps1
    Runs all tests with default settings.

.EXAMPLE
    .\Invoke-Tests.ps1 -Coverage
    Runs tests with code coverage for all assessment modules.

.EXAMPLE
    .\Invoke-Tests.ps1 -Tag 'MFA'
    Runs only tests tagged with 'MFA'.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
    Requires: Pester 5.0+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Tag,

    [Parameter(Mandatory = $false)]
    [switch]$Coverage
)

#Requires -Version 7.0

# ── Ensure Pester is available ────────────────────────────────────────────────
$pester = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version -lt [version]'5.0.0') {
    Write-Host "Installing Pester 5..." -ForegroundColor Yellow
    Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module Pester -MinimumVersion 5.0.0

# ── Build Pester configuration ────────────────────────────────────────────────
$config = New-PesterConfiguration

# Test discovery
$config.Run.Path = Join-Path $PSScriptRoot 'tests'
$config.Run.Exit = $true

# Output
$config.Output.Verbosity = 'Detailed'

# Optional tag filter
if ($Tag) {
    $config.Filter.Tag = $Tag
}

# Optional code coverage
if ($Coverage) {
    $config.CodeCoverage.Enabled = $true
    $config.CodeCoverage.Path = @(
        (Join-Path $PSScriptRoot 'modules\Security\*.ps1'),
        (Join-Path $PSScriptRoot 'modules\Exchange\*.ps1'),
        (Join-Path $PSScriptRoot 'modules\Licensing\*.ps1'),
        (Join-Path $PSScriptRoot 'modules\Core\*.ps1')
    )
    $config.CodeCoverage.OutputFormat = 'JaCoCo'
    $config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot 'tests\coverage.xml'
}

# Test results export (JUnit for CI)
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'JUnitXml'
$config.TestResult.OutputPath = Join-Path $PSScriptRoot 'tests\test-results.xml'

# ── Run ───────────────────────────────────────────────────────────────────────
Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       M365 Security Guardian — Test Runner       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Invoke-Pester -Configuration $config
