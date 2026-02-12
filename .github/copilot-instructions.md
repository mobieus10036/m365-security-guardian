# M365 Security Guardian — Copilot Instructions

## Project Overview

PowerShell 7+ tool that assesses Microsoft 365 tenant security posture against CIS Benchmarks v3.1.0 and MITRE ATT&CK. Read-only (no tenant changes). Generates HTML/JSON/CSV reports with a weighted security score (0–100, grades A–F).

## Architecture

**Pipeline:** `Start-M365Assessment.ps1` orchestrates a linear flow:
`Connect → Run Assessment Modules → Score → CIS Compliance → Baseline Compare → Export Reports → Disconnect`

**Module layout:**
- `modules/Security/Test-*.ps1` — Identity, CA, apps, privileged accounts (8 checks)
- `modules/Exchange/Test-*.ps1` — Email auth, mailbox auditing (3 checks)
- `modules/Licensing/Test-*.ps1` — License optimization (1 check)
- `modules/Core/` — Shared engines: scoring (`Get-TenantSecurityScore`), CIS mapping (`Get-CISCompliance`), baselines (`Compare-Baseline`), reporting (`Export-Reports`)

**File name = function name.** `Test-MFAConfiguration.ps1` must contain `function Test-MFAConfiguration`. The orchestrator dot-sources each file, then calls the function by its filename stem.

## Assessment Result Object Contract

Every `Test-*` function returns exactly ONE `[PSCustomObject]` with this required shape:

```powershell
[PSCustomObject]@{
    CheckName        = "MFA Enforcement"                    # Unique identifier, must match CIS assessmentKey
    Category         = "Security"                           # Security | Exchange | Licensing
    Status           = "Pass"                               # Pass | Warning | Fail | Info (exactly 4)
    Severity         = "Critical"                           # Critical | High | Medium | Low | Info (exactly 5)
    Message          = "MFA adoption: 95.2% (42/44 users)"
    Details          = @{ MfaPercentage = 95.2 }            # Structured metrics hashtable
    Recommendation   = "Enable MFA for all users..."
    DocumentationUrl = "https://learn.microsoft.com/..."
    RemediationSteps = @("1. Navigate to...", "2. Create...")
}
```

Check-specific extra properties (e.g., `UsersWithoutMFA`, `PrivilegedAccounts`, `DomainDetails`, `NonCompliantMailboxes`, `RiskyApps`) are used by `Export-DetailedCsvReports` to generate separate `_*.csv` files.

## Error Handling Convention

Assessment functions must **never throw**. On error, return the same object shape with `Status = "Info"`, `Severity = "Info"`, and the error in `Message`/`Details`:

```powershell
catch {
    return [PSCustomObject]@{
        CheckName = "MFA Configuration"; Category = "Security"
        Status = "Info"; Severity = "Info"
        Message = "Unable to assess: $_"
        Details = @{ Error = $_.Exception.Message }
        Recommendation = "Verify Microsoft Graph permissions..."
        DocumentationUrl = "https://..."; RemediationSteps = @()
    }
}
```

## Key Conventions

- **Config access:** `$Config.Section.Property` with inline fallback: `if ($Config.Security.MFAEnforcementThreshold) { ... } else { 95 }`
- **Data sharing:** The orchestrator preloads Graph API data (auth details, CA policies) and injects as parameters to specific functions — never re-fetch data another module already retrieved.
- **Console output:** Use `Write-Information -InformationAction Continue` via helpers (`Write-Step`, `Write-Success`, `Write-Failure`, `Write-Info`). Never use `Write-Host` in assessment modules.
- **HTML safety:** All dynamic text in reports passes through `ConvertTo-HtmlSafe` (`[System.Net.WebUtility]::HtmlEncode`).
- **File output:** Always use `-Encoding UTF8`.
- **Report template:** `templates/report-template.html` uses `{{PLACEHOLDER}}` tokens replaced by `Export-HtmlReport`.
- **Module headers:** Include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.OUTPUTS`, `.NOTES` with Project/Author/Version).

## Adding a New Assessment Check

1. Create `modules/<Category>/Test-YourCheck.ps1` containing `function Test-YourCheck`.
2. Return the standard result object (see contract above).
3. Register the script path in the `$moduleScripts` hashtable in `Start-M365Assessment.ps1`.
4. If the check needs cached API data, add parameter injection logic in the orchestrator's preload section.
5. Map to CIS controls by adding an entry in `config/cis-benchmark-mapping.json` with `assessmentKey` matching your `CheckName`.
6. Add a weight in `config/assessment-config.json` under `Scoring.RiskWeights`.

## Scoring & CIS Mapping

- **Scoring:** 5 weighted categories (Identity 35%, CA 25%, Apps 20%, Email 15%, Governance 5%). Status scoring: Pass=1.0, Warning=0.5, Fail=0.0, Info=1.0 (neutral). Severity multipliers: Critical=1.0, High=0.75, Medium=0.5, Low=0.25.
- **CIS controls** in `config/cis-benchmark-mapping.json` link to checks via `assessmentKey` (matches `CheckName`) and `checkType` (drives specialized compliance logic like `GlobalAdminCount` or `AllUserMFAEnabled`).

## Testing

Tests use **Pester 5+** and run entirely offline — all Microsoft Graph / EXO calls are mocked.

```powershell
.\Invoke-Tests.ps1              # Run all tests
.\Invoke-Tests.ps1 -Coverage    # With code coverage report
```

**Test structure mirrors source layout:**
- `tests/TestHelpers.ps1` — Shared mock factories (`New-MockUser`, `New-MockConfig`, etc.) and `Assert-AssessmentResult` contract validator
- `tests/Security/*.Tests.ps1` — Tests for `modules/Security/Test-*.ps1`
- `tests/Core/*.Tests.ps1` — Tests for `modules/Core/*.ps1`

**Pattern for testing an assessment module** (see `tests/Security/Test-MFAConfiguration.Tests.ps1`):
1. Dot-source `TestHelpers.ps1` and the module under test in `BeforeAll`
2. Stub any orchestrator-provided helpers (e.g., `function Get-AuthRegistrationDetails { @() }`)
3. `Mock Get-MgUser { ... }` and other Graph cmdlets with `New-Mock*` factories
4. Call the function and validate with `Assert-AssessmentResult $result` (checks all 9 required properties + enum values)
5. Test threshold boundaries, edge cases (empty data, API errors), and detail properties

**Core modules** (scoring, CIS) need no external mocks — they accept `$AssessmentResults` arrays built with `New-MockAssessmentResult`.

## Developer Workflow

```powershell
# Install dependencies (PS 7+, Graph SDK v2, EXO v3)
.\Install-Prerequisites.ps1

# Run all tests (no tenant connection needed)
.\Invoke-Tests.ps1

# Run full assessment (opens browser for auth)
.\Start-M365Assessment.ps1

# Run specific modules only
.\Start-M365Assessment.ps1 -Modules Security,Exchange -OutputFormat HTML

# Save/compare baselines
.\Start-M365Assessment.ps1 -SaveBaseline -BaselineName "Pre-ZeroTrust"
.\Start-M365Assessment.ps1 -CompareToBaseline "Pre-ZeroTrust"

# Lint markdown
npx markdownlint-cli2 "**/*.md"
```

## Dependencies

- **PowerShell 7.0+** (`#Requires -Version 7.0`)
- **Pester 5.0+** (auto-installed by `Invoke-Tests.ps1`)
- **Microsoft.Graph.*** v2.0+ (9 sub-modules: Authentication, Users, Identity.DirectoryManagement, Identity.SignIns, Identity.Governance, Groups, Security, Applications, Reports)
- **ExchangeOnlineManagement** v3.0+
- WAM broker is disabled at startup (`$env:AZURE_IDENTITY_DISABLE_BROKER = "true"`)
