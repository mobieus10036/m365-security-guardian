<#
.SYNOPSIS
    Validates assessment result objects against the required schema contract.

.DESCRIPTION
    Ensures all assessment module outputs comply with the standard schema:
    - All 9 required properties present and correctly typed
    - Enum values strictly enforced (Status, Severity, Category)
    - No null/empty required fields
    - Details hashtable is properly structured

    Used by the orchestrator to catch invalid results early and prevent
    downstream reporting failures.

.PARAMETER Result
    The assessment result object to validate.

.PARAMETER Strict
    If $true, throws on schema violations. If $false, logs warning and returns $false.

.OUTPUTS
    [bool] $true if result is valid; $false if invalid.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

# Define valid enum values
$validStatuses = @('Pass', 'Warning', 'Fail', 'Info')
$validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
$validCategories = @('Security', 'Exchange', 'Licensing')

function Test-AssessmentResultSchema {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory=$false)]
        [bool]$Strict = $false
    )

    $requiredProperties = @(
        'CheckName', 'Category', 'Status', 'Severity', 'Message',
        'Details', 'Recommendation', 'DocumentationUrl', 'RemediationSteps'
    )

    # Check all required properties exist
    foreach ($prop in $requiredProperties) {
        if ($null -eq $Result.PSObject.Properties[$prop]) {
            $msg = "Assessment result missing required property: $prop"
            if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
        }
    }

    # Validate enum values
    if ($Result.Status -notin $validStatuses) {
        $msg = "Invalid Status value: '$($Result.Status)'. Must be one of: $($validStatuses -join ', ')"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    if ($Result.Severity -notin $validSeverities) {
        $msg = "Invalid Severity value: '$($Result.Severity)'. Must be one of: $($validSeverities -join ', ')"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    if ($Result.Category -notin $validCategories) {
        $msg = "Invalid Category value: '$($Result.Category)'. Must be one of: $($validCategories -join ', ')"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    # Validate required field values
    if ([string]::IsNullOrWhiteSpace($Result.CheckName)) {
        $msg = "CheckName cannot be null or empty"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    if ([string]::IsNullOrWhiteSpace($Result.Message)) {
        $msg = "Message cannot be null or empty"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    if ([string]::IsNullOrWhiteSpace($Result.Recommendation)) {
        $msg = "Recommendation cannot be null or empty"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    if ([string]::IsNullOrWhiteSpace($Result.DocumentationUrl)) {
        $msg = "DocumentationUrl cannot be null or empty"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    # Validate Details is a hashtable (not null)
    if ($null -eq $Result.Details) {
        $msg = "Details cannot be null (should be @{} at minimum)"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    # Validate RemediationSteps is array (can be empty array)
    if ($null -ne $Result.RemediationSteps -and $Result.RemediationSteps -isnot [array]) {
        $msg = "RemediationSteps must be an array"
        if ($Strict) { throw $msg } else { Write-Warning $msg; return $false }
    }

    return $true
}

function Assert-AssessmentResult {
    <#
    .SYNOPSIS
        Asserts that an assessment result is valid; throws if not.

    .PARAMETER Result
        The result object to assert on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$Result
    )

    process {
        $valid = Test-AssessmentResultSchema -Result $Result -Strict $false
        if (-not $valid) {
            throw "Assessment result failed schema validation: CheckName='$($Result.CheckName)'"
        }
        return $Result
    }
}

function Get-AssessmentSchemaContract {
    <#
    .SYNOPSIS
        Returns the official assessment result schema for documentation.

    .OUTPUTS
        [string] Formatted schema documentation.
    #>
    return @"
=== M365 Security Guardian - Assessment Result Schema ===

REQUIRED PROPERTIES (all 9):
  - CheckName          [string]   : Unique check identifier (matches CIS assessmentKey)
  - Category           [string]   : One of: Security | Exchange | Licensing
  - Status             [string]   : One of: Pass | Warning | Fail | Info
  - Severity           [string]   : One of: Critical | High | Medium | Low | Info
  - Message            [string]   : Human-readable summary (e.g., "MFA adoption: 95.2%")
  - Details            [hashtable]: Structured metrics ({MfaPercentage = 95.2})
  - Recommendation     [string]   : Remediation guidance (non-empty)
  - DocumentationUrl   [string]   : Link to guidance (valid URL)
  - RemediationSteps   [array]    : Ordered steps (can be empty @())

OPTIONAL PROPERTIES (check-specific):
  - UsersWithoutMFA, PrivilegedAccounts, DomainDetails, etc.
  - Used by Export-DetailedCsvReports for additional CSV export files

CONTRACT RULES:
  1. Every Test-* module MUST return exactly ONE [PSCustomObject]
  2. All 9 required properties MUST be populated (no $null for required fields)
  3. Status/Severity/Category MUST use exact casing (Pass, not "pass" or "PASS")
  4. CheckName must be unique per module (orchestrator uses it as key)
  5. Never return $null or multiple objects
  6. On error, return same object shape with Status="Info", Severity="Info"
  7. Details should capture metrics needed for scoring/reporting

EXAMPLE (valid):
  [PSCustomObject]@{
    CheckName = "MFA Enforcement"
    Category = "Security"
    Status = "Pass"
    Severity = "Critical"
    Message = "MFA enabled for 42/44 users (95.5%)"
    Details = @{ MfaPercentage=95.5; UsersWithoutMFA=2 }
    Recommendation = "Enable MFA for remaining 2 users immediately"
    DocumentationUrl = "https://learn.microsoft.com/azure/..."
    RemediationSteps = @("1. Navigate to...", "2. Enable...")
    UsersWithoutMFA = @([PSCustomObject]@{UserPrincipalName="user@contoso.com"})
  }
"@
}

<#
    Note: This file is dot-sourced (not imported as a module), so we do not
    call Export-ModuleMember here.
#>
