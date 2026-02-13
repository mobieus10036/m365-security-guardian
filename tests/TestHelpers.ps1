<#
.SYNOPSIS
    Shared test helpers and assertion functions for M365 Security Guardian.

.DESCRIPTION
    Provides reusable mock data factories, result contract validators, and
    common Pester helpers used across all test files.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

# ── Valid enum values (single source of truth for tests) ──────────────────────
$script:ValidStatuses   = @('Pass', 'Warning', 'Fail', 'Info')
$script:ValidSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
$script:ValidCategories = @('Security', 'Exchange', 'Licensing')

$script:RequiredResultProperties = @(
    'CheckName', 'Category', 'Status', 'Severity',
    'Message', 'Details', 'Recommendation',
    'DocumentationUrl', 'RemediationSteps'
)

# ── Result Contract Validator ─────────────────────────────────────────────────
function Assert-AssessmentResult {
    <#
    .SYNOPSIS
        Validates that an assessment result object conforms to the standard contract.
    .DESCRIPTION
        Checks that all required properties exist and contain valid values.
        Use inside Pester It blocks: Assert-AssessmentResult $result
    #>
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result
    )

    # All required properties must exist
    foreach ($prop in $script:RequiredResultProperties) {
        $Result.PSObject.Properties.Name | Should -Contain $prop -Because "Result must have '$prop' property"
    }

    # Enum constraints
    $Result.Status   | Should -BeIn $script:ValidStatuses   -Because "Status must be one of: $($script:ValidStatuses -join ', ')"
    $Result.Severity | Should -BeIn $script:ValidSeverities -Because "Severity must be one of: $($script:ValidSeverities -join ', ')"
    $Result.Category | Should -BeIn $script:ValidCategories -Because "Category must be one of: $($script:ValidCategories -join ', ')"

    # Type constraints
    $Result.CheckName        | Should -BeOfType [string]
    $Result.Message          | Should -BeOfType [string]
    $Result.Recommendation   | Should -BeOfType [string]
    $Result.DocumentationUrl | Should -BeOfType [string]
    $Result.RemediationSteps | Should -Not -BeNullOrEmpty -Because "RemediationSteps must be an array (can be empty @())" -ErrorAction SilentlyContinue
}

# ── Mock Data Factories ───────────────────────────────────────────────────────

function New-MockUser {
    <#
    .SYNOPSIS
        Creates a mock Microsoft Graph user object.
    #>
    param(
        [string]$DisplayName = "Test User",
        [string]$UserPrincipalName = "testuser@contoso.com",
        [string]$Id = [guid]::NewGuid().ToString(),
        [bool]$AccountEnabled = $true
    )

    [PSCustomObject]@{
        Id                = $Id
        DisplayName       = $DisplayName
        UserPrincipalName = $UserPrincipalName
        AccountEnabled    = $AccountEnabled
    }
}

function New-MockAuthRegistration {
    <#
    .SYNOPSIS
        Creates a mock auth method registration detail object.
    #>
    param(
        [string]$UserPrincipalName = "testuser@contoso.com",
        [bool]$IsMfaRegistered = $true,
        [string[]]$MethodsRegistered = @('microsoftAuthenticator')
    )

    [PSCustomObject]@{
        UserPrincipalName = $UserPrincipalName
        IsMfaRegistered   = $IsMfaRegistered
        MethodsRegistered = $MethodsRegistered
    }
}

function New-MockDirectoryRole {
    <#
    .SYNOPSIS
        Creates a mock directory role object.
    #>
    param(
        [string]$DisplayName = "Global Administrator",
        [string]$Id = [guid]::NewGuid().ToString()
    )

    [PSCustomObject]@{
        Id          = $Id
        DisplayName = $DisplayName
    }
}

function New-MockRoleMember {
    <#
    .SYNOPSIS
        Creates a mock directory role member object with AdditionalProperties.
    #>
    param(
        [string]$UserPrincipalName = "admin@contoso.com",
        [string]$DisplayName = "Admin User",
        [string]$Id = [guid]::NewGuid().ToString()
    )

    [PSCustomObject]@{
        Id                   = $Id
        AdditionalProperties = @{
            userPrincipalName = $UserPrincipalName
            displayName       = $DisplayName
        }
    }
}

function New-MockConfig {
    <#
    .SYNOPSIS
        Creates a default test configuration object matching assessment-config.json structure.
    #>
    param(
        [int]$MFAThreshold = 95,
        [int]$MaxPrivilegedAccounts = 3
    )

    [PSCustomObject]@{
        Security = [PSCustomObject]@{
            MFAEnforcementThreshold = $MFAThreshold
            MaxPrivilegedAccounts   = $MaxPrivilegedAccounts
            BreakGlassAccounts      = @()
            ServiceAccountExclusions = @()
        }
        Scoring = [PSCustomObject]@{
            Enabled     = $true
            RiskWeights = [PSCustomObject]@{
                'MFA Enforcement'                     = 12
                'Privileged Account Security'         = 10
                'Conditional Access Policies'         = 15
                'Email Authentication (SPF/DKIM/DMARC)' = 8
                'License Optimization'                = 5
            }
        }
        Exchange = [PSCustomObject]@{
            SPFRecordRequired = $true
        }
        Licensing = [PSCustomObject]@{
            InactiveDaysThreshold = 90
        }
        CISBenchmark = [PSCustomObject]@{
            Enabled       = $true
            Version       = "3.1.2"
            IncludeLevels = @(1, 2)
        }
    }
}

function New-MockAssessmentResult {
    <#
    .SYNOPSIS
        Creates a valid assessment result for use in scoring/CIS tests.
    #>
    param(
        [string]$CheckName = "MFA Enforcement",
        [string]$Category = "Security",
        [string]$Status = "Pass",
        [string]$Severity = "Critical",
        [string]$Message = "Test finding"
    )

    [PSCustomObject]@{
        CheckName        = $CheckName
        Category         = $Category
        Status           = $Status
        Severity         = $Severity
        Message          = $Message
        Details          = @{ TestMetric = 100 }
        Recommendation   = "Test recommendation"
        DocumentationUrl = "https://learn.microsoft.com/test"
        RemediationSteps = @("Step 1", "Step 2")
    }
}
