<#
.SYNOPSIS
    Tests compliance policy coverage across Microsoft Purview and Exchange compliance controls.

.DESCRIPTION
    Evaluates whether core compliance controls are configured:
    - Data Loss Prevention (DLP) policies
    - Retention compliance policies
    - Sensitivity labels and label publishing

.PARAMETER Config
    Configuration object containing compliance requirements.

.OUTPUTS
    PSCustomObject containing compliance coverage assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 1.0.0
    Created with assistance from GitHub Copilot
#>

function Test-CompliancePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing compliance policy coverage..."

        $requireDlp = if ($null -ne $Config.Compliance.DLPPoliciesRequired) { $Config.Compliance.DLPPoliciesRequired } else { $true }
        $requireRetention = if ($null -ne $Config.Compliance.RetentionPoliciesRequired) { $Config.Compliance.RetentionPoliciesRequired } else { $true }
        $requireSensitivity = if ($null -ne $Config.Compliance.SensitivityLabelsRequired) { $Config.Compliance.SensitivityLabelsRequired } else { $true }

        $dlpPolicies = @()
        $retentionPolicies = @()
        $labels = @()
        $labelPolicies = @()

        try {
            $dlpPolicies = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Verbose "Could not retrieve DLP policies: $_"
        }

        try {
            $retentionPolicies = @(Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Verbose "Could not retrieve retention policies: $_"
        }

        try {
            $labels = @(Get-Label -ErrorAction SilentlyContinue)
            $labelPolicies = @(Get-LabelPolicy -ErrorAction SilentlyContinue)
        }
        catch {
            Write-Verbose "Could not retrieve sensitivity labels or label policies: $_"
        }

        $hasDlp = $dlpPolicies.Count -gt 0
        $hasRetention = $retentionPolicies.Count -gt 0
        $hasSensitivity = ($labels.Count -gt 0) -and ($labelPolicies.Count -gt 0)

        $issues = @()
        if ($requireDlp -and -not $hasDlp) {
            $issues += "No DLP policies found"
        }
        if ($requireRetention -and -not $hasRetention) {
            $issues += "No retention policies found"
        }
        if ($requireSensitivity -and -not $hasSensitivity) {
            $issues += "Sensitivity labeling is incomplete (labels and publishing policies required)"
        }

        $status = "Pass"
        $severity = "Low"

        $requiredChecks = @()
        if ($requireDlp) { $requiredChecks += 'DLP' }
        if ($requireRetention) { $requiredChecks += 'Retention' }
        if ($requireSensitivity) { $requiredChecks += 'Sensitivity' }

        $missingRequired = $issues.Count
        if ($missingRequired -gt 0) {
            $status = if ($missingRequired -ge 2) { "Fail" } else { "Warning" }
            $severity = if ($missingRequired -ge 2) { "High" } else { "Medium" }
        }

        $message = "Compliance controls: DLP=$hasDlp, Retention=$hasRetention, Sensitivity=$hasSensitivity"
        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues -join '; ')"
        }

        return [PSCustomObject]@{
            CheckName = "Compliance Policy Coverage"
            Category = "Exchange"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                DlpPoliciesRequired = $requireDlp
                RetentionPoliciesRequired = $requireRetention
                SensitivityLabelsRequired = $requireSensitivity
                DlpPolicyCount = $dlpPolicies.Count
                RetentionPolicyCount = $retentionPolicies.Count
                SensitivityLabelCount = $labels.Count
                LabelPolicyCount = $labelPolicies.Count
                HasDlpPolicies = $hasDlp
                HasRetentionPolicies = $hasRetention
                HasSensitivityLabels = $hasSensitivity
                MissingRequiredControls = $missingRequired
            }
            Recommendation = if ($status -eq "Pass") {
                "Compliance baseline controls are present. Continue periodic review and control testing."
            } else {
                "Implement missing compliance controls in Microsoft Purview: DLP, Retention, and Sensitivity Label publishing."
            }
            DocumentationUrl = "https://learn.microsoft.com/purview/"
            RemediationSteps = @(
                "1. Open Microsoft Purview compliance portal",
                "2. Configure Data Loss Prevention policies for key data types",
                "3. Configure retention policies for required business and regulatory records",
                "4. Create sensitivity labels and publish them via label policies",
                "5. Validate policy scope and monitor policy match/activity reports"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Compliance Policy Coverage"
            Category = "Exchange"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess compliance policy coverage: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Exchange Online / Purview compliance connectivity and required permissions"
            DocumentationUrl = "https://learn.microsoft.com/purview/"
            RemediationSteps = @()
        }
    }
}
