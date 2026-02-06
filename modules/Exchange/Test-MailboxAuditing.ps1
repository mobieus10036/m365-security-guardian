<#
.SYNOPSIS
    Tests mailbox auditing configuration.

.DESCRIPTION
    Verifies that mailbox auditing is enabled for compliance and
    security monitoring.

.PARAMETER Config
    Configuration object.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-MailboxAuditing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing mailbox auditing configuration..."

        # Check organization-wide mailbox auditing
        $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
        
        $auditDisabledByDefault = $orgConfig.AuditDisabled

        # Sample check of mailboxes (first 100)
        $mailboxes = Get-EXOMailbox -ResultSize 100 -Properties AuditEnabled,UserPrincipalName,DisplayName,PrimarySmtpAddress,WhenCreated -ErrorAction SilentlyContinue
        
        if ($null -eq $mailboxes) {
            return [PSCustomObject]@{
                CheckName = "Mailbox Auditing"
                Category = "Exchange"
                Status = "Info"
                Severity = "Info"
                Message = "Unable to retrieve mailbox information"
                Details = @{}
                NonCompliantMailboxes = @()
                Recommendation = "Verify Exchange Online connection and permissions"
                DocumentationUrl = "https://learn.microsoft.com/purview/audit-mailboxes"
                RemediationSteps = @()
            }
        }

        $totalSampled = @($mailboxes).Count
        $auditEnabled = @($mailboxes | Where-Object { $_.AuditEnabled -eq $true }).Count
        $auditPercentage = if ($totalSampled -gt 0) {
            [math]::Round(($auditEnabled / $totalSampled) * 100, 1)
        } else { 0 }

        # Capture mailboxes with auditing disabled
        $nonCompliantMailboxes = $mailboxes | 
            Where-Object { $_.AuditEnabled -ne $true } |
            Select-Object @{N='UserPrincipalName';E={$_.UserPrincipalName}},
                         @{N='DisplayName';E={$_.DisplayName}},
                         @{N='PrimarySmtpAddress';E={$_.PrimarySmtpAddress}},
                         @{N='WhenCreated';E={$_.WhenCreated}},
                         @{N='AuditEnabled';E={$_.AuditEnabled}}

        # Determine status
        $status = "Pass"
        $severity = "Low"
        $auditDisabledCount = $totalSampled - $auditEnabled

        if ($auditDisabledByDefault) {
            $status = "Fail"
            $severity = "High"
            $message = "Mailbox auditing is disabled by default at organization level"
        }
        elseif ($auditPercentage -lt 90) {
            $status = "Warning"
            $severity = "Medium"
            $message = "Mailbox auditing: $auditPercentage% enabled (sampled $totalSampled mailboxes, $auditDisabledCount without auditing)"
            # Add sample of non-compliant mailboxes to message
            if ($nonCompliantMailboxes.Count -gt 0 -and $nonCompliantMailboxes.Count -le 10) {
                $sampleList = ($nonCompliantMailboxes.UserPrincipalName -join ", ")
                $message += ". Non-compliant: $sampleList"
            }
            elseif ($nonCompliantMailboxes.Count -gt 10) {
                $sampleList = ($nonCompliantMailboxes | Select-Object -First 5 -ExpandProperty UserPrincipalName) -join ", "
                $message += ". Non-compliant (sample): $sampleList (and $($nonCompliantMailboxes.Count - 5) more...)"
            }
        }
        else {
            $message = "Mailbox auditing enabled ($auditPercentage% of sampled mailboxes)"
            if ($auditDisabledCount -gt 0) {
                $message += " - $auditDisabledCount mailbox(es) without auditing"
            }
        }

        return [PSCustomObject]@{
            CheckName = "Mailbox Auditing"
            Category = "Exchange"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                OrgAuditDisabled = $auditDisabledByDefault
                SampledMailboxes = $totalSampled
                AuditEnabledMailboxes = $auditEnabled
                AuditDisabledMailboxes = $auditDisabledCount
                AuditPercentage = $auditPercentage
                NonCompliantCount = $nonCompliantMailboxes.Count
            }
            NonCompliantMailboxes = $nonCompliantMailboxes
            Recommendation = if ($status -ne "Pass") {
                if ($auditDisabledByDefault) {
                    "CRITICAL: Enable mailbox auditing organization-wide immediately. Run: Set-OrganizationConfig -AuditDisabled `$false"
                }
                else {
                    "Enable auditing for $auditDisabledCount mailbox(es). See NonCompliantMailboxes list in JSON/CSV report for details."
                }
            } else {
                if ($auditDisabledCount -gt 0) {
                    "Consider enabling auditing for remaining $auditDisabledCount mailbox(es) for complete coverage."
                }
                else {
                    "Mailbox auditing is enabled. Review audit logs regularly for suspicious activity."
                }
            }
            DocumentationUrl = "https://learn.microsoft.com/purview/audit-mailboxes"
            RemediationSteps = @(
                "1. Connect to Exchange Online PowerShell"
                "2. For organization-wide: Set-OrganizationConfig -AuditDisabled `$false"
                "3. For specific mailboxes: Set-Mailbox -Identity user@domain.com -AuditEnabled `$true"
                "4. Bulk enable from CSV: Import-Csv report.csv | ForEach-Object { Set-Mailbox -Identity `$_.UserPrincipalName -AuditEnabled `$true }"
                "5. Verify auditing: Get-Mailbox -ResultSize Unlimited | Where-Object { -not `$_.AuditEnabled }"
                "6. Review audit logs in Microsoft Purview compliance portal"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Mailbox Auditing"
            Category = "Exchange"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess mailbox auditing: $_"
            Details = @{ Error = $_.Exception.Message }
            NonCompliantMailboxes = @()
            Recommendation = "Ensure Exchange Online PowerShell is connected"
            DocumentationUrl = "https://learn.microsoft.com/purview/audit-mailboxes"
            RemediationSteps = @()
        }
    }
}
