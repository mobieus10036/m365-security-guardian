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

        # Full tenant mailbox assessment (streamed for memory safety)
        $mailboxQuery = Get-EXOMailbox -ResultSize Unlimited -Properties AuditEnabled,UserPrincipalName,DisplayName,PrimarySmtpAddress,WhenCreated -ErrorAction SilentlyContinue

        if ($null -eq $mailboxQuery) {
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

        $maxDetailedNonCompliant = if ($Config.Exchange.MaxDetailedNonCompliantMailboxes) {
            [int]$Config.Exchange.MaxDetailedNonCompliantMailboxes
        } else { 5000 }

        $totalAssessed = 0
        $auditEnabled = 0
        $nonCompliantCount = 0
        $nonCompliantMailboxes = [System.Collections.Generic.List[object]]::new()

        $mailboxQuery | ForEach-Object {
            $totalAssessed++

            if ($_.AuditEnabled -eq $true) {
                $auditEnabled++
            }
            else {
                $nonCompliantCount++
                if ($nonCompliantMailboxes.Count -lt $maxDetailedNonCompliant) {
                    $nonCompliantMailboxes.Add([PSCustomObject]@{
                        UserPrincipalName = $_.UserPrincipalName
                        DisplayName = $_.DisplayName
                        PrimarySmtpAddress = $_.PrimarySmtpAddress
                        WhenCreated = $_.WhenCreated
                        AuditEnabled = $_.AuditEnabled
                    })
                }
            }
        }

        $auditPercentage = if ($totalAssessed -gt 0) {
            [math]::Round(($auditEnabled / $totalAssessed) * 100, 1)
        } else { 0 }
        $nonCompliantTruncated = $nonCompliantCount -gt $nonCompliantMailboxes.Count

        # Determine status
        $status = "Pass"
        $severity = "Low"
        $auditDisabledCount = $nonCompliantCount

        if ($auditDisabledByDefault) {
            $status = "Fail"
            $severity = "High"
            $message = "Mailbox auditing is disabled by default at organization level"
        }
        elseif ($auditPercentage -lt 90) {
            $status = "Warning"
            $severity = "Medium"
            $message = "Mailbox auditing: $auditPercentage% enabled ($totalAssessed mailboxes assessed, $auditDisabledCount without auditing)"
            # Add sample of non-compliant mailboxes to message
            if ($nonCompliantMailboxes.Count -gt 0 -and $nonCompliantMailboxes.Count -le 10) {
                $sampleList = ($nonCompliantMailboxes.UserPrincipalName -join ", ")
                $message += ". Non-compliant: $sampleList"
            }
            elseif ($nonCompliantMailboxes.Count -gt 10) {
                $sampleList = ($nonCompliantMailboxes | Select-Object -First 5 -ExpandProperty UserPrincipalName) -join ", "
                $remaining = [math]::Max(0, $nonCompliantCount - 5)
                $message += ". Non-compliant (sample): $sampleList (and $remaining more...)"
            }
            if ($nonCompliantTruncated) {
                $message += " Detailed non-compliant export capped at $maxDetailedNonCompliant records for performance."
            }
        }
        else {
            $message = "Mailbox auditing enabled ($auditPercentage% of assessed mailboxes)"
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
                TotalMailboxesAssessed = $totalAssessed
                # Backward compatibility for existing report consumers
                SampledMailboxes = $totalAssessed
                AuditEnabledMailboxes = $auditEnabled
                AuditDisabledMailboxes = $auditDisabledCount
                AuditPercentage = $auditPercentage
                NonCompliantCount = $nonCompliantCount
                NonCompliantExportCount = $nonCompliantMailboxes.Count
                NonCompliantTruncated = $nonCompliantTruncated
                MaxDetailedNonCompliantMailboxes = $maxDetailedNonCompliant
            }
            NonCompliantMailboxes = @($nonCompliantMailboxes)
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
