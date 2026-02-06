<#
.SYNOPSIS
    Tests email security configuration including anti-spam and anti-malware.

.DESCRIPTION
    Evaluates Exchange Online Protection settings and Defender for Office 365
    security policies.

.PARAMETER Config
    Configuration object.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-EmailSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing email security configuration..."

        # Get anti-spam policies
        $antispamPolicies = Get-HostedOutboundSpamFilterPolicy -ErrorAction SilentlyContinue
        $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction SilentlyContinue
        
        # Check for Safe Attachments and Safe Links (Defender for Office 365)
        $safeAttachmentPolicies = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue
        $safeLinksPolicies = Get-SafeLinksPolicy -ErrorAction SilentlyContinue

        $hasAntiSpam = $null -ne $antispamPolicies
        $hasMalwareFilter = $null -ne $malwarePolicies
        $hasSafeAttachments = $null -ne $safeAttachmentPolicies -and @($safeAttachmentPolicies).Count -gt 0
        $hasSafeLinks = $null -ne $safeLinksPolicies -and @($safeLinksPolicies).Count -gt 0

        # Build structured findings
        $findings = @()
        
        $findings += [PSCustomObject]@{
            Setting = "Anti-Spam Protection"
            Value = if ($hasAntiSpam) { "Enabled" } else { "Not Configured" }
            Risk = if ($hasAntiSpam) { "Low" } else { "High" }
            PolicyCount = if ($antispamPolicies) { @($antispamPolicies).Count } else { 0 }
        }
        
        $findings += [PSCustomObject]@{
            Setting = "Malware Filter"
            Value = if ($hasMalwareFilter) { "Enabled" } else { "Not Configured" }
            Risk = if ($hasMalwareFilter) { "Low" } else { "High" }
            PolicyCount = if ($malwarePolicies) { @($malwarePolicies).Count } else { 0 }
        }
        
        $findings += [PSCustomObject]@{
            Setting = "Safe Attachments (Defender for O365)"
            Value = if ($hasSafeAttachments) { "Enabled ($(@($safeAttachmentPolicies).Count) policies)" } else { "Not Configured" }
            Risk = if ($hasSafeAttachments) { "Low" } else { "Medium" }
            PolicyCount = if ($safeAttachmentPolicies) { @($safeAttachmentPolicies).Count } else { 0 }
        }
        
        $findings += [PSCustomObject]@{
            Setting = "Safe Links (Defender for O365)"
            Value = if ($hasSafeLinks) { "Enabled ($(@($safeLinksPolicies).Count) policies)" } else { "Not Configured" }
            Risk = if ($hasSafeLinks) { "Low" } else { "Medium" }
            PolicyCount = if ($safeLinksPolicies) { @($safeLinksPolicies).Count } else { 0 }
        }

        # Determine status
        $status = "Pass"
        $severity = "Low"
        $issues = @()
        $recommendations = @()

        if (-not $hasMalwareFilter) {
            $status = "Warning"
            $severity = "Medium"
            $issues += "No malware filter policies found"
        }

        if (-not $hasSafeAttachments) {
            if ($status -eq "Pass") { $status = "Warning" }
            $severity = "Medium"
            $issues += "No Safe Attachments policies (Defender for Office 365)"
            $recommendations += "Enable Safe Attachments for malware protection"
        }

        if (-not $hasSafeLinks) {
            if ($status -eq "Pass") { $status = "Warning" }
            $issues += "No Safe Links policies (Defender for Office 365)"
            $recommendations += "Enable Safe Links for URL protection"
        }

        $message = "Email security: Anti-spam=$hasAntiSpam, Malware=$hasMalwareFilter, Safe Attachments=$hasSafeAttachments, Safe Links=$hasSafeLinks"
        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues -join '; ')"
        }

        return [PSCustomObject]@{
            CheckName = "Email Security Configuration"
            Category = "Exchange"
            Status = $status
            Severity = $severity
            Message = $message
            Findings = $findings
            Issues = $issues
            Details = @{
                HasAntiSpam = $hasAntiSpam
                HasMalwareFilter = $hasMalwareFilter
                HasSafeAttachments = $hasSafeAttachments
                HasSafeLinks = $hasSafeLinks
                SafeAttachmentPolicies = if ($safeAttachmentPolicies) { @($safeAttachmentPolicies).Count } else { 0 }
                SafeLinksPolicies = if ($safeLinksPolicies) { @($safeLinksPolicies).Count } else { 0 }
            }
            Recommendation = if ($recommendations.Count -gt 0) {
                $recommendations -join ". "
            } else {
                "Email security policies are configured. Review settings regularly."
            }
            DocumentationUrl = "https://learn.microsoft.com/defender-office-365/mdo-deployment-guide"
            RemediationSteps = @(
                "1. Navigate to Microsoft Defender portal (security.microsoft.com)"
                "2. Go to Email & collaboration > Policies & rules"
                "3. Enable Safe Attachments and Safe Links policies"
                "4. Configure anti-malware and anti-spam settings"
                "5. Enable Zero-hour auto purge (ZAP)"
                "6. Review and tune policies based on threat data"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Email Security Configuration"
            Category = "Exchange"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess email security: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Ensure Exchange Online PowerShell is connected"
            DocumentationUrl = "https://learn.microsoft.com/defender-office-365/mdo-deployment-guide"
            RemediationSteps = @()
        }
    }
}
