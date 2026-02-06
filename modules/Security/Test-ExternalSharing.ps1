<#
.SYNOPSIS
    Tests SharePoint and OneDrive external sharing configuration.

.DESCRIPTION
    Evaluates external sharing settings for SharePoint and OneDrive,
    identifying overly permissive configurations that could lead to
    data leakage.

.PARAMETER Config
    Configuration object (reserved for future use).

.OUTPUTS
    PSCustomObject containing external sharing assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
    Requires: SharePoint Online Management Shell module
#>

function Test-ExternalSharing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing external sharing configuration..."

        # Check if SharePoint module is available
        $spoModule = Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable
        if (-not $spoModule) {
            # Try to use PnP.PowerShell as alternative
            $pnpModule = Get-Module -Name PnP.PowerShell -ListAvailable
            if (-not $pnpModule) {
                return [PSCustomObject]@{
                    CheckName = "External Sharing Configuration"
                    Category = "Security"
                    Status = "Info"
                    Severity = "Info"
                    Message = "SharePoint Online module not available. Install Microsoft.Online.SharePoint.PowerShell or PnP.PowerShell to enable this check."
                    Details = @{}
                    Recommendation = "Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser"
                    DocumentationUrl = "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off"
                    RemediationSteps = @("Install SharePoint Online Management Shell to enable this assessment")
                }
            }
        }

        # Try to get SharePoint tenant settings via Graph API first (more accessible)
        $sharepointSettings = $null
        $oneDriveSettings = $null
        $issues = @()
        $findings = @()
        
        try {
            # Use Graph API to get SharePoint settings
            $sharepointSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/admin/sharepoint/settings" -ErrorAction Stop
        }
        catch {
            Write-Verbose "Could not get SharePoint settings via Graph: $_"
        }

        if ($sharepointSettings) {
            # Analyze sharing capability
            $sharingCapability = $sharepointSettings.sharingCapability
            $sharingCapabilityText = switch ($sharingCapability) {
                'disabled' { 'Disabled (Most Secure)' }
                'externalUserSharingOnly' { 'Existing Guests Only' }
                'externalUserAndGuestSharing' { 'New and Existing Guests' }
                'anyone' { 'Anyone (Anonymous Links)' }
                default { $sharingCapability }
            }

            $findings += [PSCustomObject]@{
                Setting = "SharePoint External Sharing"
                Value = $sharingCapabilityText
                Risk = if ($sharingCapability -eq 'anyone') { 'High' } 
                       elseif ($sharingCapability -eq 'externalUserAndGuestSharing') { 'Medium' }
                       else { 'Low' }
            }

            if ($sharingCapability -eq 'anyone') {
                $issues += "SharePoint allows anonymous sharing links (Anyone)"
            }

            # Check OneDrive sharing capability if available
            $oneDriveSharingCapability = $sharepointSettings.oneDriveSharingCapability
            if ($oneDriveSharingCapability) {
                $oneDriveSharingText = switch ($oneDriveSharingCapability) {
                    'disabled' { 'Disabled (Most Secure)' }
                    'externalUserSharingOnly' { 'Existing Guests Only' }
                    'externalUserAndGuestSharing' { 'New and Existing Guests' }
                    'anyone' { 'Anyone (Anonymous Links)' }
                    default { $oneDriveSharingCapability }
                }

                $findings += [PSCustomObject]@{
                    Setting = "OneDrive External Sharing"
                    Value = $oneDriveSharingText
                    Risk = if ($oneDriveSharingCapability -eq 'anyone') { 'High' } 
                           elseif ($oneDriveSharingCapability -eq 'externalUserAndGuestSharing') { 'Medium' }
                           else { 'Low' }
                }

                if ($oneDriveSharingCapability -eq 'anyone') {
                    $issues += "OneDrive allows anonymous sharing links (Anyone)"
                }
            }

            # Check default sharing link type
            $defaultLinkType = $sharepointSettings.defaultSharingLinkType
            if ($defaultLinkType) {
                $linkTypeText = switch ($defaultLinkType) {
                    'none' { 'None (User chooses)' }
                    'direct' { 'Specific People (Most Secure)' }
                    'internal' { 'People in Organization' }
                    'anonymousAccess' { 'Anyone with Link' }
                    default { $defaultLinkType }
                }

                $findings += [PSCustomObject]@{
                    Setting = "Default Sharing Link Type"
                    Value = $linkTypeText
                    Risk = if ($defaultLinkType -eq 'anonymousAccess') { 'High' }
                           elseif ($defaultLinkType -eq 'none') { 'Medium' }
                           else { 'Low' }
                }

                if ($defaultLinkType -eq 'anonymousAccess') {
                    $issues += "Default sharing link type is 'Anyone' (anonymous)"
                }
            }

            # Check if external users can reshare
            $allowExternalReshare = $sharepointSettings.isResharingByExternalUsersEnabled
            if ($null -ne $allowExternalReshare) {
                $findings += [PSCustomObject]@{
                    Setting = "External Users Can Reshare"
                    Value = if ($allowExternalReshare) { 'Yes' } else { 'No' }
                    Risk = if ($allowExternalReshare) { 'Medium' } else { 'Low' }
                }

                if ($allowExternalReshare) {
                    $issues += "External users can reshare content"
                }
            }

            # Check anonymous link expiration
            $anonymousLinkExpiration = $sharepointSettings.externalUserExpirationRequired
            $anonymousLinkExpirationDays = $sharepointSettings.externalUserExpireInDays
            
            if ($anonymousLinkExpiration -eq $false -and $sharingCapability -eq 'anyone') {
                $findings += [PSCustomObject]@{
                    Setting = "Anonymous Link Expiration"
                    Value = "Not Required"
                    Risk = "High"
                }
                $issues += "Anonymous links do not expire automatically"
            }
            elseif ($anonymousLinkExpiration -and $anonymousLinkExpirationDays) {
                $findings += [PSCustomObject]@{
                    Setting = "Anonymous Link Expiration"
                    Value = "$anonymousLinkExpirationDays days"
                    Risk = if ($anonymousLinkExpirationDays -gt 90) { 'Medium' } else { 'Low' }
                }

                if ($anonymousLinkExpirationDays -gt 90) {
                    $issues += "Anonymous link expiration is set to $anonymousLinkExpirationDays days (consider 30-90 days)"
                }
            }

            # Check allowed domains
            $sharingDomainRestrictionMode = $sharepointSettings.sharingDomainRestrictionMode
            if ($sharingDomainRestrictionMode -eq 'none' -and $sharingCapability -in @('externalUserAndGuestSharing', 'anyone')) {
                $findings += [PSCustomObject]@{
                    Setting = "Sharing Domain Restrictions"
                    Value = "No Restrictions"
                    Risk = "Medium"
                }
                $issues += "No domain restrictions on external sharing (any domain can receive shares)"
            }
            elseif ($sharingDomainRestrictionMode -eq 'allowList') {
                $findings += [PSCustomObject]@{
                    Setting = "Sharing Domain Restrictions"
                    Value = "Allow List Configured"
                    Risk = "Low"
                }
            }
            elseif ($sharingDomainRestrictionMode -eq 'blockList') {
                $findings += [PSCustomObject]@{
                    Setting = "Sharing Domain Restrictions"
                    Value = "Block List Configured"
                    Risk = "Low"
                }
            }
        }
        else {
            # Fallback message if we couldn't get settings
            return [PSCustomObject]@{
                CheckName = "External Sharing Configuration"
                Category = "Security"
                Status = "Info"
                Severity = "Info"
                Message = "Could not retrieve SharePoint external sharing settings. Additional permissions may be required."
                Details = @{}
                Recommendation = "Ensure SharePoint.Settings.Read permission is granted, or connect via SharePoint Online PowerShell"
                DocumentationUrl = "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off"
                RemediationSteps = @(
                    "1. Connect to SharePoint Online: Connect-SPOService -Url https://yourtenant-admin.sharepoint.com",
                    "2. Run: Get-SPOTenant | Select *sharing*"
                )
            }
        }

        # Determine status
        $status = "Pass"
        $severity = "Low"

        $highRiskFindings = @($findings | Where-Object { $_.Risk -eq 'High' })
        $mediumRiskFindings = @($findings | Where-Object { $_.Risk -eq 'Medium' })

        if ($highRiskFindings.Count -gt 0) {
            $status = "Fail"
            $severity = "High"
        }
        elseif ($mediumRiskFindings.Count -gt 2) {
            $status = "Warning"
            $severity = "Medium"
        }
        elseif ($mediumRiskFindings.Count -gt 0) {
            $status = "Warning"
            $severity = "Low"
        }

        $message = "External sharing analysis complete"
        if ($issues.Count -gt 0) {
            $message += ". Issues: " + ($issues | Select-Object -First 3 | ForEach-Object { $_ }) -join '; '
            if ($issues.Count -gt 3) {
                $message += " (+$($issues.Count - 3) more)"
            }
        }
        else {
            $message += ". No critical external sharing issues detected"
        }

        # Build recommendations
        $recommendations = @()
        if ($sharingCapability -eq 'anyone') {
            $recommendations += "Restrict SharePoint sharing to 'New and Existing Guests' or more restrictive"
        }
        if ($oneDriveSharingCapability -eq 'anyone') {
            $recommendations += "Restrict OneDrive sharing to 'New and Existing Guests' or more restrictive"
        }
        if ($defaultLinkType -eq 'anonymousAccess') {
            $recommendations += "Change default sharing link type to 'Specific People' or 'People in Organization'"
        }
        if ($highRiskFindings.Count -eq 0 -and $mediumRiskFindings.Count -eq 0) {
            $recommendations += "External sharing configuration follows security best practices"
        }

        return [PSCustomObject]@{
            CheckName = "External Sharing Configuration"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                SharePointSharingCapability = $sharingCapability
                OneDriveSharingCapability = $oneDriveSharingCapability
                DefaultLinkType = $defaultLinkType
                HighRiskSettings = $highRiskFindings.Count
                MediumRiskSettings = $mediumRiskFindings.Count
                TotalIssues = $issues.Count
            }
            Findings = $findings
            Issues = $issues
            Recommendations = $recommendations
            Recommendation = if ($recommendations.Count -gt 0) {
                $recommendations -join ". "
            } else {
                "External sharing settings are well-configured. Continue monitoring for changes."
            }
            DocumentationUrl = "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off"
            RemediationSteps = @(
                "1. Navigate to SharePoint Admin Center > Policies > Sharing"
                "2. Set 'External sharing' to 'New and existing guests' or more restrictive"
                "3. Set 'Default sharing link type' to 'Specific people'"
                "4. Set 'Default link permission' to 'View' (not Edit)"
                "5. Enable 'Guest access to a site or OneDrive expires automatically after this many days'"
                "6. Configure domain restrictions to allow only trusted domains"
                "7. Consider enabling 'People who use a verification code must reauthenticate after this many days'"
                "8. Review and restrict site-level sharing settings for sensitive sites"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "External Sharing Configuration"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess external sharing configuration: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Connect to SharePoint Online PowerShell or verify Graph API permissions"
            DocumentationUrl = "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off"
            RemediationSteps = @()
        }
    }
}
