<#
.SYNOPSIS
    Audits Enterprise Applications and App Registrations for risky permissions.

.DESCRIPTION
    Identifies applications with high-risk permissions, admin consent grants,
    stale/unused apps, multi-tenant apps, and apps with secrets/certificates
    expiring soon.

.PARAMETER Config
    Configuration object (reserved for future use).

.OUTPUTS
    PSCustomObject containing application permission audit results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-AppPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Auditing application permissions and configurations..."

        # High-risk permissions to flag
        $highRiskPermissions = @(
            'Mail.ReadWrite',
            'Mail.ReadWrite.All',
            'Mail.Send',
            'Mail.Send.All',
            'MailboxSettings.ReadWrite',
            'User.ReadWrite.All',
            'Directory.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'Application.ReadWrite.All',
            'AppRoleAssignment.ReadWrite.All',
            'Files.ReadWrite.All',
            'Sites.ReadWrite.All',
            'full_access_as_app',
            'Exchange.ManageAsApp'
        )

        $mediumRiskPermissions = @(
            'User.Read.All',
            'Directory.Read.All',
            'Group.ReadWrite.All',
            'GroupMember.ReadWrite.All',
            'Mail.Read',
            'Mail.Read.All',
            'Files.Read.All',
            'Sites.Read.All',
            'Calendars.ReadWrite',
            'Contacts.ReadWrite'
        )

        # Get all service principals (Enterprise Apps)
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, ServicePrincipalType, AccountEnabled, CreatedDateTime, SignInAudience, AppRoles, Oauth2PermissionScopes -ErrorAction Stop

        # Filter to application type (exclude Microsoft first-party where possible)
        $enterpriseApps = $servicePrincipals | Where-Object { 
            $_.ServicePrincipalType -eq 'Application' 
        }

        $totalApps = @($enterpriseApps).Count
        
        if ($totalApps -eq 0) {
            return [PSCustomObject]@{
                CheckName = "Application Permissions Audit"
                Category = "Security"
                Status = "Info"
                Severity = "Info"
                Message = "No enterprise applications found"
                Details = @{}
                Recommendation = "No action required"
                DocumentationUrl = "https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions"
                RemediationSteps = @()
            }
        }

        $riskyApps = @()
        $appsWithAdminConsent = @()
        $staleApps = @()
        $multiTenantApps = @()
        $appsWithExpiringCredentials = @()

        # Get OAuth2 permission grants (delegated permissions with admin consent)
        $oauth2Grants = @()
        try {
            $oauth2Grants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Could not retrieve OAuth2 permission grants: $_"
        }

        # Build lookup of grants by service principal
        $grantsByApp = @{}
        foreach ($grant in $oauth2Grants) {
            if (-not $grantsByApp.ContainsKey($grant.ClientId)) {
                $grantsByApp[$grant.ClientId] = @()
            }
            $grantsByApp[$grant.ClientId] += $grant
        }

        # Analyze each enterprise app
        foreach ($app in $enterpriseApps) {
            $appRisks = @()
            $appPermissions = @()
            $isRisky = $false
            $hasAdminConsent = $false

            # Check OAuth2 permission grants for this app
            $appGrants = $grantsByApp[$app.Id]
            if ($appGrants) {
                foreach ($grant in $appGrants) {
                    $scopes = $grant.Scope -split ' ' | Where-Object { $_ }
                    foreach ($scope in $scopes) {
                        $appPermissions += $scope
                        
                        if ($scope -in $highRiskPermissions) {
                            $appRisks += "High-risk delegated permission: $scope"
                            $isRisky = $true
                        }
                        elseif ($scope -in $mediumRiskPermissions) {
                            $appRisks += "Medium-risk delegated permission: $scope"
                        }
                    }
                    
                    # Check for admin consent (ConsentType = AllPrincipals)
                    if ($grant.ConsentType -eq 'AllPrincipals') {
                        $hasAdminConsent = $true
                        $appRisks += "Has admin consent for: $($grant.Scope)"
                    }
                }
            }

            # Get app role assignments (application permissions)
            try {
                $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.Id -ErrorAction SilentlyContinue
                
                foreach ($assignment in $appRoleAssignments) {
                    # Get the resource (API) this permission is for
                    $resourceSp = $servicePrincipals | Where-Object { $_.Id -eq $assignment.ResourceId }
                    $resourceName = if ($resourceSp) { $resourceSp.DisplayName } else { "Unknown" }
                    
                    # Get the actual permission name from the app role
                    $roleName = $assignment.AppRoleId
                    if ($resourceSp -and $resourceSp.AppRoles) {
                        $role = $resourceSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
                        if ($role) {
                            $roleName = $role.Value
                        }
                    }
                    
                    $appPermissions += "$resourceName - $roleName (Application)"
                    
                    if ($roleName -in $highRiskPermissions) {
                        $appRisks += "High-risk application permission: $roleName"
                        $isRisky = $true
                    }
                    elseif ($roleName -in $mediumRiskPermissions) {
                        $appRisks += "Medium-risk application permission: $roleName"
                    }
                }
            }
            catch {
                Write-Verbose "Could not get app role assignments for $($app.DisplayName): $_"
            }

            # Check if multi-tenant
            if ($app.SignInAudience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount')) {
                $multiTenantApps += [PSCustomObject]@{
                    DisplayName = $app.DisplayName
                    AppId = $app.AppId
                    SignInAudience = $app.SignInAudience
                }
            }

            # Check for stale apps (created more than 365 days ago with no recent activity indicator)
            if ($app.CreatedDateTime) {
                $daysSinceCreation = ((Get-Date) - [DateTime]$app.CreatedDateTime).TotalDays
                if ($daysSinceCreation -gt 365 -and -not $app.AccountEnabled) {
                    $staleApps += [PSCustomObject]@{
                        DisplayName = $app.DisplayName
                        AppId = $app.AppId
                        CreatedDateTime = $app.CreatedDateTime
                        DaysSinceCreation = [math]::Round($daysSinceCreation, 0)
                        Enabled = $app.AccountEnabled
                    }
                }
            }

            # Record risky apps
            if ($isRisky) {
                # Extract just the high-risk permission names for display
                $highRiskPerms = @()
                foreach ($risk in $appRisks) {
                    if ($risk -match 'High-risk (?:delegated|application) permission: (.+)$') {
                        $highRiskPerms += $matches[1]
                    }
                }
                
                # Determine app type
                $appType = if ($hasAdminConsent) { "Admin Consented" } else { "User Consented" }
                
                $riskyApps += [PSCustomObject]@{
                    DisplayName = $app.DisplayName
                    AppId = $app.AppId
                    Type = $appType
                    Enabled = $app.AccountEnabled
                    Risks = $appRisks
                    RiskReasons = $appRisks
                    Permissions = $appPermissions
                    HighRiskPermissions = $highRiskPerms
                    HasAdminConsent = $hasAdminConsent
                }
            }

            # Track apps with admin consent separately
            if ($hasAdminConsent) {
                $appsWithAdminConsent += [PSCustomObject]@{
                    DisplayName = $app.DisplayName
                    AppId = $app.AppId
                    Permissions = $appPermissions -join '; '
                }
            }
        }

        # Check App Registrations for expiring credentials
        try {
            $appRegistrations = Get-MgApplication -All -Property Id, DisplayName, AppId, PasswordCredentials, KeyCredentials -ErrorAction SilentlyContinue
            
            $now = Get-Date
            $warningThreshold = $now.AddDays(30)
            $criticalThreshold = $now.AddDays(7)

            foreach ($appReg in $appRegistrations) {
                # Check password credentials (secrets)
                foreach ($cred in $appReg.PasswordCredentials) {
                    if ($cred.EndDateTime -and $cred.EndDateTime -lt $warningThreshold) {
                        $daysUntilExpiry = [math]::Round(($cred.EndDateTime - $now).TotalDays, 0)
                        $appsWithExpiringCredentials += [PSCustomObject]@{
                            DisplayName = $appReg.DisplayName
                            AppId = $appReg.AppId
                            CredentialType = "Secret"
                            ExpiryDate = $cred.EndDateTime.ToString('yyyy-MM-dd')
                            DaysUntilExpiry = $daysUntilExpiry
                            Status = if ($daysUntilExpiry -lt 0) { "Expired" } elseif ($daysUntilExpiry -lt 7) { "Critical" } else { "Warning" }
                        }
                    }
                }

                # Check key credentials (certificates)
                foreach ($cred in $appReg.KeyCredentials) {
                    if ($cred.EndDateTime -and $cred.EndDateTime -lt $warningThreshold) {
                        $daysUntilExpiry = [math]::Round(($cred.EndDateTime - $now).TotalDays, 0)
                        $appsWithExpiringCredentials += [PSCustomObject]@{
                            DisplayName = $appReg.DisplayName
                            AppId = $appReg.AppId
                            CredentialType = "Certificate"
                            ExpiryDate = $cred.EndDateTime.ToString('yyyy-MM-dd')
                            DaysUntilExpiry = $daysUntilExpiry
                            Status = if ($daysUntilExpiry -lt 0) { "Expired" } elseif ($daysUntilExpiry -lt 7) { "Critical" } else { "Warning" }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not check app registration credentials: $_"
        }

        # Determine status
        $status = "Pass"
        $severity = "Low"
        $issues = @()

        $expiredOrCriticalCreds = @($appsWithExpiringCredentials | Where-Object { $_.Status -in @('Expired', 'Critical') })

        if ($riskyApps.Count -gt 0) {
            $status = "Fail"
            $severity = "High"
            $issues += "$($riskyApps.Count) app(s) with high-risk permissions"
        }

        if ($expiredOrCriticalCreds.Count -gt 0) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            $severity = if ($severity -eq "Low") { "High" } else { $severity }
            $issues += "$($expiredOrCriticalCreds.Count) app(s) with expired or critically expiring credentials"
        }

        if ($appsWithAdminConsent.Count -gt 10) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            $severity = if ($severity -eq "Low") { "Medium" } else { $severity }
            $issues += "$($appsWithAdminConsent.Count) apps have admin consent (review for necessity)"
        }

        if ($multiTenantApps.Count -gt 5) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            $severity = if ($severity -eq "Low") { "Medium" } else { $severity }
            $issues += "$($multiTenantApps.Count) multi-tenant apps configured"
        }

        $message = "Analyzed $totalApps enterprise apps"
        if ($issues.Count -gt 0) {
            $message += ". Issues: " + ($issues -join '; ')
        }
        else {
            $message += ". No high-risk permission configurations detected"
        }

        # Build recommendations
        $recommendations = @()
        if ($riskyApps.Count -gt 0) {
            $recommendations += "Review $($riskyApps.Count) app(s) with high-risk permissions - consider removing unnecessary access"
            foreach ($app in ($riskyApps | Select-Object -First 3)) {
                $recommendations += "  - $($app.DisplayName): $($app.Risks[0])"
            }
        }
        if ($expiredOrCriticalCreds.Count -gt 0) {
            $recommendations += "Rotate credentials for $($expiredOrCriticalCreds.Count) app(s) with expired/expiring secrets or certificates"
        }
        if ($appsWithAdminConsent.Count -gt 10) {
            $recommendations += "Review admin consent grants - ensure all are necessary and justified"
        }

        return [PSCustomObject]@{
            CheckName = "Application Permissions Audit"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                TotalEnterpriseApps = $totalApps
                AppsWithHighRiskPermissions = $riskyApps.Count
                AppsWithAdminConsent = $appsWithAdminConsent.Count
                MultiTenantApps = $multiTenantApps.Count
                StaleDisabledApps = $staleApps.Count
                AppsWithExpiringCredentials = $appsWithExpiringCredentials.Count
                ExpiredOrCriticalCredentials = $expiredOrCriticalCreds.Count
            }
            RiskyApps = $riskyApps
            AppsWithAdminConsent = $appsWithAdminConsent
            MultiTenantApps = $multiTenantApps
            ExpiringCredentials = $appsWithExpiringCredentials
            Recommendations = $recommendations
            Recommendation = if ($recommendations.Count -gt 0) {
                $recommendations -join ". "
            } else {
                "Application permissions appear well-managed. Continue regular reviews."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions"
            RemediationSteps = @(
                "1. Navigate to Entra ID > Enterprise Applications"
                "2. Review apps with high-risk permissions in the RiskyApps list"
                "3. For each risky app, evaluate if permissions are necessary"
                "4. Remove unnecessary permissions or disable unused apps"
                "5. Review admin consent grants under Permissions"
                "6. Configure admin consent workflow to control future grants"
                "7. Rotate expiring credentials before they expire"
                "8. Enable app governance in Microsoft Defender for Cloud Apps"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Application Permissions Audit"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to audit application permissions: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Microsoft Graph permissions: Application.Read.All, Directory.Read.All"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions"
            RemediationSteps = @()
        }
    }
}
