<#
.SYNOPSIS
    Tests privileged account security and MFA enforcement with risk context.

.DESCRIPTION
    Identifies privileged accounts (Global Admins, other admin roles) and
    verifies MFA enforcement, dedicated accounts, and security best practices.
    Includes risk context with role classification, last sign-in dates, and
    stale account detection.

.PARAMETER Config
    Configuration object containing privileged account requirements.

.OUTPUTS
    PSCustomObject containing assessment results with detailed risk context.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.2.0
    Created with assistance from GitHub Copilot
#>

function Test-PrivilegedAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [array]$AuthRegistrationDetails
    )

    try {
        Write-Verbose "Analyzing privileged account configuration with risk context..."

        # Define privileged roles with risk levels
        # Critical = Can compromise entire tenant
        # High = Can compromise significant resources or users
        # Medium = Limited blast radius but still sensitive
        $privilegedRoleDefinitions = @{
            'Global Administrator' = @{ RiskLevel = 'Critical'; RiskScore = 100; Description = 'Full tenant control' }
            'Privileged Role Administrator' = @{ RiskLevel = 'Critical'; RiskScore = 95; Description = 'Can assign any role' }
            'Privileged Authentication Administrator' = @{ RiskLevel = 'Critical'; RiskScore = 90; Description = 'Can reset any credentials' }
            'Security Administrator' = @{ RiskLevel = 'High'; RiskScore = 80; Description = 'Security settings and alerts' }
            'Exchange Administrator' = @{ RiskLevel = 'High'; RiskScore = 75; Description = 'Email and mailbox access' }
            'SharePoint Administrator' = @{ RiskLevel = 'High'; RiskScore = 70; Description = 'SharePoint and OneDrive' }
            'User Administrator' = @{ RiskLevel = 'High'; RiskScore = 65; Description = 'User account management' }
            'Application Administrator' = @{ RiskLevel = 'High'; RiskScore = 70; Description = 'App registrations and consent' }
            'Cloud Application Administrator' = @{ RiskLevel = 'High'; RiskScore = 65; Description = 'Enterprise apps (no app reg)' }
            'Authentication Administrator' = @{ RiskLevel = 'Medium'; RiskScore = 55; Description = 'Non-admin credential resets' }
            'Helpdesk Administrator' = @{ RiskLevel = 'Medium'; RiskScore = 40; Description = 'Password resets for non-admins' }
            'Groups Administrator' = @{ RiskLevel = 'Medium'; RiskScore = 45; Description = 'Group management' }
            'License Administrator' = @{ RiskLevel = 'Low'; RiskScore = 20; Description = 'License assignment only' }
            'Directory Readers' = @{ RiskLevel = 'Low'; RiskScore = 10; Description = 'Read-only directory access' }
        }

        $privilegedRoles = $privilegedRoleDefinitions.Keys

        $allPrivilegedUsers = @()
        $roleDetails = @()
        $privilegedAccountDetails = @{}
        $staleThresholdDays = 30
        $staleDate = (Get-Date).AddDays(-$staleThresholdDays)

        foreach ($roleName in $privilegedRoles) {
            try {
                $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                
                if ($role) {
                    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    
                    if ($roleMembers.Count -gt 0) {
                        $roleDef = $privilegedRoleDefinitions[$roleName]
                        $roleDetails += [PSCustomObject]@{
                            RoleName = $roleName
                            RiskLevel = $roleDef.RiskLevel
                            RiskScore = $roleDef.RiskScore
                            Description = $roleDef.Description
                            MemberCount = $roleMembers.Count
                            Members = $roleMembers.AdditionalProperties.userPrincipalName
                        }
                        
                        foreach ($member in $roleMembers) {
                            $upn = $member.AdditionalProperties.userPrincipalName
                            $displayName = $member.AdditionalProperties.displayName
                            $userId = $member.Id
                            
                            if ($upn) {
                                $allPrivilegedUsers += $upn
                                
                                # Track which roles each user has (use hashtable for efficient updates)
                                if ($privilegedAccountDetails.ContainsKey($upn)) {
                                    $privilegedAccountDetails[$upn].Roles += $roleName
                                    # Update risk level if this role is higher risk
                                    if ($roleDef.RiskScore -gt $privilegedAccountDetails[$upn].RiskScore) {
                                        $privilegedAccountDetails[$upn].RiskLevel = $roleDef.RiskLevel
                                        $privilegedAccountDetails[$upn].RiskScore = $roleDef.RiskScore
                                        $privilegedAccountDetails[$upn].HighestRiskRole = $roleName
                                    }
                                } else {
                                    $privilegedAccountDetails[$upn] = @{
                                        UserPrincipalName = $upn
                                        DisplayName = $displayName
                                        UserId = $userId
                                        Roles = @($roleName)
                                        RiskLevel = $roleDef.RiskLevel
                                        RiskScore = $roleDef.RiskScore
                                        HighestRiskRole = $roleName
                                        HasMFA = $null
                                        LastSignIn = $null
                                        LastSignInDaysAgo = $null
                                        IsStale = $false
                                        AccountType = 'Unknown'
                                        RiskFactors = @()
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Error checking role $roleName : $_"
            }
        }

        $allPrivilegedUsers = $allPrivilegedUsers | Select-Object -Unique
        $totalPrivilegedUsers = $allPrivilegedUsers.Count

        if ($totalPrivilegedUsers -eq 0) {
            return [PSCustomObject]@{
                CheckName = "Privileged Account Security"
                Category = "Security"
                Status = "Warning"
                Severity = "High"
                Message = "No privileged accounts found (may indicate permission issues)"
                Details = @{ PrivilegedUsers = 0 }
                Recommendation = "Verify permissions to read directory roles"
                DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning"
                RemediationSteps = @()
            }
        }

        # Resolve authentication registration details (cached if provided)
        $registrationDetails = $AuthRegistrationDetails
        if (-not $registrationDetails) {
            try {
                $registrationDetails = Get-AuthRegistrationDetails
            }
            catch {
                Write-Verbose "Could not retrieve authentication registration details: $_"
                $registrationDetails = @()
            }
        }

        $registrationLookup = @{}
        foreach ($detail in $registrationDetails) {
            if ($detail.UserPrincipalName) {
                $registrationLookup[$detail.UserPrincipalName.ToLower()] = $detail
            }
        }

        # Get sign-in activity for privileged users
        Write-Verbose "Retrieving sign-in activity for privileged accounts..."
        $signInLookup = @{}
        try {
            # Get users with sign-in activity (requires AuditLog.Read.All)
            $userIds = $privilegedAccountDetails.Values | ForEach-Object { $_.UserId } | Where-Object { $_ }
            foreach ($userId in $userIds) {
                try {
                    $user = Get-MgUser -UserId $userId -Property "signInActivity,accountEnabled,userType,createdDateTime" -ErrorAction SilentlyContinue
                    if ($user) {
                        $signInLookup[$userId] = @{
                            LastSignIn = $user.SignInActivity.LastSignInDateTime
                            LastNonInteractiveSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
                            AccountEnabled = $user.AccountEnabled
                            UserType = $user.UserType
                            CreatedDateTime = $user.CreatedDateTime
                        }
                    }
                } catch {
                    Write-Verbose "Could not get sign-in activity for user $userId : $_"
                }
            }
        } catch {
            Write-Verbose "Could not retrieve sign-in activity: $_"
        }

        # Check MFA status and sign-in activity for privileged users
        $privUsersWithoutMFA = @()
        $stalePrivilegedAccounts = @()
        $criticalRiskAccounts = @()
        $highRiskAccounts = @()
        
        foreach ($upn in $allPrivilegedUsers) {
            $key = $upn.ToLower()
            $detail = if ($registrationLookup.ContainsKey($key)) { $registrationLookup[$key] } else { $null }
            $accountData = $privilegedAccountDetails[$upn]
            
            # Check MFA status
            $hasMFA = $false
            if ($detail) {
                $methods = @($detail.MethodsRegistered)
                if ($detail.IsMfaRegistered -or ($methods -and $methods.Count -gt 0)) {
                    $hasMFA = $true
                }
            }
            $accountData.HasMFA = $hasMFA

            # Get sign-in activity
            $userId = $accountData.UserId
            if ($userId -and $signInLookup.ContainsKey($userId)) {
                $signInData = $signInLookup[$userId]
                $lastSignIn = $signInData.LastSignIn
                if (-not $lastSignIn) {
                    $lastSignIn = $signInData.LastNonInteractiveSignIn
                }
                
                if ($lastSignIn) {
                    $accountData.LastSignIn = $lastSignIn
                    $accountData.LastSignInDaysAgo = [math]::Round(((Get-Date) - $lastSignIn).TotalDays)
                    $accountData.IsStale = $lastSignIn -lt $staleDate
                } else {
                    $accountData.LastSignIn = $null
                    $accountData.LastSignInDaysAgo = $null
                    $accountData.IsStale = $true  # Never signed in = stale
                }
                
                $accountData.AccountEnabled = $signInData.AccountEnabled
                $accountData.UserType = $signInData.UserType
                
                # Determine account type
                if ($upn -match '\.onmicrosoft\.com$' -and $upn -match 'admin|emergency|breakglass') {
                    $accountData.AccountType = 'Dedicated Admin'
                } elseif ($upn -match '\.onmicrosoft\.com$') {
                    $accountData.AccountType = 'Cloud-Only'
                } elseif ($signInData.UserType -eq 'Guest') {
                    $accountData.AccountType = 'Guest'
                } else {
                    $accountData.AccountType = 'Synced/Hybrid'
                }
            }

            # Calculate risk factors
            $riskFactors = @()
            
            if (-not $hasMFA) {
                $riskFactors += "No MFA registered"
                $privUsersWithoutMFA += $upn
            }
            
            if ($accountData.IsStale) {
                $riskFactors += "Stale account (no sign-in in $staleThresholdDays+ days)"
                $stalePrivilegedAccounts += $upn
            }
            
            if ($accountData.AccountType -eq 'Guest') {
                $riskFactors += "Guest account with privileged access"
            }
            
            if ($accountData.Roles.Count -gt 3) {
                $riskFactors += "Excessive roles ($($accountData.Roles.Count) roles assigned)"
            }
            
            if ($accountData.RiskLevel -eq 'Critical' -and -not $hasMFA) {
                $riskFactors += "CRITICAL: Unprotected tenant-wide access"
            }
            
            $accountData.RiskFactors = $riskFactors
            
            # Categorize by risk level
            if ($accountData.RiskLevel -eq 'Critical') {
                $criticalRiskAccounts += $accountData
            } elseif ($accountData.RiskLevel -eq 'High') {
                $highRiskAccounts += $accountData
            }
        }

        # Determine status
        $requireMFA = if ($null -ne $Config.Security.PrivilegedAccountMFARequired) {
            $Config.Security.PrivilegedAccountMFARequired
        } else { $true }

        $maxPrivilegedAccounts = if ($null -ne $Config.Security.MaxPrivilegedAccounts) {
            $Config.Security.MaxPrivilegedAccounts
        } else { 3 }

        $status = "Pass"
        $severity = "Low"
        $issues = @()
        $maxPrivilegedAccounts = 3

        if ($requireMFA -and $privUsersWithoutMFA.Count -gt 0) {
            $status = "Fail"
            $severity = "Critical"
            $issues += "$($privUsersWithoutMFA.Count) privileged accounts without MFA: $($privUsersWithoutMFA -join ', ')"
        }

        # Check if total privileged account count exceeds threshold
        if ($totalPrivilegedUsers -gt $maxPrivilegedAccounts) {
            if ($status -eq "Pass") { $status = "Warning" }
            # Only escalate severity if it's currently lower than Medium
            if ($severity -in @("Low", "Info")) { $severity = "Medium" }
            $issues += "Total privileged account count ($totalPrivilegedUsers) exceeds recommended maximum ($maxPrivilegedAccounts)"
        }

        # Check for excessive Global Admins
        $globalAdminRole = $roleDetails | Where-Object { $_.RoleName -eq 'Global Administrator' }
        $globalAdminCount = if ($globalAdminRole) { $globalAdminRole.MemberCount } else { 0 }

        if ($globalAdminCount -gt 5) {
            if ($status -eq "Pass") { $status = "Warning" }
            # Only escalate severity if it's currently lower than Medium
            if ($severity -in @("Low", "Info")) { $severity = "Medium" }
            $issues += "Excessive Global Administrators ($globalAdminCount). Recommended: 2-5"
        }

        # Check for excessive privileged accounts overall
        if ($totalPrivilegedUsers -gt $maxPrivilegedAccounts) {
            if ($status -eq "Pass") { $status = "Warning" }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += "Privileged accounts exceed recommended maximum of $maxPrivilegedAccounts (found $totalPrivilegedUsers)"
        }

        # Check for stale privileged accounts
        if ($stalePrivilegedAccounts.Count -gt 0) {
            if ($status -eq "Pass") { $status = "Warning" }
            if ($severity -in @("Low", "Info")) { $severity = "Medium" }
            $issues += "$($stalePrivilegedAccounts.Count) stale privileged account(s) (no sign-in in $staleThresholdDays+ days)"
        }

        # Convert hashtable to array for output
        $privilegedAccountList = $privilegedAccountDetails.Values | ForEach-Object {
            [PSCustomObject]@{
                UserPrincipalName = $_.UserPrincipalName
                DisplayName = $_.DisplayName
                Roles = $_.Roles -join '; '
                RoleCount = $_.Roles.Count
                HighestRiskRole = $_.HighestRiskRole
                RiskLevel = $_.RiskLevel
                RiskScore = $_.RiskScore
                HasMFA = $_.HasMFA
                LastSignIn = if ($_.LastSignIn) { $_.LastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }
                LastSignInDaysAgo = $_.LastSignInDaysAgo
                IsStale = $_.IsStale
                AccountType = $_.AccountType
                RiskFactors = $_.RiskFactors -join '; '
                RiskFactorCount = $_.RiskFactors.Count
            }
        } | Sort-Object -Property RiskScore -Descending

        # Build risk summary
        $riskSummary = @{
            Critical = ($privilegedAccountList | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
            High = ($privilegedAccountList | Where-Object { $_.RiskLevel -eq 'High' }).Count
            Medium = ($privilegedAccountList | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
            Low = ($privilegedAccountList | Where-Object { $_.RiskLevel -eq 'Low' }).Count
        }

        $message = "$totalPrivilegedUsers privileged accounts found"
        $message += " (Critical: $($riskSummary.Critical), High: $($riskSummary.High))"
        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues -join '; ')"
        }
        elseif ($privUsersWithoutMFA.Count -eq 0) {
            $message += ". All privileged accounts have MFA enabled"
        }

        return [PSCustomObject]@{
            CheckName = "Privileged Account Security"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                TotalPrivilegedUsers = $totalPrivilegedUsers
                MaxRecommendedPrivilegedAccounts = $maxPrivilegedAccounts
                PrivilegedUsersWithoutMFA = $privUsersWithoutMFA.Count
                StalePrivilegedAccounts = $stalePrivilegedAccounts.Count
                GlobalAdminCount = $globalAdminCount
                RiskSummary = $riskSummary
                RoleBreakdown = $roleDetails
                UsersWithoutMFA = $privUsersWithoutMFA
                StaleAccounts = $stalePrivilegedAccounts
            }
            PrivilegedAccounts = $privilegedAccountList
            Recommendation = if ($status -ne "Pass") {
                "Enforce MFA for all privileged accounts immediately. Review stale accounts and remove unnecessary access. Use dedicated admin accounts (not user accounts). Limit total privileged accounts to $maxPrivilegedAccounts or fewer. Limit Global Admin role to 2-5 accounts."
            } else {
                "Privileged account security meets requirements. Review regularly and use Privileged Identity Management (PIM) for just-in-time access."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"
            RemediationSteps = @(
                "1. Require MFA for all privileged accounts via Conditional Access"
                "2. Review and remove stale privileged accounts that haven't signed in recently"
                "3. Create dedicated cloud-only admin accounts (admin@domain.onmicrosoft.com)"
                "4. Limit total privileged account count to $maxPrivilegedAccounts or fewer to minimize attack surface"
                "5. Limit Global Administrator count to 2-5 emergency access accounts"
                "6. Implement Privileged Identity Management (PIM) for just-in-time access"
                "7. Enable break-glass emergency access accounts with strong security"
                "8. Regular access reviews for privileged role assignments"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Privileged Account Security"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess privileged accounts: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Microsoft Graph permissions: Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"
            RemediationSteps = @()
        }
    }
}
