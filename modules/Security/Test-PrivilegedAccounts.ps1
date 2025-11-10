<#
.SYNOPSIS
    Tests privileged account security and MFA enforcement.

.DESCRIPTION
    Identifies privileged accounts (Global Admins, other admin roles) and
    verifies MFA enforcement, dedicated accounts, and security best practices.

.PARAMETER Config
    Configuration object containing privileged account requirements.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Author: M365 Assessment Toolkit
    Version: 1.0
#>

function Test-PrivilegedAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing privileged account configuration..."

        # Get privileged directory roles
        $privilegedRoles = @(
            'Global Administrator',
            'Privileged Role Administrator',
            'Security Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'User Administrator'
        )

        $allPrivilegedUsers = @()
        $roleDetails = @()
        $privilegedAccountDetails = @()

        foreach ($roleName in $privilegedRoles) {
            try {
                $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
                
                if ($role) {
                    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    
                    if ($roleMembers.Count -gt 0) {
                        $roleDetails += [PSCustomObject]@{
                            RoleName = $roleName
                            MemberCount = $roleMembers.Count
                            Members = $roleMembers.AdditionalProperties.userPrincipalName
                        }
                        
                        foreach ($member in $roleMembers) {
                            $upn = $member.AdditionalProperties.userPrincipalName
                            if ($upn) {
                                $allPrivilegedUsers += $upn
                                
                                # Track which roles each user has
                                $existingAccount = $privilegedAccountDetails | Where-Object { $_.UserPrincipalName -eq $upn }
                                if ($existingAccount) {
                                    $existingAccount.Roles += $roleName
                                } else {
                                    $privilegedAccountDetails += [PSCustomObject]@{
                                        UserPrincipalName = $upn
                                        Roles = @($roleName)
                                        HasMFA = $null
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

        # Check MFA status for privileged users
        $privUsersWithoutMFA = @()
        
        foreach ($upn in $allPrivilegedUsers) {
            try {
                $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
                
                if ($user) {
                    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                    
                    $hasMFA = $authMethods | Where-Object {
                        $_.AdditionalProperties.'@odata.type' -in @(
                            '#microsoft.graph.phoneAuthenticationMethod',
                            '#microsoft.graph.fido2AuthenticationMethod',
                            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                            '#microsoft.graph.softwareOathAuthenticationMethod',
                            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
                        )
                    }

                    # Update the privileged account details with MFA status
                    $accountDetail = $privilegedAccountDetails | Where-Object { $_.UserPrincipalName -eq $upn }
                    if ($accountDetail) {
                        $accountDetail.HasMFA = ($null -ne $hasMFA -and $hasMFA.Count -gt 0)
                    }

                    if (-not $hasMFA) {
                        $privUsersWithoutMFA += $upn
                    }
                }
            }
            catch {
                Write-Verbose "Could not check MFA for privileged user: $upn"
            }
        }

        # Determine status
        $requireMFA = if ($null -ne $Config.Security.PrivilegedAccountMFARequired) {
            $Config.Security.PrivilegedAccountMFARequired
        } else { $true }

        $status = "Pass"
        $severity = "Low"
        $issues = @()

        if ($requireMFA -and $privUsersWithoutMFA.Count -gt 0) {
            $status = "Fail"
            $severity = "Critical"
            $issues += "$($privUsersWithoutMFA.Count) privileged accounts without MFA: $($privUsersWithoutMFA -join ', ')"
        }

        # Check for excessive Global Admins
        $globalAdminRole = $roleDetails | Where-Object { $_.RoleName -eq 'Global Administrator' }
        $globalAdminCount = if ($globalAdminRole) { $globalAdminRole.MemberCount } else { 0 }

        if ($globalAdminCount -gt 5) {
            if ($status -eq "Pass") { $status = "Warning" }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += "Excessive Global Administrators ($globalAdminCount). Recommended: 2-5"
        }

        $message = "$totalPrivilegedUsers privileged accounts found"
        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues -join '; ')"
        }
        else {
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
                PrivilegedUsersWithoutMFA = $privUsersWithoutMFA.Count
                GlobalAdminCount = $globalAdminCount
                RoleBreakdown = $roleDetails
                UsersWithoutMFA = $privUsersWithoutMFA
            }
            PrivilegedAccounts = $privilegedAccountDetails
            Recommendation = if ($status -ne "Pass") {
                "Enforce MFA for all privileged accounts immediately. Use dedicated admin accounts (not user accounts). Limit Global Admin role to 2-5 accounts."
            } else {
                "Privileged account security meets requirements. Review regularly and use Privileged Identity Management (PIM) for just-in-time access."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"
            RemediationSteps = @(
                "1. Require MFA for all privileged accounts via Conditional Access"
                "2. Create dedicated cloud-only admin accounts (admin@domain.onmicrosoft.com)"
                "3. Limit Global Administrator count to 2-5 emergency access accounts"
                "4. Implement Privileged Identity Management (PIM) for just-in-time access"
                "5. Enable break-glass emergency access accounts with strong security"
                "6. Regular access reviews for privileged role assignments"
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
            Recommendation = "Verify Microsoft Graph permissions: Directory.Read.All, RoleManagement.Read.Directory"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"
            RemediationSteps = @()
        }
    }
}
