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
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
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

        # Check MFA status for privileged users
        $privUsersWithoutMFA = @()
        
        foreach ($upn in $allPrivilegedUsers) {
            $key = $upn.ToLower()
            $detail = if ($registrationLookup.ContainsKey($key)) { $registrationLookup[$key] } else { $null }
            $hasMFA = $false
            if ($detail) {
                $methods = @($detail.MethodsRegistered)
                if ($detail.IsMfaRegistered -or ($methods -and $methods.Count -gt 0)) {
                    $hasMFA = $true
                }
            }

            # Update the privileged account details with MFA status
            $accountDetail = $privilegedAccountDetails | Where-Object { $_.UserPrincipalName -eq $upn }
            if ($accountDetail) {
                $accountDetail.HasMFA = $hasMFA
            }

            if (-not $hasMFA) {
                $privUsersWithoutMFA += $upn
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
                MaxRecommendedPrivilegedAccounts = $maxPrivilegedAccounts
                PrivilegedUsersWithoutMFA = $privUsersWithoutMFA.Count
                GlobalAdminCount = $globalAdminCount
                RoleBreakdown = $roleDetails
                UsersWithoutMFA = $privUsersWithoutMFA
                RegistrationDetailsCount = $registrationDetails.Count
                RegistrationDetailsSource = if ($AuthRegistrationDetails) { 'Cached' } else { 'Live' }
            }
            PrivilegedAccounts = $privilegedAccountDetails
            Recommendation = if ($status -ne "Pass") {
                "Enforce MFA for all privileged accounts immediately. Use dedicated admin accounts (not user accounts). Limit total privileged accounts to $maxPrivilegedAccounts or fewer. Limit Global Admin role to 2-5 accounts."
            } else {
                "Privileged account security meets requirements. Review regularly and use Privileged Identity Management (PIM) for just-in-time access."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices"
            RemediationSteps = @(
                "1. Require MFA for all privileged accounts via Conditional Access"
                "2. Create dedicated cloud-only admin accounts (admin@domain.onmicrosoft.com)"
                "3. Limit total privileged account count to $maxPrivilegedAccounts or fewer to minimize attack surface"
                "4. Limit Global Administrator count to 2-5 emergency access accounts"
                "5. Implement Privileged Identity Management (PIM) for just-in-time access"
                "6. Enable break-glass emergency access accounts with strong security"
                "7. Regular access reviews for privileged role assignments"
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
