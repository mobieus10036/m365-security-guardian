<#
.SYNOPSIS
    Tests Multi-Factor Authentication (MFA) configuration across the tenant.

.DESCRIPTION
    Evaluates MFA adoption and enforcement, identifying users without MFA,
    privileged accounts lacking MFA, and overall tenant MFA compliance.

.PARAMETER Config
    Configuration object containing MFA thresholds and requirements.

.OUTPUTS
    PSCustomObject containing assessment results with status, findings, and recommendations.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-MFAConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [array]$AuthRegistrationDetails
    )

    try {
        Write-Verbose "Analyzing MFA configuration..."

        # Get all users
        $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled |
                    Where-Object { $_.AccountEnabled -eq $true }
        
        $totalUsers = $allUsers.Count

        if ($totalUsers -eq 0) {
            return [PSCustomObject]@{
                CheckName = "MFA Configuration"
                Category = "Security"
                Status = "Info"
                Severity = "Info"
                Message = "No enabled users found in tenant"
                Details = @{ TotalUsers = 0 }
                Recommendation = "Ensure users are properly provisioned"
                DocumentationUrl = "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
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

        # Build lookup for fast per-user checks
        $registrationLookup = @{}
        foreach ($detail in $registrationDetails) {
            if ($detail.UserPrincipalName) {
                $registrationLookup[$detail.UserPrincipalName.ToLower()] = $detail
            }
        }

        $usersWithMFA = 0
        $usersWithoutMFA = @()

        Write-Verbose "Checking MFA status for $totalUsers users via registration detail cache..."
        foreach ($user in $allUsers) {
            $userKey = $user.UserPrincipalName.ToLower()
            $detail = if ($registrationLookup.ContainsKey($userKey)) { $registrationLookup[$userKey] } else { $null }

            $hasMFA = $false
            if ($detail) {
                $methods = @($detail.MethodsRegistered)
                if ($detail.IsMfaRegistered -or ($methods -and $methods.Count -gt 0)) {
                    $hasMFA = $true
                }
            }

            if ($hasMFA) {
                $usersWithMFA++
            }
            else {
                $usersWithoutMFA += [PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    UserId = $user.Id
                }
            }
        }

        # Calculate compliance percentage
        $mfaPercentage = if ($totalUsers -gt 0) { 
            [math]::Round(($usersWithMFA / $totalUsers) * 100, 1) 
        } else { 0 }

        # Determine status based on threshold
        $threshold = if ($Config.Security.MFAEnforcementThreshold) { 
            $Config.Security.MFAEnforcementThreshold 
        } else { 95 }

        $status = if ($mfaPercentage -ge $threshold) { "Pass" }
                  elseif ($mfaPercentage -ge 75) { "Warning" }
                  else { "Fail" }

        $severity = if ($mfaPercentage -ge 90) { "Low" }
                    elseif ($mfaPercentage -ge 75) { "Medium" }
                    elseif ($mfaPercentage -ge 50) { "High" }
                    else { "Critical" }

        $message = "MFA adoption: $mfaPercentage% ($usersWithMFA/$totalUsers users)"
        
        if ($usersWithoutMFA.Count -gt 0 -and $usersWithoutMFA.Count -le 10) {
            $message += ". Users without MFA: $($usersWithoutMFA.UserPrincipalName -join ', ')"
        }
        elseif ($usersWithoutMFA.Count -gt 10) {
            $message += ". $($usersWithoutMFA.Count) users without MFA"
        }

        return [PSCustomObject]@{
            CheckName = "MFA Enforcement"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                TotalUsers = $totalUsers
                UsersWithMFA = $usersWithMFA
                UsersWithoutMFA = $usersWithoutMFA.Count
                CompliancePercentage = $mfaPercentage
                Threshold = $threshold
                RegistrationDetailsCount = $registrationDetails.Count
                RegistrationDetailsSource = if ($AuthRegistrationDetails) { 'Cached' } else { 'Live' }
            }
            UsersWithoutMFA = $usersWithoutMFA
            Recommendation = if ($status -ne "Pass") {
                "Enable MFA for all users via Conditional Access policies. Target: $threshold% adoption"
            } else {
                "MFA adoption meets requirements. Continue monitoring."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted"
            RemediationSteps = @(
                "1. Navigate to Entra ID > Security > Conditional Access"
                "2. Create a new policy requiring MFA for all users"
                "3. Enable policy in Report-only mode initially"
                "4. Review sign-in logs and adjust exclusions"
                "5. Enable policy enforcement"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "MFA Configuration"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess MFA configuration: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Microsoft Graph permissions: UserAuthenticationMethod.Read.All"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/authentication/concept-mfa-howitworks"
            RemediationSteps = @()
        }
    }
}
