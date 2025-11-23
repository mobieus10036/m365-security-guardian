<#
.SYNOPSIS
    Tests Conditional Access policy configuration and coverage.

.DESCRIPTION
    Evaluates the presence and effectiveness of Conditional Access policies,
    checking for minimum required policies and coverage of critical scenarios.

.PARAMETER Config
    Configuration object containing Conditional Access requirements.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-ConditionalAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing Conditional Access policies..."

        # Get all Conditional Access policies
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All

        $totalPolicies = $caPolicies.Count
        $enabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
        $reportOnlyPolicies = ($caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
        $disabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'disabled' }).Count

        $breakGlass = @()
        if ($Config.Security.BreakGlassAccounts) { $breakGlass = @($Config.Security.BreakGlassAccounts) }
        $minPolicies = if ($Config.Security.MinConditionalAccessPolicies) { $Config.Security.MinConditionalAccessPolicies } else { 1 }
        $staleReportOnlyDays = if ($Config.Security.ReportOnlyStaleDays) { $Config.Security.ReportOnlyStaleDays } else { 30 }
        $adminAppIds = @(
            # Azure Management / portal
            "797f4846-ba00-4fd7-ba43-dac1f8f63013",
            # Microsoft Graph
            "00000003-0000-0000-c000-000000000000",
            # Exchange Online
            "00000002-0000-0ff1-ce00-000000000000",
            # SharePoint Online
            "00000003-0000-0ff1-ce00-000000000000"
        )

        # Collect enabled policy details for reporting
        $enabledPolicyList = @()
        foreach ($policy in ($caPolicies | Where-Object { $_.State -eq 'enabled' })) {
            $enabledPolicyList += [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                State = $policy.State
                Id = $policy.Id
            }
        }

        # Evaluate key posture controls
        $baselineMfa = $caPolicies | Where-Object { (_isEnabled $_) -and (_coversAllUsers $_ $breakGlass) -and (_enforcesMfa $_) }
        $legacyBlock = $caPolicies | Where-Object { (_isEnabled $_) -and (_coversAllUsers $_ $breakGlass) -and (_includesAllApps $_) -and (_blocksLegacyAuth $_) }
        $legacyComplete = $legacyBlock | Where-Object { _legacyComplete $_ }
        $adminProtection = $caPolicies | Where-Object { (_isEnabled $_) -and (_targetsAdmins $_) -and (_enforcesMfa $_) }
        $riskySignIn = $caPolicies | Where-Object { (_isEnabled $_) -and (_handlesRiskySignIns $_) }
        $strongAuthStrength = $caPolicies | Where-Object { (_isEnabled $_) -and (_hasAuthStrength $_) }
        $sessionGoverned = $caPolicies | Where-Object { (_isEnabled $_) -and (_coversAdminApps $_ $adminAppIds) -and (_hasSessionControls $_) }
        $exclusionOverreach = $caPolicies | Where-Object { (_isEnabled $_) -and (_coversAllUsers $_ $breakGlass) -and (_overbroadExclusions $_ $breakGlass) }
        $staleReportOnly = $caPolicies | Where-Object { _isReportOnlyStale $_ $staleReportOnlyDays }

        # Determine status and issues
        $issues = @()
        $status = "Pass"
        $severity = "Low"

        if ($totalPolicies -eq 0) {
            $status = "Fail"; $severity = "Critical"
            $issues += [PSCustomObject]@{ Message = "No Conditional Access policies found"; Severity = "Critical" }
        }
        elseif ($enabledPolicies -eq 0) {
            $status = "Fail"; $severity = "Critical"
            $issues += [PSCustomObject]@{ Message = "No enabled Conditional Access policies"; Severity = "Critical" }
        }
        elseif ($enabledPolicies -lt $minPolicies) {
            $status = "Fail"; $severity = "High"
            $issues += [PSCustomObject]@{ Message = "Only $enabledPolicies enabled policies (minimum required: $minPolicies)"; Severity = "High" }
        }

        if (-not $baselineMfa) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            $severity = if ($severity -eq "Low") { "High" } else { $severity }
            $issues += [PSCustomObject]@{ Message = "No tenant-wide MFA policy with minimal exclusions"; Severity = "High" }
        }
        if (-not $legacyBlock) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "High" }
            $issues += [PSCustomObject]@{ Message = "Legacy authentication not blocked for all users/apps"; Severity = "High" }
        }
        elseif (-not $legacyComplete) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "Legacy auth block does not cover EAS and Other clients together"; Severity = "Medium" }
        }
        if (-not $adminProtection) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "Privileged roles/groups not explicitly protected by CA"; Severity = "Medium" }
        }
        if (-not $riskySignIn) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No CA policy governing medium/high sign-in risk"; Severity = "Medium" }
        }
        if (-not $strongAuthStrength) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No policy using strong Authentication Strength (phishing-resistant)"; Severity = "Medium" }
        }
        if (-not $sessionGoverned) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "Admin/critical apps lack sign-in frequency or persistent browser governance"; Severity = "Medium" }
        }
        if ($exclusionOverreach) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "All-users policies exclude accounts beyond break-glass"; Severity = "Medium" }
        }
        if ($staleReportOnly) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Low" }
            $issues += [PSCustomObject]@{ Message = "Report-only policies older than $staleReportOnlyDays days; consider enforcing or retiring"; Severity = "Low" }
        }

        $message = "$enabledPolicies enabled policies found"
        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues.Message -join '; ')"
        }

        $recommendations = @()
        if (-not $baselineMfa) { $recommendations += "Create/enable a tenant-wide MFA or strong authentication policy with minimal exclusions (break-glass only)" }
        if (-not $legacyBlock) { $recommendations += "Add a policy to block legacy authentication (EAS/older clients) for all users/apps" }
        elseif (-not $legacyComplete) { $recommendations += "Ensure the legacy auth block covers both Exchange ActiveSync and Other clients with Block control" }
        if (-not $adminProtection) { $recommendations += "Add a privileged-role policy requiring MFA/strong auth and tighter session controls" }
        if (-not $riskySignIn) { $recommendations += "Add a risk-based policy to require MFA or block medium/high sign-in risk" }
        if (-not $strongAuthStrength) { $recommendations += "Adopt Authentication Strength (phishing-resistant/strong) on baseline/admin/risk policies" }
        if (-not $sessionGoverned) { $recommendations += "Configure sign-in frequency and avoid persistent browser sessions for admin/critical apps" }
        if ($exclusionOverreach) { $recommendations += "Reduce exclusions on all-user policies to break-glass accounts only" }
        if ($staleReportOnly) { $recommendations += "Review report-only policies older than $staleReportOnlyDays days and enforce or retire" }
        if ($enabledPolicies -lt $minPolicies) { $recommendations += "Increase coverage with additional Conditional Access policies per security requirements" }

        return [PSCustomObject]@{
            CheckName = "Conditional Access Policies"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                TotalPolicies = $totalPolicies
                EnabledPolicies = $enabledPolicies
                ReportOnlyPolicies = $reportOnlyPolicies
                DisabledPolicies = $disabledPolicies
                BaselineMFA = [bool]$baselineMfa
                LegacyAuthBlocked = [bool]$legacyBlock
                LegacyBlockComplete = [bool]$legacyComplete
                AdminProtection = [bool]$adminProtection
                RiskySignInGoverned = [bool]$riskySignIn
                StrongAuthStrength = [bool]$strongAuthStrength
                SessionGoverned = [bool]$sessionGoverned
                ExclusionOverreach = [bool]$exclusionOverreach
                ReportOnlyStale = [bool]$staleReportOnly
                Issues = $issues
            }
            EnabledPolicies = $enabledPolicyList
            Recommendation = if ($recommendations.Count -gt 0) {
                $recommendations -join ". "
            } else {
                "Conditional Access configuration meets baseline checks. Review policies regularly."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/conditional-access/overview"
            RemediationSteps = @(
                "1. Navigate to Entra ID > Security > Conditional Access"
                "2. Ensure a tenant-wide MFA/strong auth policy with minimal exclusions (break-glass only)"
                "3. Add a policy blocking legacy authentication for all users/apps"
                "4. Add privileged-role protection (MFA/strong auth) and risk-based sign-in controls"
                "5. Test in Report-only where needed, then enforce and monitor sign-in logs"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Conditional Access Policies"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess Conditional Access: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Microsoft Graph permissions: Policy.Read.All"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/conditional-access/overview"
            RemediationSteps = @()
        }
    }
}

# Helpers to keep posture checks readable
function _isEnabled($policy) {
    return $policy.State -eq 'enabled'
}

function _coversAllUsers($policy, $breakGlass) {
    $includeAll = $policy.Conditions.Users.IncludeUsers -contains 'All'
    if (-not $includeAll) { return $false }
    $exclusions = @($policy.Conditions.Users.ExcludeUsers)
    if ($exclusions.Count -eq 0) { return $true }
    # Allow only break-glass accounts to be excluded if configured
    $nonBreakGlass = $exclusions | Where-Object { $breakGlass -notcontains $_ }
    return $nonBreakGlass.Count -eq 0
}

function _includesAllApps($policy) {
    return $policy.Conditions.Applications.IncludeApplications -contains 'All'
}

function _enforcesMfa($policy) {
    $grant = $policy.GrantControls
    if ($grant.BuiltInControls -contains 'mfa') { return $true }
    if ($grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id) { return $true }
    return $false
}

function _blocksLegacyAuth($policy) {
    $grant = $policy.GrantControls
    $clientApps = @($policy.Conditions.ClientAppTypes | ForEach-Object { $_.ToLower() })
    return ($grant.BuiltInControls -contains 'block') -and (
        $clientApps -contains 'exchangeactivesync' -or $clientApps -contains 'other'
    )
}

function _legacyComplete($policy) {
    $clientApps = @($policy.Conditions.ClientAppTypes | ForEach-Object { $_.ToLower() })
    return ($clientApps -contains 'exchangeactivesync') -and ($clientApps -contains 'other')
}

function _targetsAdmins($policy) {
    return ($policy.Conditions.Users.IncludeRoles.Count -gt 0) -or ($policy.Conditions.Users.IncludeGroups.Count -gt 0)
}

function _handlesRiskySignIns($policy) {
    $risks = @($policy.Conditions.SignInRiskLevels | ForEach-Object { $_.ToLower() })
    if (-not ($risks -contains 'medium' -or $risks -contains 'high')) { return $false }
    $grant = $policy.GrantControls
    $controls = @($grant.BuiltInControls | ForEach-Object { $_.ToLower() })
    $hasAuthStrength = $grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id
    return ($controls -contains 'block') -or ($controls -contains 'mfa') -or $hasAuthStrength
}

function _hasAuthStrength($policy) {
    return ($policy.GrantControls.AuthenticationStrength -and $policy.GrantControls.AuthenticationStrength.Id)
}

function _coversAdminApps($policy, $adminAppIds) {
    if (_includesAllApps $policy) { return $true }
    $includes = @($policy.Conditions.Applications.IncludeApplications)
    return ($includes | Where-Object { $adminAppIds -contains $_ }).Count -gt 0
}

function _hasSessionControls($policy) {
    $session = $policy.SessionControls
    if (-not $session) { return $false }
    $signInFreq = $session.SignInFrequency
    $persistent = $session.PersistentBrowser
    $hasSignInFreq = $false
    $hasPersistentGovernance = $false

    if ($signInFreq -and $signInFreq.IsEnabled) { $hasSignInFreq = $true }
    if ($persistent -and $persistent.IsEnabled -and ($persistent.Mode -eq 'never')) { $hasPersistentGovernance = $true }

    return $hasSignInFreq -or $hasPersistentGovernance
}

function _overbroadExclusions($policy, $breakGlass) {
    $exclusions = @($policy.Conditions.Users.ExcludeUsers)
    if ($exclusions.Count -eq 0) { return $false }
    $nonBreakGlass = $exclusions | Where-Object { $breakGlass -notcontains $_ }
    return $nonBreakGlass.Count -gt 0
}

function _isReportOnlyStale($policy, $staleDays) {
    if ($policy.State -ne 'enabledForReportingButNotEnforced') { return $false }
    if (-not $policy.ModifiedDateTime) { return $false }
    $modified = [datetime]$policy.ModifiedDateTime
    return $modified -lt (Get-Date).AddDays(-1 * [int]$staleDays)
}
