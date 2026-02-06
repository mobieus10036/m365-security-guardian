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
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-ConditionalAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [array]$ConditionalAccessPolicies
    )

    try {
        Write-Verbose "Analyzing Conditional Access policies..."

        # Get all Conditional Access policies
        $caPolicies = if ($ConditionalAccessPolicies) {
            $ConditionalAccessPolicies
        }
        else {
            Get-MgIdentityConditionalAccessPolicy -All
        }

        $totalPolicies = $caPolicies.Count
        $enabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
        $reportOnlyPolicies = ($caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
        $disabledPolicies = ($caPolicies | Where-Object { $_.State -eq 'disabled' }).Count

        $breakGlass = @()
        if ($Config.Security.BreakGlassAccounts) { $breakGlass = @($Config.Security.BreakGlassAccounts) }
        $minPolicies = if ($Config.Security.MinConditionalAccessPolicies) { $Config.Security.MinConditionalAccessPolicies } else { 1 }
        $staleReportOnlyDays = if ($Config.Security.ReportOnlyStaleDays) { $Config.Security.ReportOnlyStaleDays } else { 30 }
        $longStaleReportOnlyDays = if ($Config.Security.LongStaleReportOnlyDays) { $Config.Security.LongStaleReportOnlyDays } else { 90 }
        $maxExclusions = if ($null -ne $Config.Security.MaxConditionalAccessExclusions) { $Config.Security.MaxConditionalAccessExclusions } else { $null }
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

        # Enhanced security posture checks (Zero Trust essentials)
        # 1. Device Compliance - require compliant or hybrid-joined devices
        $deviceCompliance = $caPolicies | Where-Object { (_isEnabled $_) -and (_requiresDeviceCompliance $_) }
        
        # 2. User Risk Policy - protect against compromised accounts (distinct from sign-in risk)
        $userRiskPolicy = $caPolicies | Where-Object { (_isEnabled $_) -and (_handlesUserRisk $_) }
        
        # 3. Location-Based Controls - named locations, geo-blocking, trusted networks
        $locationPolicy = $caPolicies | Where-Object { (_isEnabled $_) -and (_hasLocationControls $_) }
        $untrustedLocationBlock = $caPolicies | Where-Object { (_isEnabled $_) -and (_blocksUntrustedLocations $_) }
        
        # 4. Token Protection - prevent token theft/replay attacks
        $tokenProtection = $caPolicies | Where-Object { (_isEnabled $_) -and (_hasTokenProtection $_) }
        
        # 5. Workload Identity Coverage - service principals and managed identities
        $workloadIdentityPolicy = $caPolicies | Where-Object { (_isEnabled $_) -and (_coversWorkloadIdentities $_) }
        
        # 6. App Protection Policy - MAM/Intune app protection
        $appProtectionPolicy = $caPolicies | Where-Object { (_isEnabled $_) -and (_requiresAppProtection $_) }
        
        # 7. Policy Conflict Detection - identify potentially conflicting policies
        $policyConflicts = _detectPolicyConflicts $caPolicies
        
        # 8. Coverage Gap Analysis - identify unprotected scenarios
        $coverageGaps = _analyzeCoverageGaps $caPolicies $breakGlass
        
        # 9. Guest/External User Controls
        $guestPolicy = $caPolicies | Where-Object { (_isEnabled $_) -and (_targetsGuestUsers $_) -and (_enforcesMfa $_) }

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

        # Enhanced security checks - Zero Trust essentials
        if (-not $deviceCompliance) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "High" }
            $issues += [PSCustomObject]@{ Message = "No policy requiring device compliance or hybrid Azure AD join"; Severity = "High" }
        }
        if (-not $userRiskPolicy) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "High" }
            $issues += [PSCustomObject]@{ Message = "No policy addressing user risk (compromised accounts)"; Severity = "High" }
        }
        if (-not $locationPolicy) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No location-based Conditional Access controls configured"; Severity = "Medium" }
        }
        if (-not $untrustedLocationBlock) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No policy blocking or requiring MFA from untrusted/unknown locations"; Severity = "Medium" }
        }
        if (-not $tokenProtection) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "Token protection not enabled (vulnerable to token theft attacks)"; Severity = "Medium" }
        }
        if (-not $workloadIdentityPolicy) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No Conditional Access policy protecting workload identities (service principals)"; Severity = "Medium" }
        }
        if (-not $appProtectionPolicy) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Low" }
            $issues += [PSCustomObject]@{ Message = "No policy requiring approved client apps or app protection"; Severity = "Low" }
        }
        if (-not $guestPolicy) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "No policy specifically protecting guest/external user access"; Severity = "Medium" }
        }
        if ($policyConflicts.Count -gt 0) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "$($policyConflicts.Count) potential policy conflicts detected"; Severity = "Medium" }
        }
        if ($coverageGaps.Count -gt 0) {
            $status = if ($status -eq "Pass") { "Warning" } else { $status }
            if ($severity -eq "Low") { $severity = "Medium" }
            $issues += [PSCustomObject]@{ Message = "Coverage gaps identified: $($coverageGaps -join '; ')"; Severity = "Medium" }
        }

        # ============================================
        # Per-Policy Gap Analysis
        # ============================================
        # Analyze each enabled policy for risks and improvement opportunities
        $policyFindings = @()
        $riskAggregation = @{}      # Key = Message, Value = @{ Count; Severity }
        $opportunityAggregation = @{} # Key = Message, Value = @{ Count; Severity }

        foreach ($policy in ($caPolicies | Where-Object { $_.State -ne 'disabled' })) {
            $policyRisks = @()
            $policyOpportunities = @()
            
            # === RISK DETECTION ===
            
            # 1. Overbroad Exclusions
            if (_overbroadExclusions $policy $breakGlass) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Excludes users beyond break-glass accounts, creating coverage gaps"
                    Severity = "High" 
                }
            }
            
            # 2. No Grant Controls
            if (-not (_hasGrantControls $policy)) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "No grant controls defined (MFA, block, compliance, etc.)"
                    Severity = "Critical" 
                }
            }
            
            # 3. Legacy Auth Not Blocked (if legacy clients targeted)
            $clientApps = @($policy.Conditions.ClientAppTypes | ForEach-Object { $_.ToLower() })
            $targetsLegacy = ($clientApps -contains 'exchangeactivesync') -or ($clientApps -contains 'other')
            if ($targetsLegacy -and -not (_blocksAccess $policy)) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Targets legacy auth clients but does not block access"
                    Severity = "High" 
                }
            }
            
            # 4. Stale Report-Only Policy
            if (_isReportOnlyStale $policy $longStaleReportOnlyDays) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Report-only mode for $longStaleReportOnlyDays+ days without enforcement"
                    Severity = "Medium" 
                }
            }
            elseif (_isReportOnlyStale $policy $staleReportOnlyDays) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Report-only mode for $staleReportOnlyDays+ days; consider enforcing or retiring"
                    Severity = "Low" 
                }
            }
            
            # 5. All Users + All Apps without MFA or Block
            $allUsers = (_coversAllUsers $policy $breakGlass)
            $allApps = (_includesAllApps $policy)
            $hasMfaOrBlock = (_enforcesMfa $policy) -or (_blocksAccess $policy)
            if ($allUsers -and $allApps -and -not $hasMfaOrBlock -and -not (_requiresDeviceCompliance $policy)) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Broad scope (all users/apps) without strong controls (MFA, block, or device compliance)"
                    Severity = "High" 
                }
            }
            
            # 6. Targets Admins Without Strong Auth
            if ((_targetsAdmins $policy) -and -not (_enforcesMfa $policy) -and -not (_hasAuthStrength $policy) -and -not (_blocksAccess $policy)) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Targets privileged roles/groups without MFA or authentication strength requirement"
                    Severity = "Critical" 
                }
            }
            
            # 7. Risk-based policy without appropriate response
            $signInRisks = @($policy.Conditions.SignInRiskLevels | ForEach-Object { $_.ToLower() })
            $userRisks = @($policy.Conditions.UserRiskLevels | ForEach-Object { $_.ToLower() })
            $hasRiskConditions = ($signInRisks.Count -gt 0) -or ($userRisks.Count -gt 0)
            if ($hasRiskConditions -and -not $hasMfaOrBlock -and -not (_hasAuthStrength $policy)) {
                $policyRisks += [PSCustomObject]@{ 
                    Message = "Has risk conditions but no strong response (MFA, block, or auth strength)"
                    Severity = "High" 
                }
            }
            
            # === OPPORTUNITY DETECTION ===
            
            # 1. Could use Authentication Strength (phishing-resistant)
            if ((_enforcesMfa $policy) -and -not (_hasAuthStrength $policy)) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Consider upgrading from MFA to Authentication Strength for phishing-resistant auth"
                    Severity = "Low" 
                }
            }
            
            # 2. Missing Session Controls for sensitive apps
            if ((_coversAdminApps $policy $adminAppIds) -and -not (_hasSessionControls $policy)) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Covers admin apps but lacks session controls (sign-in frequency, persistent browser)"
                    Severity = "Medium" 
                }
            }
            
            # 3. All Users but no Device Compliance
            if ($allUsers -and -not (_requiresDeviceCompliance $policy) -and -not (_blocksAccess $policy)) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Consider adding device compliance requirements for Zero Trust posture"
                    Severity = "Low" 
                }
            }
            
            # 4. No Location Controls
            if ($allUsers -and $allApps -and -not (_hasLocationControls $policy) -and -not (_blocksAccess $policy)) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Could benefit from location-based controls (trusted networks, geo-blocking)"
                    Severity = "Low" 
                }
            }
            
            # 5. Missing Token Protection for critical apps
            if ((_coversAdminApps $policy $adminAppIds) -and -not (_hasTokenProtection $policy)) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Critical apps could benefit from token protection against token theft"
                    Severity = "Medium" 
                }
            }
            
            # 6. User Risk Not Addressed
            $hasSignInRisk = $signInRisks.Count -gt 0
            if ($hasSignInRisk -and $userRisks.Count -eq 0 -and $allUsers) {
                $policyOpportunities += [PSCustomObject]@{ 
                    Message = "Addresses sign-in risk but not user risk; consider adding user risk conditions"
                    Severity = "Low" 
                }
            }
            
            # Build policy finding object
            $policyFindings += [PSCustomObject]@{
                DisplayName   = $policy.DisplayName
                State         = $policy.State
                Id            = $policy.Id
                Risks         = $policyRisks
                Opportunities = $policyOpportunities
            }
            
            # Aggregate for summary
            foreach ($risk in $policyRisks) {
                $key = $risk.Message
                if (-not $riskAggregation.ContainsKey($key)) {
                    $riskAggregation[$key] = @{ Count = 0; Severity = $risk.Severity }
                }
                $riskAggregation[$key].Count++
            }
            foreach ($opp in $policyOpportunities) {
                $key = $opp.Message
                if (-not $opportunityAggregation.ContainsKey($key)) {
                    $opportunityAggregation[$key] = @{ Count = 0; Severity = $opp.Severity }
                }
                $opportunityAggregation[$key].Count++
            }
        }
        
        # Build summary object
        $policyFindingsSummary = [PSCustomObject]@{
            Risks = @($riskAggregation.Keys | ForEach-Object {
                [PSCustomObject]@{
                    Message  = $_
                    Severity = $riskAggregation[$_].Severity
                    Count    = $riskAggregation[$_].Count
                }
            })
            Opportunities = @($opportunityAggregation.Keys | ForEach-Object {
                [PSCustomObject]@{
                    Message  = $_
                    Severity = $opportunityAggregation[$_].Severity
                    Count    = $opportunityAggregation[$_].Count
                }
            })
        }

        $message = "$enabledPolicies enabled policies found"
        $policiesWithRisks = ($policyFindings | Where-Object { $_.Risks.Count -gt 0 }).Count
        $policiesConsidered = $policyFindings.Count
        $caScore = if ($policiesConsidered -gt 0) {
            [math]::Round((($policiesConsidered - $policiesWithRisks) / $policiesConsidered) * 100, 1)
        } else { 0 }
        
        # Build a concise summary message for console/CSV
        if ($issues.Count -gt 0) {
            # Count issues by severity
            $criticalCount = ($issues | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highCount = ($issues | Where-Object { $_.Severity -eq 'High' }).Count
            $mediumCount = ($issues | Where-Object { $_.Severity -eq 'Medium' }).Count
            
            $severitySummary = @()
            if ($criticalCount -gt 0) { $severitySummary += "$criticalCount critical" }
            if ($highCount -gt 0) { $severitySummary += "$highCount high" }
            if ($mediumCount -gt 0) { $severitySummary += "$mediumCount medium" }
            
            $message += ". $($issues.Count) security gaps found"
            if ($severitySummary.Count -gt 0) {
                $message += " ($($severitySummary -join ', '))"
            }
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
        
        # Enhanced recommendations for Zero Trust controls
        if (-not $deviceCompliance) { $recommendations += "Implement device compliance policy requiring compliant or hybrid Azure AD joined devices for corporate resource access" }
        if (-not $userRiskPolicy) { $recommendations += "Add user risk-based policy to block or require password change for medium/high risk users (Identity Protection)" }
        if (-not $locationPolicy) { $recommendations += "Configure named locations and implement location-based access controls" }
        if (-not $untrustedLocationBlock) { $recommendations += "Block access or require additional verification from untrusted/unknown locations" }
        if (-not $tokenProtection) { $recommendations += "Enable token protection (Conditional Access token binding) to prevent token theft attacks" }
        if (-not $workloadIdentityPolicy) { $recommendations += "Create CA policies for workload identities to protect service principals and managed identities" }
        if (-not $appProtectionPolicy) { $recommendations += "Require approved client apps or Intune app protection policies for mobile access" }
        if (-not $guestPolicy) { $recommendations += "Create dedicated CA policy for guest/external users with appropriate MFA and access restrictions" }
        if ($policyConflicts.Count -gt 0) { $recommendations += "Review and resolve detected policy conflicts to ensure consistent access controls" }
        if ($coverageGaps.Count -gt 0) { $recommendations += "Address identified coverage gaps: $($coverageGaps -join '; ')" }

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
                PolicyFindings = $policyFindings
                PolicyFindingsSummary = $policyFindingsSummary
                BaselineMFA = [bool]$baselineMfa
                LegacyAuthBlocked = [bool]$legacyBlock
                LegacyBlockComplete = [bool]$legacyComplete
                AdminProtection = [bool]$adminProtection
                RiskySignInGoverned = [bool]$riskySignIn
                StrongAuthStrength = [bool]$strongAuthStrength
                SessionGoverned = [bool]$sessionGoverned
                ExclusionOverreach = [bool]$exclusionOverreach
                ReportOnlyStale = [bool]$staleReportOnly
                # Enhanced Zero Trust controls
                DeviceCompliance = [bool]$deviceCompliance
                UserRiskPolicy = [bool]$userRiskPolicy
                LocationControls = [bool]$locationPolicy
                UntrustedLocationBlocked = [bool]$untrustedLocationBlock
                TokenProtection = [bool]$tokenProtection
                WorkloadIdentityProtection = [bool]$workloadIdentityPolicy
                AppProtectionPolicy = [bool]$appProtectionPolicy
                GuestUserPolicy = [bool]$guestPolicy
                PolicyConflicts = $policyConflicts
                CoverageGaps = $coverageGaps
                Issues = $issues
            }
            EnabledPolicies = $enabledPolicyList
            PolicyFindings = $policyFindings
            PolicyFindingsSummary = $policyFindingsSummary
            ConditionalAccessScore = $caScore
            # Structured findings for display (array format for list rendering)
            Findings = $issues | ForEach-Object {
                [PSCustomObject]@{
                    Message = $_.Message
                    Severity = $_.Severity
                }
            }
            # Recommendations as array for bullet list display
            Recommendations = $recommendations
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
                "5. Configure device compliance requirements (Intune/hybrid join)"
                "6. Add user risk policy to handle compromised accounts (block or password change)"
                "7. Set up named locations and location-based access controls"
                "8. Enable token protection for critical apps"
                "9. Create workload identity policies for service principals"
                "10. Configure guest/external user access policies"
                "11. Review policies for conflicts and coverage gaps"
                "12. Test in Report-only where needed, then enforce and monitor sign-in logs"
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

function _blocksAccess($policy) {
    $grant = $policy.GrantControls
    return $grant -and ($grant.BuiltInControls -contains 'block')
}

function _hasGrantControls($policy) {
    $grant = $policy.GrantControls
    if (-not $grant) { return $false }
    if ($grant.BuiltInControls -and $grant.BuiltInControls.Count -gt 0) { return $true }
    if ($grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id) { return $true }
    if ($grant.TermsOfUse -and $grant.TermsOfUse.Count -gt 0) { return $true }
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

# ============================================
# Enhanced Security Posture Helper Functions
# ============================================

function _requiresDeviceCompliance($policy) {
    # Check if policy requires compliant device, hybrid Azure AD join, or approved device
    $grant = $policy.GrantControls
    if (-not $grant) { return $false }
    $controls = @($grant.BuiltInControls | ForEach-Object { $_.ToLower() })
    return ($controls -contains 'compliantdevice') -or 
           ($controls -contains 'domainjoineddevice') -or
           ($controls -contains 'approvedapplication')
}

function _handlesUserRisk($policy) {
    # Check if policy handles user risk levels (distinct from sign-in risk)
    $userRisks = @($policy.Conditions.UserRiskLevels | ForEach-Object { $_.ToLower() })
    if (-not ($userRisks -contains 'medium' -or $userRisks -contains 'high')) { return $false }
    
    $grant = $policy.GrantControls
    if (-not $grant) { return $false }
    $controls = @($grant.BuiltInControls | ForEach-Object { $_.ToLower() })
    $hasAuthStrength = $grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id
    
    # User risk should block or require password change
    return ($controls -contains 'block') -or 
           ($controls -contains 'passwordchange') -or 
           ($controls -contains 'mfa') -or 
           $hasAuthStrength
}

function _hasLocationControls($policy) {
    # Check if policy uses location conditions
    $locations = $policy.Conditions.Locations
    if (-not $locations) { return $false }
    
    $hasInclude = $locations.IncludeLocations -and $locations.IncludeLocations.Count -gt 0
    $hasExclude = $locations.ExcludeLocations -and $locations.ExcludeLocations.Count -gt 0
    
    return $hasInclude -or $hasExclude
}

function _blocksUntrustedLocations($policy) {
    # Check if policy blocks or requires MFA from untrusted/all locations
    $locations = $policy.Conditions.Locations
    if (-not $locations) { return $false }
    
    # Policy should include all locations or specifically target untrusted
    $includesAllLocations = $locations.IncludeLocations -contains 'All'
    $includesAllTrusted = $locations.IncludeLocations -contains 'AllTrusted'
    
    # Must have grant controls (block or MFA)
    $grant = $policy.GrantControls
    if (-not $grant) { return $false }
    $controls = @($grant.BuiltInControls | ForEach-Object { $_.ToLower() })
    $hasAuthStrength = $grant.AuthenticationStrength -and $grant.AuthenticationStrength.Id
    
    # Either blocks access or requires MFA from non-trusted locations
    $hasStrongControl = ($controls -contains 'block') -or 
                        ($controls -contains 'mfa') -or 
                        $hasAuthStrength
    
    # Scenario 1: Includes all locations but excludes trusted (blocks untrusted)
    $excludesTrusted = $locations.ExcludeLocations -contains 'AllTrusted'
    
    # Scenario 2: Only includes all trusted locations (implicitly allows only trusted)
    return ($includesAllLocations -and $excludesTrusted -and $hasStrongControl) -or
           ($includesAllLocations -and $hasStrongControl)
}

function _hasTokenProtection($policy) {
    # Check if policy enables token protection (Conditional Access token binding)
    $session = $policy.SessionControls
    if (-not $session) { return $false }
    
    # Token protection is in SessionControls.SecureSignInSession or similar
    if ($session.SecureSignInSession -and $session.SecureSignInSession.IsEnabled) {
        return $true
    }
    
    # Also check for continuous access evaluation (related protection)
    if ($session.ContinuousAccessEvaluation -and 
        $session.ContinuousAccessEvaluation.Mode -eq 'strictEnforcement') {
        return $true
    }
    
    return $false
}

function _coversWorkloadIdentities($policy) {
    # Check if policy targets service principals / workload identities
    $clientApps = $policy.Conditions.ClientApplications
    if (-not $clientApps) { return $false }
    
    # Check for service principal coverage
    $includesSPs = $clientApps.IncludeServicePrincipals -and 
                   ($clientApps.IncludeServicePrincipals.Count -gt 0 -or 
                    $clientApps.IncludeServicePrincipals -contains 'All')
    
    return $includesSPs
}

function _requiresAppProtection($policy) {
    # Check if policy requires approved apps or app protection policy
    $grant = $policy.GrantControls
    if (-not $grant) { return $false }
    $controls = @($grant.BuiltInControls | ForEach-Object { $_.ToLower() })
    
    return ($controls -contains 'approvedapplication') -or 
           ($controls -contains 'compliantapplication')
}

function _targetsGuestUsers($policy) {
    # Check if policy specifically targets guest/external users
    $users = $policy.Conditions.Users
    if (-not $users) { return $false }
    
    # Check for guest user types
    $includesGuests = $users.IncludeGuestsOrExternalUsers -and 
                      $users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes
    
    # Also check if include users contains 'GuestsOrExternalUsers'
    $includesAll = $users.IncludeUsers -contains 'All'
    $includesGuestType = $users.IncludeUsers -contains 'GuestsOrExternalUsers'
    
    return $includesGuests -or $includesGuestType -or $includesAll
}

function _detectPolicyConflicts($policies) {
    # Detect potentially conflicting policies
    $conflicts = @()
    $enabledPolicies = @($policies | Where-Object { $_.State -eq 'enabled' })
    
    for ($i = 0; $i -lt $enabledPolicies.Count; $i++) {
        for ($j = $i + 1; $j -lt $enabledPolicies.Count; $j++) {
            $policy1 = $enabledPolicies[$i]
            $policy2 = $enabledPolicies[$j]
            
            # Check for overlapping scope with conflicting controls
            $overlap = _policiesOverlap $policy1 $policy2
            if ($overlap) {
                $conflict = _hasConflictingControls $policy1 $policy2
                if ($conflict) {
                    $conflicts += [PSCustomObject]@{
                        Policy1 = $policy1.DisplayName
                        Policy2 = $policy2.DisplayName
                        ConflictType = $conflict
                    }
                }
            }
        }
    }
    
    return $conflicts
}

function _policiesOverlap($policy1, $policy2) {
    # Check if two policies have overlapping user/app scope
    $users1 = $policy1.Conditions.Users
    $users2 = $policy2.Conditions.Users
    $apps1 = $policy1.Conditions.Applications
    $apps2 = $policy2.Conditions.Applications
    
    # Both target all users
    $bothAllUsers = ($users1.IncludeUsers -contains 'All') -and 
                    ($users2.IncludeUsers -contains 'All')
    
    # Both target all apps
    $bothAllApps = ($apps1.IncludeApplications -contains 'All') -and 
                   ($apps2.IncludeApplications -contains 'All')
    
    # Same apps targeted
    $sameApps = $apps1.IncludeApplications | Where-Object { 
        $apps2.IncludeApplications -contains $_ 
    }
    
    return $bothAllUsers -or ($bothAllApps -and ($sameApps.Count -gt 0))
}

function _hasConflictingControls($policy1, $policy2) {
    # Check if policies have conflicting grant controls
    $grant1 = $policy1.GrantControls
    $grant2 = $policy2.GrantControls
    
    if (-not $grant1 -or -not $grant2) { return $null }
    
    $controls1 = @($grant1.BuiltInControls | ForEach-Object { $_.ToLower() })
    $controls2 = @($grant2.BuiltInControls | ForEach-Object { $_.ToLower() })
    
    # Block vs Allow conflict
    $oneBlocks = ($controls1 -contains 'block') -and ($controls2 -notcontains 'block')
    $otherBlocks = ($controls2 -contains 'block') -and ($controls1 -notcontains 'block')
    
    if ($oneBlocks -or $otherBlocks) {
        return "Block vs Allow conflict"
    }
    
    # Different MFA requirements
    $mfa1 = $controls1 -contains 'mfa'
    $mfa2 = $controls2 -contains 'mfa'
    $auth1 = $grant1.AuthenticationStrength -and $grant1.AuthenticationStrength.Id
    $auth2 = $grant2.AuthenticationStrength -and $grant2.AuthenticationStrength.Id
    
    if (($mfa1 -or $auth1) -and -not ($mfa2 -or $auth2)) {
        return "Inconsistent MFA requirements"
    }
    
    return $null
}

function _analyzeCoverageGaps($policies, $breakGlass) {
    # Identify gaps in policy coverage
    $gaps = @()
    $enabledPolicies = @($policies | Where-Object { $_.State -eq 'enabled' })
    
    if ($enabledPolicies.Count -eq 0) {
        $gaps += "No enabled policies"
        return $gaps
    }
    
    # Check for browser vs mobile app coverage
    $browserPolicies = $enabledPolicies | Where-Object {
        $clientApps = @($_.Conditions.ClientAppTypes)
        ($clientApps.Count -eq 0) -or ($clientApps -contains 'browser') -or ($clientApps -contains 'all')
    }
    $mobileAppPolicies = $enabledPolicies | Where-Object {
        $clientApps = @($_.Conditions.ClientAppTypes)
        ($clientApps.Count -eq 0) -or ($clientApps -contains 'mobileAppsAndDesktopClients') -or ($clientApps -contains 'all')
    }
    
    if ($browserPolicies.Count -eq 0) {
        $gaps += "No policies covering browser access"
    }
    if ($mobileAppPolicies.Count -eq 0) {
        $gaps += "No policies covering mobile/desktop apps"
    }
    
    # Check for platform coverage
    $windowsPolicies = $enabledPolicies | Where-Object {
        $platforms = $_.Conditions.Platforms
        (-not $platforms) -or 
        ($platforms.IncludePlatforms -contains 'all') -or 
        ($platforms.IncludePlatforms -contains 'windows')
    }
    $iosPolicies = $enabledPolicies | Where-Object {
        $platforms = $_.Conditions.Platforms
        (-not $platforms) -or 
        ($platforms.IncludePlatforms -contains 'all') -or 
        ($platforms.IncludePlatforms -contains 'iOS')
    }
    $androidPolicies = $enabledPolicies | Where-Object {
        $platforms = $_.Conditions.Platforms
        (-not $platforms) -or 
        ($platforms.IncludePlatforms -contains 'all') -or 
        ($platforms.IncludePlatforms -contains 'android')
    }
    $macPolicies = $enabledPolicies | Where-Object {
        $platforms = $_.Conditions.Platforms
        (-not $platforms) -or 
        ($platforms.IncludePlatforms -contains 'all') -or 
        ($platforms.IncludePlatforms -contains 'macOS')
    }
    $linuxPolicies = $enabledPolicies | Where-Object {
        $platforms = $_.Conditions.Platforms
        (-not $platforms) -or 
        ($platforms.IncludePlatforms -contains 'all') -or 
        ($platforms.IncludePlatforms -contains 'linux')
    }
    
    # Only flag if explicitly excluding platforms without coverage
    $platformGaps = @()
    if ($windowsPolicies.Count -eq 0) { $platformGaps += "Windows" }
    if ($iosPolicies.Count -eq 0) { $platformGaps += "iOS" }
    if ($androidPolicies.Count -eq 0) { $platformGaps += "Android" }
    if ($macPolicies.Count -eq 0) { $platformGaps += "macOS" }
    if ($linuxPolicies.Count -eq 0) { $platformGaps += "Linux" }
    
    if ($platformGaps.Count -gt 0) {
        $gaps += "Platform gaps: $($platformGaps -join ', ')"
    }
    
    # Check for O365 apps not covered
    $o365Apps = @(
        "Office365", 
        "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
        "00000003-0000-0ff1-ce00-000000000000"   # SharePoint Online
    )
    
    $o365Covered = $enabledPolicies | Where-Object {
        $apps = $_.Conditions.Applications
        ($apps.IncludeApplications -contains 'All') -or
        ($apps.IncludeApplications -contains 'Office365') -or
        ($o365Apps | Where-Object { $apps.IncludeApplications -contains $_ })
    }
    
    if ($o365Covered.Count -eq 0) {
        $gaps += "Office 365 apps may not be fully covered by CA policies"
    }
    
    return $gaps
}
