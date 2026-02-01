<#
.SYNOPSIS
    Tests Privileged Identity Management (PIM) configuration and role assignments.

.DESCRIPTION
    Evaluates PIM configuration including:
    - Standing vs Just-In-Time (JIT) admin assignments
    - Role activation requirements (MFA, justification, approval)
    - Eligible vs active role assignments
    - PIM alerts configuration
    - Access review status
    Identifies security risks from permanent privileged access.

.PARAMETER Config
    Configuration object containing PIM requirements.

.OUTPUTS
    PSCustomObject containing PIM assessment results.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
    Requires: Microsoft.Graph.Identity.Governance module
#>

function Test-PIMConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing Privileged Identity Management configuration..."

        # Configuration defaults
        $maxStandingGlobalAdmins = if ($Config.Security.MaxStandingGlobalAdmins) { 
            $Config.Security.MaxStandingGlobalAdmins 
        } else { 2 }
        
        $requirePIMForAdmins = if ($null -ne $Config.Security.RequirePIMForAdmins) { 
            $Config.Security.RequirePIMForAdmins 
        } else { $true }

        $breakGlassAccounts = @()
        if ($Config.Security.BreakGlassAccounts) { 
            $breakGlassAccounts = @($Config.Security.BreakGlassAccounts) 
        }

        # Critical roles to check for PIM coverage
        $criticalRoles = @(
            'Global Administrator',
            'Privileged Role Administrator',
            'Security Administrator',
            'Exchange Administrator',
            'SharePoint Administrator',
            'User Administrator',
            'Application Administrator',
            'Cloud Application Administrator',
            'Authentication Administrator',
            'Privileged Authentication Administrator',
            'Conditional Access Administrator',
            'Intune Administrator',
            'Billing Administrator',
            'Helpdesk Administrator'
        )

        $highestPrivilegeRoles = @(
            'Global Administrator',
            'Privileged Role Administrator',
            'Privileged Authentication Administrator'
        )

        # Initialize results
        $issues = @()
        $roleAnalysis = @()
        $standingAdminDetails = @()
        $eligibleAssignments = @()
        $pimRoleSettings = @()
        $accessReviewStatus = @()

        # Check if PIM is available (requires Entra ID P2)
        $pimAvailable = $false
        $roleAssignmentSchedules = @()
        $roleEligibilitySchedules = @()

        try {
            # Get active (standing) role assignments via PIM API
            $roleAssignmentSchedules = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction Stop
            $pimAvailable = $true
            Write-Verbose "PIM is available - retrieved $($roleAssignmentSchedules.Count) active assignments"
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -match "Forbidden|Authorization|Premium|P2|license") {
                Write-Verbose "PIM not available - likely missing Entra ID P2 license"
                return [PSCustomObject]@{
                    CheckName = "Privileged Identity Management (PIM)"
                    Category = "Security"
                    Status = "Warning"
                    Severity = "High"
                    Message = "PIM not available - Entra ID P2 license required for Just-In-Time privileged access"
                    Details = @{
                        PIMAvailable = $false
                        LicenseRequired = "Microsoft Entra ID P2 or Microsoft Entra ID Governance"
                    }
                    Recommendation = "Enable Entra ID P2 licensing to use PIM for Just-In-Time admin access, reducing standing privilege attack surface"
                    DocumentationUrl = "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"
                    RemediationSteps = @(
                        "1. Acquire Microsoft Entra ID P2 or Entra ID Governance licenses",
                        "2. Assign licenses to privileged users",
                        "3. Configure PIM for critical admin roles",
                        "4. Convert permanent assignments to eligible (JIT) assignments",
                        "5. Configure activation requirements (MFA, justification, approval)"
                    )
                }
            }
            Write-Verbose "Error checking PIM: $_"
        }

        if ($pimAvailable) {
            # Get eligible role assignments
            try {
                $roleEligibilitySchedules = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue
                Write-Verbose "Retrieved $($roleEligibilitySchedules.Count) eligible assignments"
            }
            catch {
                Write-Verbose "Could not retrieve eligible assignments: $_"
            }

            # Get role definitions for mapping
            $roleDefinitions = @{}
            try {
                $roles = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction SilentlyContinue
                foreach ($role in $roles) {
                    $roleDefinitions[$role.Id] = $role.DisplayName
                }
            }
            catch {
                Write-Verbose "Could not retrieve role definitions: $_"
            }

            # Analyze active (standing) assignments
            $standingAssignmentsByRole = @{}
            foreach ($assignment in $roleAssignmentSchedules) {
                $roleName = if ($roleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                    $roleDefinitions[$assignment.RoleDefinitionId]
                } else {
                    $assignment.RoleDefinitionId
                }

                # Get principal details
                $principalId = $assignment.PrincipalId
                $principalName = ""
                $principalType = ""
                $principalUpn = ""
                
                try {
                    $principal = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction SilentlyContinue
                    if ($principal) {
                        $principalType = $principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                        $principalName = $principal.AdditionalProperties.displayName
                        $principalUpn = $principal.AdditionalProperties.userPrincipalName
                    }
                }
                catch {
                    Write-Verbose "Could not get principal details for $principalId"
                }

                # Check if this is a break-glass account
                $isBreakGlass = $false
                if ($principalUpn -and $breakGlassAccounts.Count -gt 0) {
                    foreach ($bg in $breakGlassAccounts) {
                        if ($principalUpn -like $bg) {
                            $isBreakGlass = $true
                            break
                        }
                    }
                }

                # Track by role
                if (-not $standingAssignmentsByRole.ContainsKey($roleName)) {
                    $standingAssignmentsByRole[$roleName] = @()
                }

                $assignmentDetail = [PSCustomObject]@{
                    RoleName = $roleName
                    PrincipalId = $principalId
                    PrincipalName = $principalName
                    PrincipalUpn = $principalUpn
                    PrincipalType = $principalType
                    AssignmentType = "Active (Standing)"
                    IsBreakGlass = $isBreakGlass
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                    AssignmentState = if ($assignment.EndDateTime) { "Time-Bound" } else { "Permanent" }
                }

                $standingAssignmentsByRole[$roleName] += $assignmentDetail

                # Only add to details if it's a critical role and not break-glass
                if ($roleName -in $criticalRoles -and -not $isBreakGlass) {
                    $standingAdminDetails += $assignmentDetail
                }
            }

            # Analyze eligible assignments
            foreach ($eligibility in $roleEligibilitySchedules) {
                $roleName = if ($roleDefinitions.ContainsKey($eligibility.RoleDefinitionId)) {
                    $roleDefinitions[$eligibility.RoleDefinitionId]
                } else {
                    $eligibility.RoleDefinitionId
                }

                $principalId = $eligibility.PrincipalId
                $principalName = ""
                $principalUpn = ""
                
                try {
                    $principal = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction SilentlyContinue
                    if ($principal) {
                        $principalName = $principal.AdditionalProperties.displayName
                        $principalUpn = $principal.AdditionalProperties.userPrincipalName
                    }
                }
                catch {
                    Write-Verbose "Could not get principal details for $principalId"
                }

                if ($roleName -in $criticalRoles) {
                    $eligibleAssignments += [PSCustomObject]@{
                        RoleName = $roleName
                        PrincipalName = $principalName
                        PrincipalUpn = $principalUpn
                        StartDateTime = $eligibility.StartDateTime
                        EndDateTime = $eligibility.EndDateTime
                    }
                }
            }

            # Analyze role settings (activation requirements)
            try {
                $roleSettingsPolicies = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -ExpandProperty "policy(`$expand=rules)" -All -ErrorAction SilentlyContinue
                
                foreach ($policyAssignment in $roleSettingsPolicies) {
                    $roleName = if ($roleDefinitions.ContainsKey($policyAssignment.RoleDefinitionId)) {
                        $roleDefinitions[$policyAssignment.RoleDefinitionId]
                    } else {
                        continue  # Skip if we can't identify the role
                    }

                    if ($roleName -notin $criticalRoles) { continue }

                    $policy = $policyAssignment.Policy
                    if (-not $policy) { continue }

                    $rules = $policy.Rules
                    
                    # Analyze rules for this role
                    $requiresMfa = $false
                    $requiresJustification = $false
                    $requiresApproval = $false
                    $maxActivationDuration = $null
                    $approvers = @()

                    foreach ($rule in $rules) {
                        $ruleType = $rule.AdditionalProperties.'@odata.type'
                        
                        switch -Wildcard ($ruleType) {
                            "*AuthenticationContextRule*" {
                                # Check for authentication requirements
                                if ($rule.AdditionalProperties.isEnabled) {
                                    $requiresMfa = $true
                                }
                            }
                            "*EnablementRule*" {
                                $enabledRules = $rule.AdditionalProperties.enabledRules
                                if ($enabledRules -contains "MultiFactorAuthentication") {
                                    $requiresMfa = $true
                                }
                                if ($enabledRules -contains "Justification") {
                                    $requiresJustification = $true
                                }
                                if ($enabledRules -contains "Ticketing") {
                                    # Ticketing system integration
                                }
                            }
                            "*ApprovalRule*" {
                                $approvalSettings = $rule.AdditionalProperties.setting
                                if ($approvalSettings.isApprovalRequired) {
                                    $requiresApproval = $true
                                    # Get approvers
                                    $stages = $approvalSettings.approvalStages
                                    foreach ($stage in $stages) {
                                        foreach ($approver in $stage.primaryApprovers) {
                                            $approvers += $approver.description
                                        }
                                    }
                                }
                            }
                            "*ExpirationRule*" {
                                if ($rule.Id -eq "Expiration_EndUser_Assignment") {
                                    $maxDuration = $rule.AdditionalProperties.maximumDuration
                                    if ($maxDuration) {
                                        $maxActivationDuration = $maxDuration
                                    }
                                }
                            }
                        }
                    }

                    $pimRoleSettings += [PSCustomObject]@{
                        RoleName = $roleName
                        RequiresMFA = $requiresMfa
                        RequiresJustification = $requiresJustification
                        RequiresApproval = $requiresApproval
                        MaxActivationDuration = $maxActivationDuration
                        Approvers = ($approvers -join ", ")
                    }

                    # Flag issues with high-privilege role settings
                    if ($roleName -in $highestPrivilegeRoles) {
                        if (-not $requiresMfa) {
                            $issues += [PSCustomObject]@{
                                Message = "$roleName activation does not require MFA"
                                Severity = "High"
                            }
                        }
                        if (-not $requiresJustification) {
                            $issues += [PSCustomObject]@{
                                Message = "$roleName activation does not require justification"
                                Severity = "Medium"
                            }
                        }
                        if (-not $requiresApproval -and $roleName -eq 'Global Administrator') {
                            $issues += [PSCustomObject]@{
                                Message = "Global Administrator activation does not require approval"
                                Severity = "Medium"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve PIM role settings: $_"
            }

            # Check access reviews for privileged roles
            try {
                $accessReviews = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction SilentlyContinue
                
                foreach ($review in $accessReviews) {
                    # Check if this review covers privileged roles
                    $scope = $review.Scope
                    if ($scope -and $scope.AdditionalProperties.query -match "roleManagement") {
                        $accessReviewStatus += [PSCustomObject]@{
                            ReviewName = $review.DisplayName
                            Status = $review.Status
                            CreatedDateTime = $review.CreatedDateTime
                            StartDate = $review.Settings.StartDate
                            EndDate = $review.Settings.EndDate
                            Recurrence = if ($review.Settings.Recurrence) { "Recurring" } else { "One-Time" }
                        }
                    }
                }

                if ($accessReviewStatus.Count -eq 0) {
                    $issues += [PSCustomObject]@{
                        Message = "No access reviews configured for privileged roles"
                        Severity = "Medium"
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve access reviews: $_"
            }

            # Build role analysis summary
            foreach ($roleName in $criticalRoles) {
                $standingCount = 0
                $eligibleCount = 0
                $standingNonBreakGlass = 0

                if ($standingAssignmentsByRole.ContainsKey($roleName)) {
                    $assignments = $standingAssignmentsByRole[$roleName]
                    $standingCount = $assignments.Count
                    $standingNonBreakGlass = ($assignments | Where-Object { -not $_.IsBreakGlass }).Count
                }

                $eligibleCount = ($eligibleAssignments | Where-Object { $_.RoleName -eq $roleName }).Count

                if ($standingCount -gt 0 -or $eligibleCount -gt 0) {
                    $roleAnalysis += [PSCustomObject]@{
                        RoleName = $roleName
                        StandingAssignments = $standingCount
                        StandingNonBreakGlass = $standingNonBreakGlass
                        EligibleAssignments = $eligibleCount
                        IsHighPrivilege = ($roleName -in $highestPrivilegeRoles)
                    }
                }
            }

            # Check for standing Global Administrators (excluding break-glass)
            $gaAnalysis = $roleAnalysis | Where-Object { $_.RoleName -eq 'Global Administrator' }
            $standingGAs = if ($gaAnalysis) { $gaAnalysis.StandingNonBreakGlass } else { 0 }

            if ($standingGAs -gt $maxStandingGlobalAdmins) {
                $issues += [PSCustomObject]@{
                    Message = "$standingGAs standing Global Administrators (recommended max: $maxStandingGlobalAdmins excluding break-glass)"
                    Severity = "High"
                }
            }

            # Check for any high-privilege roles without eligible assignments (all standing)
            foreach ($role in ($roleAnalysis | Where-Object { $_.IsHighPrivilege })) {
                if ($role.EligibleAssignments -eq 0 -and $role.StandingNonBreakGlass -gt 0) {
                    $issues += [PSCustomObject]@{
                        Message = "$($role.RoleName) has no eligible (JIT) assignments - all access is standing"
                        Severity = "High"
                    }
                }
            }
        }

        # Determine overall status
        $status = "Pass"
        $severity = "Low"

        if (-not $pimAvailable) {
            $status = "Warning"
            $severity = "High"
        }
        else {
            $criticalIssues = ($issues | Where-Object { $_.Severity -eq "Critical" }).Count
            $highIssues = ($issues | Where-Object { $_.Severity -eq "High" }).Count
            $mediumIssues = ($issues | Where-Object { $_.Severity -eq "Medium" }).Count

            if ($criticalIssues -gt 0) {
                $status = "Fail"
                $severity = "Critical"
            }
            elseif ($highIssues -gt 0) {
                $status = "Fail"
                $severity = "High"
            }
            elseif ($mediumIssues -gt 0) {
                $status = "Warning"
                $severity = "Medium"
            }
        }

        # Build message
        $totalStanding = ($standingAdminDetails | Where-Object { -not $_.IsBreakGlass }).Count
        $totalEligible = $eligibleAssignments.Count
        $message = "PIM Status: $totalStanding standing privileged assignments, $totalEligible eligible (JIT) assignments"

        if ($issues.Count -gt 0) {
            $message += ". Issues: $($issues.Count) findings"
        }

        # Build recommendations
        $recommendations = @()
        if ($totalStanding -gt $maxStandingGlobalAdmins) {
            $recommendations += "Convert standing privileged role assignments to eligible (JIT) assignments"
        }
        if (($pimRoleSettings | Where-Object { -not $_.RequiresMFA -and $_.RoleName -in $highestPrivilegeRoles }).Count -gt 0) {
            $recommendations += "Enable MFA requirement for all high-privilege role activations"
        }
        if (($pimRoleSettings | Where-Object { -not $_.RequiresJustification }).Count -gt 0) {
            $recommendations += "Require justification for privileged role activations"
        }
        if ($accessReviewStatus.Count -eq 0) {
            $recommendations += "Configure recurring access reviews for privileged roles"
        }

        return [PSCustomObject]@{
            CheckName = "Privileged Identity Management (PIM)"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                PIMAvailable = $pimAvailable
                TotalStandingAssignments = $totalStanding
                TotalEligibleAssignments = $totalEligible
                CriticalRolesAnalyzed = $roleAnalysis.Count
                IssuesFound = $issues.Count
                AccessReviewsConfigured = $accessReviewStatus.Count
            }
            RoleAnalysis = $roleAnalysis
            StandingAdminDetails = $standingAdminDetails
            EligibleAssignments = $eligibleAssignments
            RoleSettings = $pimRoleSettings
            AccessReviews = $accessReviewStatus
            Issues = $issues
            Recommendations = $recommendations
            Recommendation = if ($recommendations.Count -gt 0) {
                $recommendations -join "; "
            } else {
                "PIM configuration meets security best practices. Continue monitoring privileged access."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"
            RemediationSteps = @(
                "1. Review standing privileged assignments in Entra ID > Identity Governance > PIM",
                "2. Convert permanent assignments to eligible (Just-In-Time) assignments",
                "3. Configure activation requirements: MFA, justification, approval for high-privilege roles",
                "4. Set appropriate activation duration limits (e.g., 8 hours max)",
                "5. Configure recurring access reviews for all privileged roles",
                "6. Maintain only 2 break-glass accounts with permanent Global Admin access",
                "7. Enable PIM alerts for suspicious activities",
                "8. Monitor PIM audit logs for activation patterns"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Privileged Identity Management (PIM)"
            Category = "Security"
            Status = "Error"
            Severity = "High"
            Message = "Error analyzing PIM configuration: $($_.Exception.Message)"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify permissions and module availability"
            DocumentationUrl = "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"
            RemediationSteps = @(
                "Ensure RoleManagement.Read.All and RoleManagement.Read.Directory permissions are granted",
                "Verify Microsoft.Graph.Identity.Governance module is installed"
            )
        }
    }
}
