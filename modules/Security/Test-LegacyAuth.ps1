<#
.SYNOPSIS
    Tests for legacy authentication protocol usage and blocking.

.DESCRIPTION
    Identifies if legacy authentication protocols (Basic Auth, POP, IMAP, etc.)
    are enabled and checks for policies blocking them.

.PARAMETER Config
    Configuration object containing legacy auth requirements.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Assessment Toolkit
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-LegacyAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [array]$ConditionalAccessPolicies
    )

    try {
        Write-Verbose "Analyzing legacy authentication configuration..."

        # Check Conditional Access policies for legacy auth blocking
        $caPolicies = if ($ConditionalAccessPolicies) {
            $ConditionalAccessPolicies
        }
        else {
            Get-MgIdentityConditionalAccessPolicy -All
        }

        $legacyAuthBlockPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and (
                $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
                $_.Conditions.ClientAppTypes -contains 'other'
            ) -and (
                $_.GrantControls.BuiltInControls -contains 'block'
            )
        }

        $hasLegacyAuthBlock = $null -ne $legacyAuthBlockPolicies -and $legacyAuthBlockPolicies.Count -gt 0

        # Check authentication methods policy (if accessible)
        $authMethodsPolicy = $null
        try {
            $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Could not retrieve authentication methods policy"
        }

        # Determine status
        $legacyAuthAllowed = if ($null -ne $Config.Security.LegacyAuthAllowed) {
            $Config.Security.LegacyAuthAllowed
        } else { $false }

        $status = "Pass"
        $severity = "Low"
        $message = ""

        if (-not $hasLegacyAuthBlock) {
            $status = "Fail"
            $severity = "High"
            $message = "Legacy authentication is not blocked via Conditional Access"
        }
        else {
            $message = "Legacy authentication is blocked ($($legacyAuthBlockPolicies.Count) policies found)"
        }

        # Check for any recent legacy auth sign-ins (if we can access sign-in logs)
        $recentLegacySignIns = $null
        try {
            $startDate = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
            
            # Fix: Wrap client app conditions in parentheses so date filter applies to all
            $signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and (clientAppUsed eq 'Other clients' or clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'POP3' or clientAppUsed eq 'IMAP4')" -Top 10 -ErrorAction SilentlyContinue
            
            if ($signIns -and $signIns.Count -gt 0) {
                $recentLegacySignIns = $signIns.Count
                
                if ($status -eq "Pass") {
                    $status = "Warning"
                    $severity = "Medium"
                }
                
                $message += ". WARNING: $recentLegacySignIns legacy auth sign-ins in last 7 days"
            }
        }
        catch {
            Write-Verbose "Could not check recent sign-ins: $_"
        }

        return [PSCustomObject]@{
            CheckName = "Legacy Authentication Blocking"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                HasLegacyAuthBlockPolicy = $hasLegacyAuthBlock
                BlockPolicyCount = if ($legacyAuthBlockPolicies) { $legacyAuthBlockPolicies.Count } else { 0 }
                RecentLegacySignIns = $recentLegacySignIns
                PolicyNames = if ($legacyAuthBlockPolicies) { 
                    $legacyAuthBlockPolicies.DisplayName -join ', ' 
                } else { 
                    "None" 
                }
            }
            Recommendation = if ($status -eq "Fail") {
                "Block legacy authentication protocols immediately using Conditional Access. Legacy auth bypasses MFA and modern security controls."
            } elseif ($status -eq "Warning") {
                "Legacy auth is blocked but recent sign-ins detected. Investigate and remediate affected users/apps."
            } else {
                "Legacy authentication is properly blocked. Monitor sign-in logs for blocked attempts."
            }
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication"
            RemediationSteps = @(
                "1. Identify apps/users still using legacy authentication via Sign-in logs"
                "2. Notify users and provide modern authentication alternatives"
                "3. Create Conditional Access policy blocking legacy auth protocols"
                "4. Set policy to Report-only mode initially to assess impact"
                "5. Review blocked sign-ins for 1-2 weeks"
                "6. Enable policy to block legacy authentication"
                "7. Monitor Azure AD sign-in logs for blocked attempts"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Legacy Authentication Blocking"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess legacy authentication: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Verify Microsoft Graph permissions: Policy.Read.All, AuditLog.Read.All"
            DocumentationUrl = "https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication"
            RemediationSteps = @()
        }
    }
}
