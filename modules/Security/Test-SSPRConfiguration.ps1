<#
.SYNOPSIS
    Tests Self-Service Password Reset (SSPR) tenant configuration.

.DESCRIPTION
    Evaluates whether Self-Service Password Reset is enabled for users in the tenant
    based on Microsoft Entra authorization policy settings.

.PARAMETER Config
    Configuration object (reserved for future tuning).

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 1.0.0
    Created with assistance from GitHub Copilot
#>

function Test-SSPRConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing Self-Service Password Reset (SSPR) configuration..."

        $authorizationPolicy = if (Get-Command Invoke-MgGraphWithRetry -ErrorAction SilentlyContinue) {
            Invoke-MgGraphWithRetry -ScriptBlock {
                Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            } -OperationName "Retrieving authorization policy for SSPR assessment"
        }
        else {
            Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        }

        $ssprEnabled = [bool]$authorizationPolicy.AllowedToUseSspr

        $status = if ($ssprEnabled) { 'Pass' } else { 'Warning' }
        $severity = if ($ssprEnabled) { 'Low' } else { 'Medium' }

        $message = if ($ssprEnabled) {
            'Self-service password reset (SSPR) is enabled for users.'
        }
        else {
            'Self-service password reset (SSPR) is disabled for users.'
        }

        return [PSCustomObject]@{
            CheckName = 'Self-Service Password Reset (SSPR)'
            Category = 'Security'
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                SsprEnabled = $ssprEnabled
                EvidenceSource = 'authorizationPolicy.AllowedToUseSspr'
            }
            Recommendation = if ($ssprEnabled) {
                'Keep SSPR enabled and ensure strong authentication methods and user notifications are configured.'
            }
            else {
                'Enable SSPR for users and require strong authentication methods for secure account recovery.'
            }
            DocumentationUrl = 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks'
            RemediationSteps = @(
                '1. Navigate to Entra admin center > Protection > Password reset'
                '2. Set Self service password reset enabled to All (or selected pilot groups)'
                '3. Configure authentication methods and registration requirements'
                '4. Enable notifications for password resets'
                '5. Monitor sign-ins and audit logs for reset-related anomalies'
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = 'Self-Service Password Reset (SSPR)'
            Category = 'Security'
            Status = 'Info'
            Severity = 'Info'
            Message = "Unable to assess Self-Service Password Reset configuration: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = 'Verify Microsoft Graph permissions to read authorization policy settings.'
            DocumentationUrl = 'https://learn.microsoft.com/entra/identity/authentication/howto-sspr-deployment'
            RemediationSteps = @()
        }
    }
}
