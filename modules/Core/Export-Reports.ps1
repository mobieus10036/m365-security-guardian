<#
.SYNOPSIS
    Report export module for M365 Security Guardian.

.DESCRIPTION
    This module provides functions for exporting assessment results to various formats
    including JSON, CSV, and HTML. The HTML export includes rich visualizations of
    security findings, tenant security score, and baseline comparisons.

.NOTES
    Module: Export-Reports
    Author: M365 Security Guardian Team
    Version: 1.0.0
#>

#region Helper Functions

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        HTML-encodes a string to prevent XSS attacks.
    
    .PARAMETER Text
        The text to encode.
    
    .OUTPUTS
        HTML-encoded string safe for inclusion in HTML output.
    #>
    param([string]$Text)
    
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Protect-ReportFiles {
    <#
    .SYNOPSIS
        Restricts file system permissions on report files to the current user only.
    
    .DESCRIPTION
        Removes inherited ACLs and grants FullControl only to the current user and
        local Administrators. This prevents other users on the machine from reading
        security assessment reports that may contain sensitive tenant information
        such as user principal names, security configurations, and vulnerability details.
    
    .PARAMETER Path
        The path to a file or directory to protect.
    
    .PARAMETER Recurse
        If set, also protects all files within the directory.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    try {
        if (-not (Test-Path $Path)) { return }

        $items = @($Path)
        if ($Recurse -and (Test-Path $Path -PathType Container)) {
            $items += Get-ChildItem -Path $Path -File -Recurse | Select-Object -ExpandProperty FullName
        }

        foreach ($item in $items) {
            $acl = Get-Acl -Path $item
            # Disable inheritance and remove inherited rules
            $acl.SetAccessRuleProtection($true, $false)
            # Remove all existing access rules
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
            # Grant current user FullControl
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $currentUser, 'FullControl', 'Allow'
            )
            $acl.AddAccessRule($userRule)
            # Grant BUILTIN\Administrators FullControl
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'Allow'
            )
            $acl.AddAccessRule($adminRule)
            try {
                Set-Acl -Path $item -AclObject $acl -ErrorAction Stop
            }
            catch {
                # Silently continue if we don't have SeSecurityPrivilege
                Write-Verbose "Could not set ACL on ${item}: $($_.Exception.Message)"
            }
        }
        Write-Verbose "Report file permissions restricted to current user and Administrators"
    }
    catch {
        Write-Warning "Could not restrict report file permissions: $_"
    }
}

#endregion

#region JSON Export Functions

function Export-JsonReport {
    <#
    .SYNOPSIS
        Exports assessment results to JSON format.
    
    .PARAMETER Results
        The assessment results array.
    
    .PARAMETER OutputPath
        The path for the output file (without extension).
    
    .PARAMETER TenantInfo
        Tenant information object.
    
    .PARAMETER SecurityScore
        Security score object (optional).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        $TenantInfo,
        
        [Parameter(Mandatory = $false)]
        $SecurityScore
    )
    
    $jsonPath = "$OutputPath.json"
    
    $exportData = @{
        AssessmentDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TenantId = if ($TenantInfo) { $TenantInfo.Id } else { (Get-MgContext).TenantId }
        TenantName = if ($TenantInfo) { $TenantInfo.DisplayName } else { "Unknown" }
        SecurityScore = if ($SecurityScore) {
            @{
                OverallScore = $SecurityScore.OverallScore
                LetterGrade = $SecurityScore.LetterGrade
                GradeDescription = $SecurityScore.GradeDescription
                PotentialScore = $SecurityScore.PotentialScore
                CategoryBreakdown = $SecurityScore.CategoryBreakdown
                TopPriorities = $SecurityScore.TopPriorities
                QuickWins = $SecurityScore.QuickWins
                Summary = $SecurityScore.Summary
            }
        } else { $null }
        Findings = $Results
    }
    
    $exportData | ConvertTo-Json -Depth 15 | Out-File $jsonPath -Encoding UTF8
    
    return $jsonPath
}

function Export-SecurityScoreJson {
    <#
    .SYNOPSIS
        Exports security score details to a separate JSON file.
    
    .PARAMETER SecurityScore
        The security score object.
    
    .PARAMETER OutputPath
        The base path for the output file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $SecurityScore,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $scorePath = "${OutputPath}_SecurityScore.json"
    $SecurityScore | ConvertTo-Json -Depth 10 | Out-File $scorePath -Encoding UTF8
    
    return $scorePath
}

#endregion

#region CSV Export Functions

function Export-CsvReport {
    <#
    .SYNOPSIS
        Exports main assessment results to CSV format.
    
    .PARAMETER Results
        The assessment results array.
    
    .PARAMETER OutputPath
        The path for the output file (without extension).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $csvPath = "$OutputPath.csv"
    
    $Results | Select-Object CheckName, Category, Status, Severity, Message, Recommendation | 
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    return $csvPath
}

function Export-DetailedCsvReports {
    <#
    .SYNOPSIS
        Exports detailed CSV reports for specific finding types.
    
    .DESCRIPTION
        Creates separate CSV files for non-compliant mailboxes, inactive users,
        domain authentication, privileged accounts, CA policies, users without MFA,
        risky applications, and secure score actions.
    
    .PARAMETER Results
        The assessment results array.
    
    .PARAMETER OutputPath
        The base path for output files.
    
    .OUTPUTS
        Hashtable containing paths and counts for each exported file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    $exports = @{}
    
    # Non-compliant mailboxes
    $mailboxAuditResult = $Results | Where-Object { $_.CheckName -eq "Mailbox Auditing" -and $_.NonCompliantMailboxes }
    if ($mailboxAuditResult -and $mailboxAuditResult.NonCompliantMailboxes.Count -gt 0) {
        $path = "${OutputPath}_NonCompliantMailboxes.csv"
        $mailboxAuditResult.NonCompliantMailboxes | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['NonCompliantMailboxes'] = @{ Path = $path; Count = $mailboxAuditResult.NonCompliantMailboxes.Count }
    }
    
    # Inactive mailboxes
    $licenseOptResult = $Results | Where-Object { $_.CheckName -eq "License Optimization" -and $_.InactiveMailboxes }
    if ($licenseOptResult -and $licenseOptResult.InactiveMailboxes.Count -gt 0) {
        $path = "${OutputPath}_InactiveMailboxes.csv"
        $licenseOptResult.InactiveMailboxes | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['InactiveMailboxes'] = @{ Path = $path; Count = $licenseOptResult.InactiveMailboxes.Count }
    }
    
    # Domain email authentication
    $emailAuthResult = $Results | Where-Object { $_.CheckName -eq "Email Authentication (SPF/DKIM/DMARC)" -and $_.DomainDetails }
    if ($emailAuthResult -and $emailAuthResult.DomainDetails.Count -gt 0) {
        $path = "${OutputPath}_DomainEmailAuth.csv"
        $emailAuthResult.DomainDetails | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['DomainEmailAuth'] = @{ Path = $path; Count = $emailAuthResult.DomainDetails.Count }
    }
    
    # Privileged accounts
    $privAccountResult = $Results | Where-Object { $_.CheckName -eq "Privileged Account Security" -and $_.PrivilegedAccounts }
    if ($privAccountResult -and $privAccountResult.PrivilegedAccounts.Count -gt 0) {
        $path = "${OutputPath}_PrivilegedAccounts.csv"
        $privAccountResult.PrivilegedAccounts | Select-Object `
            UserPrincipalName, DisplayName, RiskLevel, RiskScore, HighestRiskRole, Roles, RoleCount,
            @{Name='HasMFA';Expression={if($_.HasMFA){'Yes'}else{'No'}}},
            LastSignIn, LastSignInDaysAgo,
            @{Name='IsStale';Expression={if($_.IsStale){'Yes'}else{'No'}}},
            AccountType, RiskFactors, RiskFactorCount | 
            Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['PrivilegedAccounts'] = @{ Path = $path; Count = $privAccountResult.PrivilegedAccounts.Count }
    }
    
    # Conditional Access policies
    $caResult = $Results | Where-Object { $_.CheckName -eq "Conditional Access Policies" -and $_.EnabledPolicies }
    if ($caResult -and $caResult.EnabledPolicies.Count -gt 0) {
        $path = "${OutputPath}_ConditionalAccessPolicies.csv"
        $caResult.EnabledPolicies | Select-Object DisplayName, State, Id | 
            Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['ConditionalAccessPolicies'] = @{ Path = $path; Count = $caResult.EnabledPolicies.Count }
    }
    
    # Conditional Access policy findings
    if ($caResult -and $caResult.PolicyFindings -and $caResult.PolicyFindings.Count -gt 0) {
        $path = "${OutputPath}_ConditionalAccessPolicyFindings.csv"
        $flattened = @()
        foreach ($pf in $caResult.PolicyFindings) {
            $riskMessages = ""
            $riskSeverities = ""
            $oppMessages = ""
            $oppSeverities = ""
            if ($pf.Risks -and $pf.Risks.Count -gt 0) {
                $riskMessages = ($pf.Risks | ForEach-Object { $_.Message }) -join '; '
                $riskSeverities = ($pf.Risks | ForEach-Object { $_.Severity }) -join '; '
            }
            if ($pf.Opportunities -and $pf.Opportunities.Count -gt 0) {
                $oppMessages = ($pf.Opportunities | ForEach-Object { $_.Message }) -join '; '
                $oppSeverities = ($pf.Opportunities | ForEach-Object { $_.Severity }) -join '; '
            }
            $flattened += [PSCustomObject]@{
                DisplayName = $pf.DisplayName
                State = $pf.State
                Id = $pf.Id
                RiskMessages = $riskMessages
                RiskSeverities = $riskSeverities
                OpportunityMessages = $oppMessages
                OpportunitySeverities = $oppSeverities
            }
        }
        $flattened | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['ConditionalAccessPolicyFindings'] = @{ Path = $path; Count = $flattened.Count }
    }
    
    # Users without MFA
    $mfaResult = $Results | Where-Object { $_.CheckName -eq "MFA Enforcement" -and $_.UsersWithoutMFA }
    if ($mfaResult -and $mfaResult.UsersWithoutMFA.Count -gt 0) {
        $path = "${OutputPath}_UsersWithoutMFA.csv"
        $mfaResult.UsersWithoutMFA | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['UsersWithoutMFA'] = @{ Path = $path; Count = $mfaResult.UsersWithoutMFA.Count }
    }
    
    # Risky applications
    $appResult = $Results | Where-Object { $_.CheckName -eq "Application Permission Audit" -and $_.RiskyApps }
    if ($appResult -and $appResult.RiskyApps.Count -gt 0) {
        $path = "${OutputPath}_RiskyApplications.csv"
        $appResult.RiskyApps | Select-Object DisplayName, AppId, Type, 
            @{Name='RiskReasons';Expression={$_.RiskReasons -join '; '}}, 
            @{Name='HighRiskPermissions';Expression={$_.HighRiskPermissions -join '; '}}, 
            LastSignIn | 
            Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['RiskyApplications'] = @{ Path = $path; Count = $appResult.RiskyApps.Count }
    }
    
    # Secure Score actions
    $secureScoreResult = $Results | Where-Object { $_.CheckName -eq "Microsoft Secure Score" -and $_.TopActions }
    if ($secureScoreResult -and $secureScoreResult.TopActions.Count -gt 0) {
        $path = "${OutputPath}_SecureScoreActions.csv"
        $secureScoreResult.TopActions | Select-Object Title, Category, ScoreInPercentage, ImplementationStatus | 
            Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $exports['SecureScoreActions'] = @{ Path = $path; Count = $secureScoreResult.TopActions.Count }
    }
    
    return $exports
}

#endregion

#region HTML Finding Card Builders

function Build-ConditionalAccessFindingHtml {
    <#
    .SYNOPSIS
        Builds HTML content for Conditional Access findings.
    #>
    param([object]$Result)
    
    $html = "<strong>$($Result.Details.EnabledPolicies) enabled policies analyzed.</strong>"
    
    if ($null -ne $Result.ConditionalAccessScore) {
        $html += " CA Posture Score: <strong>$($Result.ConditionalAccessScore)%</strong> of policies have no flagged risks."
    }
    
    if ($Result.Findings -and $Result.Findings.Count -gt 0) {
        $criticalCount = ($Result.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount = ($Result.Findings | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount = ($Result.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        
        $html += "<br><br><div style='background: #fdf6ec; border-left: 4px solid #ffb900; padding: 12px; margin: 10px 0; border-radius: 4px;'>"
        $html += "<strong style='font-size: 14px;'>⚠ $($Result.Findings.Count) Security Gaps Identified</strong>"
        if ($criticalCount -gt 0 -or $highCount -gt 0) {
            $html += "<span style='margin-left: 15px;'>"
            if ($criticalCount -gt 0) { $html += "<span style='color: #a4262c; font-weight: 600;'>$criticalCount Critical</span> " }
            if ($highCount -gt 0) { $html += "<span style='color: #d13438; font-weight: 600;'>$highCount High</span> " }
            if ($mediumCount -gt 0) { $html += "<span style='color: #8a6b0f; font-weight: 600;'>$mediumCount Medium</span>" }
            $html += "</span>"
        }
        $html += "</div>"
        
        # Issues table
        $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
        $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300); width: 90px;'>Severity</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Security Gap</td></tr>"
        
        $severityOrder = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }
        $sortedFindings = $Result.Findings | Sort-Object { $severityOrder[$_.Severity] }
        
        foreach ($finding in $sortedFindings) {
            $findingMsgSafe = ConvertTo-HtmlSafe $finding.Message
            $findingSeveritySafe = ConvertTo-HtmlSafe $finding.Severity
            $severityColor = switch ($finding.Severity) {
                'Critical' { '#a4262c' }
                'High' { '#d13438' }
                'Medium' { '#8a6b0f' }
                'Low' { '#0078d4' }
                default { 'var(--gray-700)' }
            }
            $severityBg = switch ($finding.Severity) {
                'Critical' { '#fde7e9' }
                'High' { '#fed9cc' }
                'Medium' { '#fff4ce' }
                'Low' { '#deecf9' }
                default { 'var(--gray-100)' }
            }
            $html += "<tr>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); background: $severityBg; color: $severityColor; font-weight: 600; text-align: center;'>$findingSeveritySafe</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$findingMsgSafe</td>"
            $html += "</tr>"
        }
        $html += "</table>"
    }
    
    return $html
}

function Build-DomainEmailAuthHtml {
    <#
    .SYNOPSIS
        Builds HTML table for domain email authentication details.
    #>
    param([object]$Result)
    
    $html = "<br><br><strong>Domain Email Authentication Details:</strong><br>"
    $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
    $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Domain</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>SPF</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>DKIM</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>DMARC</td></tr>"
    
    $statusDot = @{
        Green = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#107c10;'></span>"
        Amber = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#ffb900;'></span>"
        Red   = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#d13438;'></span>"
        Gray  = "<span style='display:inline-block;width:10px;height:10px;border-radius:50%;background:#8a8886;'></span>"
    }
    
    foreach ($domain in $Result.DomainDetails) {
        $domainSafe = ConvertTo-HtmlSafe $domain.Domain
        $spfSafe = ConvertTo-HtmlSafe $domain.SPF
        $dkimSafe = ConvertTo-HtmlSafe $domain.DKIM
        $dmarcSafe = ConvertTo-HtmlSafe $domain.DMARC
        
        $spfIcon = switch -Regex ($domain.SPF) {
            "^Valid" { $statusDot.Green }
            "^Missing" { $statusDot.Red }
            "^Invalid" { $statusDot.Amber }
            default { $statusDot.Gray }
        }
        $dkimIcon = if ($domain.DKIM -eq "Enabled") { $statusDot.Green } else { $statusDot.Red }
        $dmarcIcon = switch -Regex ($domain.DMARC) {
            "^Valid" { $statusDot.Green }
            "^Missing" { $statusDot.Red }
            "^Weak" { $statusDot.Amber }
            default { $statusDot.Gray }
        }
        
        $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$domainSafe</code></td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$spfIcon $spfSafe</td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$dkimIcon $dkimSafe</td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$dmarcIcon $dmarcSafe</td></tr>"
    }
    $html += "</table>"
    
    return $html
}

function Build-PrivilegedAccountsHtml {
    <#
    .SYNOPSIS
        Builds HTML table for privileged accounts.
    #>
    param([object]$Result)
    
    $html = "<br><br><strong>Privileged Accounts ($($Result.PrivilegedAccounts.Count)):</strong><br>"
    $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
    $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>User Principal Name</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Roles</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>MFA Status</td></tr>"
    
    foreach ($account in $Result.PrivilegedAccounts) {
        $accountUpnSafe = ConvertTo-HtmlSafe $account.UserPrincipalName
        $mfaIcon = if ($account.HasMFA) { "✅ Enabled" } else { "❌ Not Enabled" }
        $mfaColor = if ($account.HasMFA) { 'var(--success-color)' } else { 'var(--danger-color)' }
        $rolesSafe = ($account.Roles | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
        $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$accountUpnSafe</code></td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); font-size: 12px;'>$rolesSafe</td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $mfaColor; font-weight: 600;'>$mfaIcon</td></tr>"
    }
    $html += "</table>"
    
    return $html
}

function Build-RiskyAppsHtml {
    <#
    .SYNOPSIS
        Builds HTML table for risky applications.
    #>
    param([object]$Result)
    
    $html = "<br><br><strong>Risky Applications ($($Result.RiskyApps.Count)):</strong><br>"
    $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
    $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Application</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Type</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Risk Reasons</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>High-Risk Permissions</td></tr>"
    
    $displayCount = [Math]::Min(15, $Result.RiskyApps.Count)
    for ($i = 0; $i -lt $displayCount; $i++) {
        $app = $Result.RiskyApps[$i]
        $appNameSafe = ConvertTo-HtmlSafe $app.DisplayName
        $appTypeSafe = ConvertTo-HtmlSafe $app.Type
        $riskReasonsSafe = ($app.RiskReasons | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join '<br>'
        $permsSafe = ($app.HighRiskPermissions | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', '
        if (-not $permsSafe) { $permsSafe = '-' }
        $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'><code>$appNameSafe</code></td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$appTypeSafe</td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: var(--danger-color);'>$riskReasonsSafe</td>"
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); font-size: 11px;'>$permsSafe</td></tr>"
    }
    if ($Result.RiskyApps.Count -gt 15) {
        $html += "<tr><td colspan='4' style='padding: 8px; border: 1px solid var(--gray-300); font-style: italic; text-align: center;'>...and $($Result.RiskyApps.Count - 15) more apps (see CSV export)</td></tr>"
    }
    $html += "</table>"
    
    return $html
}

function Build-SecureScoreHtml {
    <#
    .SYNOPSIS
        Builds HTML content for Microsoft Secure Score details.
    #>
    param([object]$Result)
    
    $scorePercent = [math]::Round(($Result.SecureScore / $Result.MaxScore) * 100, 1)
    $scoreColor = if ($scorePercent -ge 80) { 'var(--success-color)' } elseif ($scorePercent -ge 60) { 'var(--warning-color)' } else { 'var(--danger-color)' }
    
    $html = "<br><br><div style='text-align: center; padding: 20px; background: var(--gray-100); border-radius: 8px;'>"
    $html += "<div style='font-size: 48px; font-weight: 700; color: $scoreColor;'>$($Result.SecureScore) / $($Result.MaxScore)</div>"
    $html += "<div style='font-size: 18px; color: var(--gray-700); margin-top: 4px;'>Secure Score ($scorePercent%)</div>"
    $html += "</div>"
    
    # Category breakdown
    if ($Result.CategoryBreakdown -and $Result.CategoryBreakdown.Count -gt 0) {
        $html += "<br><strong>Score by Category:</strong><br>"
        $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
        $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Category</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Score</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Max</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>%</td></tr>"
        foreach ($cat in $Result.CategoryBreakdown) {
            $catNameSafe = ConvertTo-HtmlSafe $cat.Category
            $catPct = if ($cat.MaxScore -gt 0) { [math]::Round(($cat.Score / $cat.MaxScore) * 100, 0) } else { 0 }
            $catColor = if ($catPct -ge 80) { 'var(--success-color)' } elseif ($catPct -ge 60) { 'var(--warning-color)' } else { 'var(--danger-color)' }
            $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$catNameSafe</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$($cat.Score)</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$($cat.MaxScore)</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: $catColor; font-weight: 600;'>$catPct%</td></tr>"
        }
        $html += "</table>"
    }
    
    # Top improvement actions
    if ($Result.TopActions -and $Result.TopActions.Count -gt 0) {
        $html += "<br><strong>Top Improvement Actions ($($Result.TopActions.Count)):</strong><br>"
        $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
        $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Action</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Category</td><td style='padding: 8px; border: 1px solid var(--gray-300);'>Points</td></tr>"
        foreach ($action in $Result.TopActions) {
            $actionTitleSafe = ConvertTo-HtmlSafe $action.Title
            $actionCatSafe = ConvertTo-HtmlSafe $action.Category
            $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>$actionTitleSafe</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$actionCatSafe</td>"
            $html += "<td style='padding: 8px; border: 1px solid var(--gray-300); color: var(--info-color); font-weight: 600;'>+$($action.ScoreInPercentage)</td></tr>"
        }
        $html += "</table>"
    }
    
    return $html
}

function Build-ListedItemsHtml {
    <#
    .SYNOPSIS
        Builds HTML list for items like mailboxes, policies, etc.
    
    .PARAMETER Items
        Array of items to display.
    
    .PARAMETER Title
        Section title.
    
    .PARAMETER ItemFormatter
        ScriptBlock to format each item.
    
    .PARAMETER MaxDisplay
        Maximum items to display before truncating.
    #>
    param(
        [array]$Items,
        [string]$Title,
        [scriptblock]$ItemFormatter,
        [int]$MaxDisplay = 10
    )
    
    $html = "<br><br><strong>$Title ($($Items.Count)):</strong><br>"
    $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
    $html += "<tr style='background: var(--gray-100); font-weight: 600;'><td style='padding: 8px; border: 1px solid var(--gray-300);'>Item</td></tr>"

    $displayCount = [Math]::Min($MaxDisplay, $Items.Count)
    for ($i = 0; $i -lt $displayCount; $i++) {
        $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300);'>" + (& $ItemFormatter $Items[$i]) + "</td></tr>"
    }

    if ($Items.Count -gt $MaxDisplay) {
        $html += "<tr><td style='padding: 8px; border: 1px solid var(--gray-300); font-style: italic; text-align: center;'>...and $($Items.Count - $MaxDisplay) more (see CSV export)</td></tr>"
    }

    $html += "</table>"
    return $html
}

#endregion

#region Security Score Dashboard Builder

function Build-SecurityScoreDashboardHtml {
    <#
    .SYNOPSIS
        Builds the security score dashboard HTML section.
    
    .PARAMETER SecurityScore
        The security score object.
    #>
    param([object]$SecurityScore)
    
    if (-not $SecurityScore) { return "" }
    
    $score = $SecurityScore
    $gradeClass = switch ($score.LetterGrade) {
        "A" { "grade-a" }
        "B" { "grade-b" }
        "C" { "grade-c" }
        "D" { "grade-d" }
        default { "grade-f" }
    }
    
    # Build category breakdown
    $categoryHtml = ""
    foreach ($cat in $score.CategoryBreakdown) {
        $catGradeClass = switch ($cat.Grade) {
            "A" { "grade-a" }
            "B" { "grade-b" }
            "C" { "grade-c" }
            "D" { "grade-d" }
            default { "grade-f" }
        }
        $categoryHtml += @"
        <div class="score-category">
            <div class="score-category-name">$(ConvertTo-HtmlSafe $cat.Category)</div>
            <div class="score-category-bar">
                <div class="score-category-fill $catGradeClass" style="width: $($cat.Score)%"></div>
            </div>
            <div class="score-category-value">$($cat.Score)%</div>
        </div>
"@
    }
    
    # Build priorities list
    $prioritiesHtml = ""
    if ($score.TopPriorities.Count -gt 0) {
        $prioritiesHtml = "<div class='priorities-section'><h4>🎯 Top Priorities</h4><ul>"
        foreach ($priority in $score.TopPriorities) {
            $prioritiesHtml += "<li><span class='priority-severity $($priority.Severity.ToLower())'>$($priority.Severity)</span> $(ConvertTo-HtmlSafe $priority.CheckName) <span class='priority-gain'>+$($priority.PotentialGain) pts</span></li>"
        }
        $prioritiesHtml += "</ul></div>"
    }
    
    # Build quick wins list
    $quickWinsHtml = ""
    if ($score.QuickWins.Count -gt 0) {
        $quickWinsHtml = "<div class='quickwins-section'><h4>⚡ Quick Wins</h4><ul>"
        foreach ($win in $score.QuickWins) {
            $quickWinsHtml += "<li>$(ConvertTo-HtmlSafe $win.CheckName) <span class='priority-gain'>+$($win.PotentialGain) pts</span></li>"
        }
        $quickWinsHtml += "</ul></div>"
    }
    
    return @"
    <div class="security-score-dashboard">
        <h2 class="summary-title">🛡️ Tenant Security Score</h2>
        <div class="score-main-display">
            <div class="score-circle $gradeClass">
                <div class="score-value">$($score.OverallScore)%</div>
                <div class="score-grade">Grade: $($score.LetterGrade)</div>
            </div>
            <div class="score-details">
                <div class="score-description">$(ConvertTo-HtmlSafe $score.GradeDescription)</div>
                <div class="score-potential">
                    <span class="potential-label">Potential Score:</span>
                    <span class="potential-value">$($score.PotentialScore)%</span>
                    <span class="potential-gain">(+$($score.PotentialImprovement) pts available)</span>
                </div>
            </div>
        </div>
        <div class="score-categories">
            <h3>Category Breakdown</h3>
            $categoryHtml
        </div>
        <div class="score-actions-grid">
            $prioritiesHtml
            $quickWinsHtml
        </div>
    </div>
"@
}

#endregion

#region Baseline Comparison Dashboard Builder

function Build-BaselineComparisonHtml {
    <#
    .SYNOPSIS
        Builds the baseline comparison HTML section.
    
    .PARAMETER BaselineComparison
        The baseline comparison object.
    #>
    param([object]$BaselineComparison)
    
    if (-not $BaselineComparison) { return "" }
    
    $comparison = $BaselineComparison
    
    # Determine trend styling
    $trendClass = switch ($comparison.OverallTrend) {
        "Improving" { "improving" }
        "Declining" { "declining" }
        default { "stable" }
    }
    $trendIcon = switch ($comparison.OverallTrend) {
        "Improving" { "📈" }
        "Declining" { "📉" }
        default { "➡️" }
    }
    
    # Format baseline date
    $baselineDate = if ($comparison.BaselineDate) {
        try { [datetime]::Parse($comparison.BaselineDate).ToString("yyyy-MM-dd HH:mm") } catch { $comparison.BaselineDate }
    } else { "Unknown" }
    $baselineName = if ($comparison.BaselineName) { ConvertTo-HtmlSafe $comparison.BaselineName } else { "Baseline" }
    
    # Score delta formatting
    $scoreDelta = if ($comparison.SecurityScoreComparison) { $comparison.SecurityScoreComparison.Delta } else { 0 }
    $scoreDeltaClass = if ($scoreDelta -gt 0) { "positive" } elseif ($scoreDelta -lt 0) { "negative" } else { "neutral" }
    $scoreDeltaSign = if ($scoreDelta -gt 0) { "+" } else { "" }
    
    $currentScore = if ($comparison.SecurityScoreComparison -and $null -ne $comparison.SecurityScoreComparison.CurrentScore) { "$($comparison.SecurityScoreComparison.CurrentScore)%" } else { "N/A" }
    
    # CIS compliance deltas
    $cisL1Delta = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level1) { $comparison.CISComplianceComparison.Level1.Delta } else { 0 }
    $cisL2Delta = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level2) { $comparison.CISComplianceComparison.Level2.Delta } else { 0 }
    $cisL1DeltaClass = if ($cisL1Delta -gt 0) { "positive" } elseif ($cisL1Delta -lt 0) { "negative" } else { "neutral" }
    $cisL2DeltaClass = if ($cisL2Delta -gt 0) { "positive" } elseif ($cisL2Delta -lt 0) { "negative" } else { "neutral" }
    $cisL1DeltaSign = if ($cisL1Delta -gt 0) { "+" } else { "" }
    $cisL2DeltaSign = if ($cisL2Delta -gt 0) { "+" } else { "" }
    
    $currentL1 = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level1 -and $null -ne $comparison.CISComplianceComparison.Level1.Current) { "$($comparison.CISComplianceComparison.Level1.Current)%" } else { "N/A" }
    $currentL2 = if ($comparison.CISComplianceComparison -and $comparison.CISComplianceComparison.Level2 -and $null -ne $comparison.CISComplianceComparison.Level2.Current) { "$($comparison.CISComplianceComparison.Level2.Current)%" } else { "N/A" }
    
    # Build improvements list
    $improvementsHtml = ""
    if ($comparison.Improvements -and $comparison.Improvements.Count -gt 0) {
        $improvementsHtml = "<ul class='baseline-change-list'>"
        foreach ($imp in $comparison.Improvements) {
            $checkNameSafe = ConvertTo-HtmlSafe $imp.CheckName
            $improvementsHtml += @"
            <li class='baseline-change-item'>
                <span class='baseline-change-name'>$checkNameSafe</span>
                <span class='baseline-change-status'>
                    <span style='color: #d13438;'>$($imp.PreviousStatus)</span>
                    →
                    <span style='color: #107c10;'>$($imp.CurrentStatus)</span>
                </span>
            </li>
"@
        }
        $improvementsHtml += "</ul>"
    } else {
        $improvementsHtml = "<div class='baseline-empty'>No improvements detected</div>"
    }
    
    # Build regressions list
    $regressionsHtml = ""
    if ($comparison.Regressions -and $comparison.Regressions.Count -gt 0) {
        $regressionsHtml = "<ul class='baseline-change-list'>"
        foreach ($reg in $comparison.Regressions) {
            $checkNameSafe = ConvertTo-HtmlSafe $reg.CheckName
            $regressionsHtml += @"
            <li class='baseline-change-item'>
                <span class='baseline-change-name'>$checkNameSafe</span>
                <span class='baseline-change-status'>
                    <span style='color: #107c10;'>$($reg.PreviousStatus)</span>
                    →
                    <span style='color: #d13438;'>$($reg.CurrentStatus)</span>
                </span>
            </li>
"@
        }
        $regressionsHtml += "</ul>"
    } else {
        $regressionsHtml = "<div class='baseline-empty'>No regressions detected</div>"
    }
    
    # --- Build Tenant Changes HTML ---
    $tenantChangesHtml = ""
    $tc = $comparison.TenantChanges
    if ($tc -and $tc.HasChanges) {
        # Metric cards row
        $metricCards = ""
        
        if ($tc.UserMetrics) {
            $um = $tc.UserMetrics
            $userDeltaClass = if ($um.TotalUsersDelta -gt 0) { "neutral" } elseif ($um.TotalUsersDelta -lt 0) { "negative" } else { "neutral" }
            $userDeltaSign  = if ($um.TotalUsersDelta -gt 0) { "+" } else { "" }
            $mfaPctClass    = if ($um.MFAComplianceDelta -gt 0) { "positive" } elseif ($um.MFAComplianceDelta -lt 0) { "negative" } else { "neutral" }
            $mfaPctSign     = if ($um.MFAComplianceDelta -gt 0) { "+" } else { "" }
            
            $metricCards += @"
            <div class="baseline-score-card">
                <div class="baseline-score-label">Total Users</div>
                <div class="baseline-score-value">$($um.CurrentTotalUsers)</div>
                <div class="baseline-score-delta $userDeltaClass">$userDeltaSign$($um.TotalUsersDelta) since baseline</div>
            </div>
            <div class="baseline-score-card">
                <div class="baseline-score-label">MFA Adoption</div>
                <div class="baseline-score-value">$($um.CurrentMFACompliance)%</div>
                <div class="baseline-score-delta $mfaPctClass">$mfaPctSign$($um.MFAComplianceDelta)% since baseline</div>
            </div>
"@
        }
        
        if ($tc.PrivilegedAccess) {
            $pa = $tc.PrivilegedAccess
            $privDeltaClass = if ($pa.TotalPrivilegedDelta -gt 0) { "negative" } elseif ($pa.TotalPrivilegedDelta -lt 0) { "positive" } else { "neutral" }
            $privDeltaSign  = if ($pa.TotalPrivilegedDelta -gt 0) { "+" } else { "" }
            $gaDeltaClass   = if ($pa.GlobalAdminDelta -gt 0) { "negative" } elseif ($pa.GlobalAdminDelta -lt 0) { "positive" } else { "neutral" }
            $gaDeltaSign    = if ($pa.GlobalAdminDelta -gt 0) { "+" } else { "" }
            
            $metricCards += @"
            <div class="baseline-score-card">
                <div class="baseline-score-label">Privileged Accounts</div>
                <div class="baseline-score-value">$($pa.CurrentTotalPrivileged)</div>
                <div class="baseline-score-delta $privDeltaClass">$privDeltaSign$($pa.TotalPrivilegedDelta) since baseline</div>
            </div>
            <div class="baseline-score-card">
                <div class="baseline-score-label">Global Admins</div>
                <div class="baseline-score-value">$($pa.CurrentGlobalAdmins)</div>
                <div class="baseline-score-delta $gaDeltaClass">$gaDeltaSign$($pa.GlobalAdminDelta) since baseline</div>
            </div>
"@
        }
        
        # Detail cards (MFA changes + Privileged access changes)
        $detailCards = ""
        
        # MFA change detail card
        if ($tc.UserMetrics) {
            $um = $tc.UserMetrics
            $mfaRows = ""
            $hasMFADetails = $false
            
            if ($um.UsersGainedMFA -and $um.UsersGainedMFA.Count -gt 0) {
                $hasMFADetails = $true
                foreach ($upn in $um.UsersGainedMFA) {
                    $safeName = ConvertTo-HtmlSafe $upn
                    $mfaRows += "<tr><td>$safeName</td><td class='tenant-change-gained'>Gained MFA</td></tr>`n"
                }
            }
            if ($um.UsersLostMFA -and $um.UsersLostMFA.Count -gt 0) {
                $hasMFADetails = $true
                foreach ($upn in $um.UsersLostMFA) {
                    $safeName = ConvertTo-HtmlSafe $upn
                    $mfaRows += "<tr><td>$safeName</td><td class='tenant-change-lost'>Lost MFA / New without MFA</td></tr>`n"
                }
            }
            
            if ($hasMFADetails) {
                $gainedCount = if ($um.UsersGainedMFA) { $um.UsersGainedMFA.Count } else { 0 }
                $lostCount   = if ($um.UsersLostMFA) { $um.UsersLostMFA.Count } else { 0 }
                $detailCards += @"
                <div class="baseline-change-card">
                    <div class="baseline-change-header tenant-mfa-header">
                        🛡️ MFA Changes ($gainedCount gained, $lostCount lost)
                    </div>
                    <div class="tenant-change-table-wrap">
                        <table class="tenant-change-table">
                            <thead><tr><th>User</th><th>Change</th></tr></thead>
                            <tbody>$mfaRows</tbody>
                        </table>
                    </div>
                </div>
"@
            }
        }
        
        # Privileged access change detail card
        if ($tc.PrivilegedAccess) {
            $pa = $tc.PrivilegedAccess
            $privRows = ""
            $hasPrivDetails = $false
            
            if ($pa.NewPrivilegedAccounts -and $pa.NewPrivilegedAccounts.Count -gt 0) {
                $hasPrivDetails = $true
                foreach ($acct in $pa.NewPrivilegedAccounts) {
                    $safeName = ConvertTo-HtmlSafe $acct.DisplayName
                    $safeUPN  = ConvertTo-HtmlSafe $acct.UserPrincipalName
                    $safeRoles = ConvertTo-HtmlSafe $acct.Roles
                    $privRows += "<tr><td>$safeName<br><small>$safeUPN</small></td><td>$safeRoles</td><td class='tenant-change-lost'>New</td></tr>`n"
                }
            }
            if ($pa.RemovedPrivilegedAccounts -and $pa.RemovedPrivilegedAccounts.Count -gt 0) {
                $hasPrivDetails = $true
                foreach ($acct in $pa.RemovedPrivilegedAccounts) {
                    $safeName = ConvertTo-HtmlSafe $acct.DisplayName
                    $safeUPN  = ConvertTo-HtmlSafe $acct.UserPrincipalName
                    $safeRoles = ConvertTo-HtmlSafe $acct.Roles
                    $privRows += "<tr><td>$safeName<br><small>$safeUPN</small></td><td>$safeRoles</td><td class='tenant-change-gained'>Removed</td></tr>`n"
                }
            }
            
            if ($hasPrivDetails) {
                $newCount     = if ($pa.NewPrivilegedAccounts) { $pa.NewPrivilegedAccounts.Count } else { 0 }
                $removedCount = if ($pa.RemovedPrivilegedAccounts) { $pa.RemovedPrivilegedAccounts.Count } else { 0 }
                $detailCards += @"
                <div class="baseline-change-card">
                    <div class="baseline-change-header tenant-priv-header">
                        👤 Privileged Access Changes ($newCount new, $removedCount removed)
                    </div>
                    <div class="tenant-change-table-wrap">
                        <table class="tenant-change-table">
                            <thead><tr><th>Account</th><th>Roles</th><th>Change</th></tr></thead>
                            <tbody>$privRows</tbody>
                        </table>
                    </div>
                </div>
"@
            }
        }
        
        $tenantChangesHtml = @"
        <div class="tenant-changes-section">
            <h3 class="tenant-changes-title">🔄 Tenant Changes Since Baseline</h3>
            <div class="baseline-score-comparison">
                $metricCards
            </div>
            <div class="baseline-changes-grid">
                $detailCards
            </div>
        </div>
"@
    }
    
    return @"
    <div class="baseline-comparison-section">
        <div class="baseline-header">
            <div>
                <h2 class="baseline-title">📊 Baseline Comparison</h2>
                <div class="baseline-meta">Comparing to: <strong>$baselineName</strong> (saved $baselineDate)</div>
            </div>
            <div class="baseline-trend $trendClass">
                <span class="baseline-trend-icon">$trendIcon</span>
                <span>$($comparison.OverallTrend)</span>
            </div>
        </div>
        
        <div class="baseline-score-comparison">
            <div class="baseline-score-card">
                <div class="baseline-score-label">Security Score</div>
                <div class="baseline-score-value">$currentScore</div>
                <div class="baseline-score-delta $scoreDeltaClass">$scoreDeltaSign$scoreDelta pts vs baseline</div>
            </div>
            <div class="baseline-score-card">
                <div class="baseline-score-label">CIS Level 1</div>
                <div class="baseline-score-value">$currentL1</div>
                <div class="baseline-score-delta $cisL1DeltaClass">$cisL1DeltaSign$cisL1Delta% vs baseline</div>
            </div>
            <div class="baseline-score-card">
                <div class="baseline-score-label">CIS Level 2</div>
                <div class="baseline-score-value">$currentL2</div>
                <div class="baseline-score-delta $cisL2DeltaClass">$cisL2DeltaSign$cisL2Delta% vs baseline</div>
            </div>
            <div class="baseline-score-card">
                <div class="baseline-score-label">Checks Changed</div>
                <div class="baseline-score-value">$($comparison.Summary.TotalChanges)</div>
                <div class="baseline-score-delta neutral">of $($comparison.Summary.TotalChecksCompared) total</div>
            </div>
        </div>
        
        <div class="baseline-changes-grid">
            <div class="baseline-change-card">
                <div class="baseline-change-header improvements">
                    ✅ Improvements ($($comparison.Summary.TotalImprovements))
                </div>
                $improvementsHtml
            </div>
            <div class="baseline-change-card">
                <div class="baseline-change-header regressions">
                    ❌ Regressions ($($comparison.Summary.TotalRegressions))
                </div>
                $regressionsHtml
            </div>
        </div>
        
        $tenantChangesHtml
    </div>
"@
}

function Build-AttackChainsSectionHtml {
    <#
    .SYNOPSIS
        Builds the attack chains section HTML for the report.
    
    .PARAMETER AttackChains
        The attack chain analysis results object.
    #>
    param([object]$AttackChains)
    
    if (-not $AttackChains -or $AttackChains.EnabledChainCount -eq 0) { return "" }
    
    # Determine overall risk level styling
    $riskLevel = if ($AttackChains.CriticalChains -gt 0) { 'CRITICAL' }
                 elseif ($AttackChains.HighChains -gt 0) { 'HIGH' }
                 elseif ($AttackChains.EnabledChainCount -gt 0) { 'ELEVATED' }
                 else { 'LOW' }
    
    $riskClass = switch ($riskLevel) {
        'CRITICAL' { 'risk-critical' }
        'HIGH'     { 'risk-high' }
        'ELEVATED' { 'risk-elevated' }
        default    { 'risk-low' }
    }
    $riskIcon = switch ($riskLevel) {
        'CRITICAL' { '🔴' }
        'HIGH'     { '🟠' }
        'ELEVATED' { '🟡' }
        default    { '🟢' }
    }
    
    # Build attack chain cards
    $chainCardsHtml = ""
    foreach ($chain in $AttackChains.EnabledChains) {
        $severityClass = switch ($chain.Severity) {
            'Critical' { 'severity-critical' }
            'High'     { 'severity-high' }
            'Medium'   { 'severity-medium' }
            default    { 'severity-low' }
        }
        $severityIcon = switch ($chain.Severity) {
            'Critical' { '🔴' }
            'High'     { '🟠' }
            'Medium'   { '🟡' }
            default    { '🟢' }
        }
        
        $chainNameSafe = ConvertTo-HtmlSafe $chain.Name
        $narrativeSafe = ConvertTo-HtmlSafe $chain.ExecutiveNarrative
        $tacticsHtml = ($chain.Tactics | ForEach-Object { "<span class='attack-tactic'>$_</span>" }) -join ' → '
        
        # MITRE techniques badges
        $mitreBadges = ($chain.MitreTechniques | ForEach-Object { "<span class='mitre-badge'>$_</span>" }) -join ' '
        
        # Kill chain phases
        $killChainHtml = ""
        if ($chain.KillChain) {
            $killChainHtml = "<div class='kill-chain-phases'>"
            $phaseOrder = @('initialAccess', 'execution', 'persistence', 'privilegeEscalation', 'defenseEvasion', 'collection', 'exfiltration', 'impact')
            foreach ($phase in $phaseOrder) {
                $phaseValue = $chain.KillChain.$phase
                if ($phaseValue) {
                    $phaseName = switch ($phase) {
                        'initialAccess' { 'Initial Access' }
                        'execution' { 'Execution' }
                        'persistence' { 'Persistence' }
                        'privilegeEscalation' { 'Privilege Escalation' }
                        'defenseEvasion' { 'Defense Evasion' }
                        'collection' { 'Collection' }
                        'exfiltration' { 'Exfiltration' }
                        'impact' { 'Impact' }
                        default { $phase }
                    }
                    $phaseValueSafe = ConvertTo-HtmlSafe $phaseValue
                    $killChainHtml += "<div class='kill-chain-phase'><strong>$($phaseName):</strong> $phaseValueSafe</div>"
                }
            }
            $killChainHtml += "</div>"
        }
        
        # Blast radius
        $blastRadiusHtml = ""
        if ($chain.BlastRadius) {
            $dataAtRisk = if ($chain.BlastRadius.dataAtRisk) { 
                ($chain.BlastRadius.dataAtRisk | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ', ' 
            } else { 'Unknown' }
            $usersAffected = if ($chain.BlastRadius.usersAffected) { ConvertTo-HtmlSafe $chain.BlastRadius.usersAffected } else { 'Unknown' }
            $blastRadiusHtml = @"
            <div class='blast-radius'>
                <span class='blast-label'>Blast Radius:</span>
                <span class='blast-data'>$dataAtRisk</span>
                <span class='blast-users'>($usersAffected)</span>
            </div>
"@
        }
        
        $chainCardsHtml += @"
        <div class='attack-chain-card $severityClass'>
            <div class='attack-chain-header'>
                <span class='attack-chain-severity'>$severityIcon $($chain.Severity)</span>
                <span class='attack-chain-id'>$($chain.ChainId)</span>
            </div>
            <h4 class='attack-chain-name'>$chainNameSafe</h4>
            <div class='attack-chain-tactics'>$tacticsHtml</div>
            <div class='attack-chain-mitre'>$mitreBadges</div>
            <div class='attack-chain-enablement'>
                <span class='enablement-label'>Enablement:</span>
                <span class='enablement-value'>$($chain.EnablementScore)%</span>
                <span class='fix-time'>Fix Time: $($chain.EstimatedFixTime)</span>
            </div>
            <div class='attack-chain-narrative'>$narrativeSafe</div>
            $killChainHtml
            $blastRadiusHtml
        </div>
"@
    }
    
    # Build remediation priorities
    $prioritiesHtml = ""
    if ($AttackChains.RemediationPriorities -and $AttackChains.RemediationPriorities.Count -gt 0) {
        $prioritiesHtml = "<div class='remediation-priorities'><h4>🔧 Top Remediation Priorities</h4><ul>"
        $topPriorities = $AttackChains.RemediationPriorities | Select-Object -First 5
        foreach ($priority in $topPriorities) {
            $prioritiesHtml += "<li><strong>Control $($priority.ControlId)</strong> - Breaks $($priority.ChainsAffected) attack chain(s)</li>"
        }
        $prioritiesHtml += "</ul></div>"
    }
    
    # Build MITRE matrix summary
    $mitreHtml = ""
    if ($AttackChains.MitreMatrix -and $AttackChains.MitreMatrix.TacticsExploitable) {
        $mitreHtml = "<div class='mitre-summary'><h4>📊 MITRE ATT&CK Coverage</h4>"
        $mitreHtml += "<p>$($AttackChains.MitreMatrix.TotalTactics) tactics and $($AttackChains.MitreMatrix.TotalTechniques) techniques exploitable</p>"
        $mitreHtml += "<div class='tactic-list'>"
        foreach ($tactic in $AttackChains.MitreMatrix.TacticsExploitable) {
            $tacticName = ConvertTo-HtmlSafe $tactic.Tactic
            $mitreHtml += "<span class='tactic-badge'>$tacticName ($($tactic.Chains.Count) chains)</span>"
        }
        $mitreHtml += "</div></div>"
    }
    
    return @"
    <div class='attack-chains-section'>
        <div class='attack-chains-header'>
            <h2 class='attack-chains-title'>⚔️ Attack Chain Analysis</h2>
            <div class='attack-risk-level $riskClass'>
                <span class='risk-icon'>$riskIcon</span>
                <span class='risk-text'>$riskLevel RISK</span>
            </div>
        </div>
        
        <div class='attack-chains-summary'>
            <div class='chains-stat'>
                <span class='stat-value'>$($AttackChains.EnabledChainCount)</span>
                <span class='stat-label'>Enabled Chains</span>
            </div>
            <div class='chains-stat'>
                <span class='stat-value'>$($AttackChains.CriticalChains)</span>
                <span class='stat-label'>Critical</span>
            </div>
            <div class='chains-stat'>
                <span class='stat-value'>$($AttackChains.HighChains)</span>
                <span class='stat-label'>High</span>
            </div>
            <div class='chains-stat'>
                <span class='stat-value'>$($AttackChains.TotalChainsAnalyzed)</span>
                <span class='stat-label'>Total Analyzed</span>
            </div>
        </div>
        
        $prioritiesHtml
        
        <div class='attack-chains-grid'>
            $chainCardsHtml
        </div>
        
        $mitreHtml
    </div>
"@
}

function Build-TrendsSectionHtml {
    <#
    .SYNOPSIS
        Builds the trend tracking section HTML for the report.
    
    .PARAMETER Trends
        The trend analysis results object from Get-SecurityTrends.
    #>
    param([object]$Trends)
    
    if (-not $Trends -or -not $Trends.HasSufficientData) { return "" }
    
    # Trend direction styling
    $trendClass = switch ($Trends.TrendDirection) {
        'Improving' { 'trend-improving' }
        'Declining' { 'trend-declining' }
        default { 'trend-stable' }
    }
    $trendIcon = switch ($Trends.TrendDirection) {
        'Improving' { '📈' }
        'Declining' { '📉' }
        default { '➡️' }
    }
    $trendColor = switch ($Trends.TrendDirection) {
        'Improving' { '#107c10' }
        'Declining' { '#d13438' }
        default { '#605e5c' }
    }
    
    # Score delta display
    $scoreDelta = if ($Trends.ScoreDelta -gt 0) { "+$($Trends.ScoreDelta)" } else { "$($Trends.ScoreDelta)" }
    $scoreDeltaClass = if ($Trends.ScoreDelta -gt 0) { 'delta-positive' } 
                       elseif ($Trends.ScoreDelta -lt 0) { 'delta-negative' } 
                       else { 'delta-neutral' }
    
    # Build regression alerts
    $regressionHtml = ""
    if ($Trends.HasRegressions -and $Trends.Regressions) {
        $alertClass = if ($Trends.Regressions.HasCritical) { 'alert-critical' } else { 'alert-warning' }
        $alertIcon = if ($Trends.Regressions.HasCritical) { '🚨' } else { '⚠️' }
        
        $regressionItems = @()
        if ($Trends.Regressions.ScoreRegression) {
            $regressionItems += "<li>Security score decreased by $([Math]::Abs($Trends.Regressions.ScoreRegression.Delta)) points</li>"
        }
        if ($Trends.Regressions.FailedChecksIncrease -and $Trends.Regressions.FailedChecksIncrease.Count -gt 0) {
            $regressionItems += "<li>$($Trends.Regressions.FailedChecksIncrease.Count) check(s) regressed from Pass to Fail</li>"
        }
        if ($Trends.Regressions.NewAttackChains -and $Trends.Regressions.NewAttackChains.Count -gt 0) {
            $regressionItems += "<li>$($Trends.Regressions.NewAttackChains.Count) new attack chain(s) enabled</li>"
        }
        
        if ($regressionItems.Count -gt 0) {
            $regressionHtml = @"
            <div class='trend-alert $alertClass'>
                <span class='alert-icon'>$alertIcon</span>
                <div class='alert-content'>
                    <strong>Regression Alert</strong>
                    <ul>$($regressionItems -join '')</ul>
                </div>
            </div>
"@
        }
    }
    
    # Build category trends
    $categoryTrendsHtml = ""
    if ($Trends.CategoryTrends) {
        $categoryTrendsHtml = "<div class='category-trends'><h4>Category Performance</h4><div class='category-grid'>"
        foreach ($cat in $Trends.CategoryTrends.GetEnumerator()) {
            $catIcon = switch ($cat.Value.Trend) {
                'Improving' { '↑' }
                'Declining' { '↓' }
                default { '→' }
            }
            $catClass = switch ($cat.Value.Trend) {
                'Improving' { 'cat-improving' }
                'Declining' { 'cat-declining' }
                default { 'cat-stable' }
            }
            $catDelta = if ($cat.Value.Delta -gt 0) { "+$($cat.Value.Delta)" } else { "$($cat.Value.Delta)" }
            $catName = ConvertTo-HtmlSafe $cat.Key
            $categoryTrendsHtml += @"
                <div class='category-trend-item $catClass'>
                    <span class='cat-name'>$catName</span>
                    <span class='cat-delta'>$catDelta% $catIcon</span>
                </div>
"@
        }
        $categoryTrendsHtml += "</div></div>"
    }
    
    # Build velocity info
    $velocityHtml = ""
    if ($Trends.Velocity) {
        $weeklyRate = if ($Trends.Velocity.WeeklyRate -gt 0) { "+$($Trends.Velocity.WeeklyRate)" } else { "$($Trends.Velocity.WeeklyRate)" }
        $daysToTarget = if ($Trends.Velocity.DaysToTarget -gt 0 -and $Trends.Velocity.DaysToTarget -lt 9999) {
            "$($Trends.Velocity.DaysToTarget) days"
        } else { "N/A" }
        $velocityHtml = @"
            <div class='trend-velocity'>
                <div class='velocity-item'>
                    <span class='velocity-value'>$weeklyRate%</span>
                    <span class='velocity-label'>Weekly Rate</span>
                </div>
                <div class='velocity-item'>
                    <span class='velocity-value'>$daysToTarget</span>
                    <span class='velocity-label'>Est. to Target (95%)</span>
                </div>
            </div>
"@
    }
    
    # Build timeline chart data
    $timelineHtml = ""
    if ($Trends.Timeline -and $Trends.Timeline.Labels) {
        $labelsJson = ($Trends.Timeline.Labels | ForEach-Object { "'$_'" }) -join ', '
        $dataJson = ($Trends.Timeline.DataPoints | ForEach-Object { $_ }) -join ', '
        $timelineHtml = @"
            <div class='trend-chart-container'>
                <canvas id='trendChart'></canvas>
                <script>
                    if (typeof Chart !== 'undefined') {
                        new Chart(document.getElementById('trendChart'), {
                            type: 'line',
                            data: {
                                labels: [$labelsJson],
                                datasets: [{
                                    label: 'Security Score',
                                    data: [$dataJson],
                                    borderColor: '$trendColor',
                                    backgroundColor: '$($trendColor)20',
                                    fill: true,
                                    tension: 0.3
                                }]
                            },
                            options: {
                                responsive: true,
                                scales: { y: { min: 0, max: 100 } },
                                plugins: { legend: { display: false } }
                            }
                        });
                    }
                </script>
            </div>
"@
    }
    
    return @"
    <div class='trends-section'>
        <div class='trends-header'>
            <h2 class='trends-title'>📊 Security Trend Analysis</h2>
            <div class='trend-direction $trendClass'>
                <span class='trend-icon'>$trendIcon</span>
                <span class='trend-text'>$($Trends.TrendDirection)</span>
            </div>
        </div>
        
        <div class='trend-summary'>
            <div class='trend-stat'>
                <span class='stat-value $scoreDeltaClass'>$scoreDelta%</span>
                <span class='stat-label'>Score Change</span>
            </div>
            <div class='trend-stat'>
                <span class='stat-value'>$($Trends.DataPoints)</span>
                <span class='stat-label'>Data Points</span>
            </div>
            <div class='trend-stat'>
                <span class='stat-value'>$($Trends.AnalysisPeriod) days</span>
                <span class='stat-label'>Analysis Period</span>
            </div>
        </div>
        
        $regressionHtml
        $velocityHtml
        $timelineHtml
        $categoryTrendsHtml
    </div>
"@
}

#endregion

#region Main HTML Export Function

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports assessment results to an HTML report.
    
    .DESCRIPTION
        Generates a rich HTML report with charts, findings cards, security score
        dashboard, and baseline comparison sections.
    
    .PARAMETER Results
        The assessment results array.
    
    .PARAMETER OutputPath
        Full path for the HTML output file.
    
    .PARAMETER TenantInfo
        Tenant information object.
    
    .PARAMETER SecurityScore
        Security score object (optional).
    
    .PARAMETER BaselineComparison
        Baseline comparison object (optional).
    
    .PARAMETER AttackChains
        Attack chain analysis results (optional).
    
    .PARAMETER Trends
        Trend analysis results (optional).
    
    .PARAMETER TemplatePath
        Path to the HTML template file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        $TenantInfo,
        
        [Parameter(Mandatory = $false)]
        $SecurityScore,
        
        [Parameter(Mandatory = $false)]
        $BaselineComparison,
        
        [Parameter(Mandatory = $false)]
        $AttackChains,
        
        [Parameter(Mandatory = $false)]
        $Trends,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplatePath
    )
    
    # Load template
    $html = ""
    if ($TemplatePath -and (Test-Path $TemplatePath)) {
        $html = Get-Content -Path $TemplatePath -Raw -Encoding UTF8
    } else {
        Write-Warning "HTML template not found. Using minimal fallback."
        $html = Get-FallbackHtmlTemplate
    }
    
    # Calculate statistics
    $totalChecks = $Results.Count
    $passCount = ($Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $failCount = ($Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $warnCount = ($Results | Where-Object { $_.Status -eq 'Warning' }).Count
    $infoCount = ($Results | Where-Object { $_.Status -eq 'Info' }).Count
    $passPercentage = if ($totalChecks -gt 0) { [math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }
    
    # Calculate severity distribution
    $severityCounts = @{
        'Critical' = ($Results | Where-Object { $_.Severity -eq 'Critical' }).Count
        'High' = ($Results | Where-Object { $_.Severity -eq 'High' }).Count
        'Medium' = ($Results | Where-Object { $_.Severity -eq 'Medium' }).Count
        'Low' = ($Results | Where-Object { $_.Severity -eq 'Low' }).Count
        'Info' = ($Results | Where-Object { $_.Severity -eq 'Info' }).Count
    }
    
    $severityLabels = @()
    $severityValues = @()
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        if ($severityCounts[$severity] -gt 0) {
            $severityLabels += "'$severity'"
            $severityValues += $severityCounts[$severity]
        }
    }
    $severityLabelsJson = "[$($severityLabels -join ', ')]"
    $severityValuesJson = "[$($severityValues -join ', ')]"
    
    # Build results cards
    $resultsHtml = Build-FindingCardsHtml -Results $Results
    
    # Build dashboard sections
    $securityScoreHtml = Build-SecurityScoreDashboardHtml -SecurityScore $SecurityScore
    $baselineComparisonHtml = Build-BaselineComparisonHtml -BaselineComparison $BaselineComparison
    $attackChainsHtml = Build-AttackChainsSectionHtml -AttackChains $AttackChains
    $trendsHtml = Build-TrendsSectionHtml -Trends $Trends
    
    # Replace placeholders
    $tenantName = if ($TenantInfo) { $TenantInfo.DisplayName } else { "Not Connected" }
    $tenantNameSafe = ConvertTo-HtmlSafe $tenantName
    
    $html = $html -replace '{{TENANT_NAME}}', $tenantNameSafe
    $html = $html -replace '{{ASSESSMENT_DATE}}', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $html = $html -replace '{{TOTAL_CHECKS}}', $totalChecks
    $html = $html -replace '{{PASS_COUNT}}', $passCount
    $html = $html -replace '{{FAIL_COUNT}}', $failCount
    $html = $html -replace '{{WARN_COUNT}}', $warnCount
    $html = $html -replace '{{INFO_COUNT}}', $infoCount
    $html = $html -replace '{{PASS_PERCENTAGE}}', $passPercentage
    $html = $html -replace '{{SEVERITY_LABELS}}', $severityLabelsJson
    $html = $html -replace '{{SEVERITY_COUNTS}}', $severityValuesJson
    $html = $html -replace '{{SECURITY_SCORE_SECTION}}', $securityScoreHtml
    $html = $html -replace '{{BASELINE_COMPARISON_SECTION}}', $baselineComparisonHtml
    $html = $html -replace '{{ATTACK_CHAINS_SECTION}}', $attackChainsHtml
    $html = $html -replace '{{TRENDS_SECTION}}', $trendsHtml
    $html = $html -replace '{{RESULTS_CARDS}}', $resultsHtml
    
    $html | Out-File $OutputPath -Encoding UTF8
    
    return $OutputPath
}

function Get-FallbackHtmlTemplate {
    <#
    .SYNOPSIS
        Returns a minimal fallback HTML template.
    #>
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>M365 Security Guardian Report - {{TENANT_NAME}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 40px; }
        .error { color: #d13438; background: #fde7e9; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>M365 Security Guardian Report</h1>
    <div class="error">
        <h2>Template Error</h2>
        <p>The HTML report template file was not found.</p>
    </div>
    <h2>Results Summary</h2>
    <p>Total Checks: {{TOTAL_CHECKS}} | Passed: {{PASS_COUNT}} | Failed: {{FAIL_COUNT}} | Warnings: {{WARN_COUNT}}</p>
    {{RESULTS_CARDS}}
</body>
</html>
'@
}

function Build-FindingCardsHtml {
    <#
    .SYNOPSIS
        Builds HTML cards for all assessment findings.
    
    .PARAMETER Results
        Array of assessment results.
    #>
    param([array]$Results)
    
    if ($Results.Count -eq 0) {
        return @"
<div class="empty-state">
    <div class="empty-state-icon">📋</div>
    <div class="empty-state-text">No assessment results found</div>
</div>
"@
    }
    
    $resultsHtml = ""
    
    foreach ($result in $Results) {
        $statusClass = $result.Status.ToLower()
        $severityClass = $result.Severity.ToLower()
        
        # HTML-encode all dynamic text
        $checkNameSafe = ConvertTo-HtmlSafe $result.CheckName
        $categorySafe = ConvertTo-HtmlSafe $result.Category
        $statusSafe = ConvertTo-HtmlSafe $result.Status
        $severitySafe = ConvertTo-HtmlSafe $result.Severity
        $messageSafe = ConvertTo-HtmlSafe $result.Message
        $recommendationSafe = ConvertTo-HtmlSafe $result.Recommendation
        $docUrlSafe = ConvertTo-HtmlSafe $result.DocumentationUrl
        
        # Build finding content based on check type
        $findingContent = Build-FindingContentHtml -Result $result -DefaultMessage $messageSafe
        
        # Build recommendation content
        $recommendationContent = Build-RecommendationContentHtml -Result $result -DefaultRecommendation $recommendationSafe
        
        $resultsHtml += @"
<div class="finding-card" data-status="$statusClass">
    <div class="finding-header">
        <div class="finding-title-group">
            <div class="finding-name">$checkNameSafe</div>
            <div class="finding-badges">
                <span class="badge badge-category">$categorySafe</span>
                <span class="badge badge-status-$statusClass">$statusSafe</span>
                <span class="badge badge-severity-$severityClass">$severitySafe</span>
            </div>
        </div>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <div class="finding-label">Finding</div>
            <div class="finding-content">$findingContent</div>
        </div>
        <div class="finding-section">
            <div class="finding-label">Recommendation</div>
            <div class="finding-content">$recommendationContent</div>
        </div>
        <div class="finding-section">
            <a href="$docUrlSafe" target="_blank" class="doc-link">
                <span>📘</span>
                <span>View Documentation</span>
            </a>
        </div>
    </div>
</div>

"@
    }
    
    return $resultsHtml
}

function Build-FindingContentHtml {
    <#
    .SYNOPSIS
        Builds the finding content HTML based on the result type.
    #>
    param(
        [object]$Result,
        [string]$DefaultMessage
    )
    
    $findingContent = $DefaultMessage
    
    # MFA Enforcement
    if ($Result.CheckName -eq "MFA Enforcement") {
        $findingContent = Build-MFAFindingsHtml -Result $Result -DefaultMessage $DefaultMessage
    }

    # Conditional Access
    if ($Result.CheckName -eq "Conditional Access Policies" -and $Result.Findings -and $Result.Findings.Count -gt 0) {
        $findingContent = Build-ConditionalAccessFindingHtml -Result $Result
    }
    
    # Inactive mailboxes
    if ($Result.InactiveMailboxes -and $Result.InactiveMailboxes.Count -gt 0) {
        $findingContent += Build-ListedItemsHtml -Items $Result.InactiveMailboxes -Title "Inactive Licensed Users" -ItemFormatter {
            param($mailbox)
            $upnSafe = ConvertTo-HtmlSafe $mailbox.UserPrincipalName
            $nameSafe = ConvertTo-HtmlSafe $mailbox.DisplayName
            $lastSignIn = if ($mailbox.LastSignInDate -eq 'Never') { '<span style="color: #d13438; font-weight: 600;">Never</span>' } else { ConvertTo-HtmlSafe $mailbox.LastSignInDate }
            "<code>$upnSafe</code> - $nameSafe | Last: $lastSignIn ($($mailbox.DaysSinceLastSignIn) days ago)"
        }
    }
    
    # Non-compliant mailboxes
    if ($Result.NonCompliantMailboxes -and $Result.NonCompliantMailboxes.Count -gt 0) {
        $findingContent += Build-ListedItemsHtml -Items $Result.NonCompliantMailboxes -Title "Non-Compliant Mailboxes" -ItemFormatter {
            param($mailbox)
            $upnSafe = ConvertTo-HtmlSafe $mailbox.UserPrincipalName
            $nameSafe = ConvertTo-HtmlSafe $mailbox.DisplayName
            "<code>$upnSafe</code> - $nameSafe"
        }
    }
    
    # Domain email auth
    if ($Result.DomainDetails -and $Result.DomainDetails.Count -gt 0) {
        $findingContent += Build-DomainEmailAuthHtml -Result $Result
    }
    
    # Legacy Auth block policies
    if ($Result.BlockPolicies -and $Result.BlockPolicies.Count -gt 0) {
        $caPortalBase = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConditionalAccessBlade/~/policyId/"
        $findingContent += Build-ListedItemsHtml -Items $Result.BlockPolicies -Title "Legacy Auth Block Policies" -ItemFormatter {
            param($policy)
            $policyNameSafe = ConvertTo-HtmlSafe $policy.DisplayName
            $policyIdSafe = ConvertTo-HtmlSafe $policy.Id
            $policyLink = "$caPortalBase$policyIdSafe"
            "<code>$policyNameSafe</code> <a href='$policyLink' target='_blank' style='margin-left:6px; font-size:12px;'>Open in Entra</a> <span style='color: var(--gray-700); font-size: 12px;'>ID: <code>$policyIdSafe</code></span>"
        } -MaxDisplay 20
    }
    
    # Enabled CA policies
    if ($Result.EnabledPolicies -and $Result.EnabledPolicies.Count -gt 0 -and $Result.CheckName -ne "Conditional Access Policies") {
        $findingContent += Build-ListedItemsHtml -Items $Result.EnabledPolicies -Title "Enabled Conditional Access Policies" -ItemFormatter {
            param($policy)
            $policyNameSafe = ConvertTo-HtmlSafe $policy.DisplayName
            $stateColor = if ($policy.State -eq 'enabled') { 'var(--success-color)' } else { 'var(--warning-color)' }
            "<code>$policyNameSafe</code> - <span style='color: $stateColor; font-weight: 600;'>$(ConvertTo-HtmlSafe $policy.State)</span>"
        } -MaxDisplay 20
    }
    
    # Privileged accounts
    if ($Result.PrivilegedAccounts -and $Result.PrivilegedAccounts.Count -gt 0) {
        $findingContent += Build-PrivilegedAccountsHtml -Result $Result
    }
    
    # Secure Score
    if ($Result.SecureScore -and $Result.MaxScore) {
        $findingContent += Build-SecureScoreHtml -Result $Result
    }
    
    # Risky apps
    if ($Result.RiskyApps -and $Result.RiskyApps.Count -gt 0) {
        $findingContent += Build-RiskyAppsHtml -Result $Result
    }
    
    # Email Security Configuration
    if ($Result.CheckName -eq "Email Security Configuration" -and $Result.Findings -and $Result.Findings.Count -gt 0) {
        $findingContent += Build-GenericFindingsTableHtml -Result $Result -Columns @(
            @{ Name = 'Protection Layer'; Property = 'Setting' },
            @{ Name = 'Status'; Property = 'Value'; Formatter = { param($v) if ($v -like 'Enabled*') { "✅ $v" } elseif ($v -eq 'Not Configured') { "❌ $v" } else { "⚪ $v" } } },
            @{ Name = 'Risk Level'; Property = 'Risk'; ColorProperty = 'Risk' }
        )
    }
    
    # External Sharing
    if ($Result.CheckName -eq "External Sharing Configuration" -and $Result.Findings -and $Result.Findings.Count -gt 0) {
        $findingContent += Build-GenericFindingsTableHtml -Result $Result -Columns @(
            @{ Name = 'Setting'; Property = 'Setting' },
            @{ Name = 'Current Value'; Property = 'Value' },
            @{ Name = 'Risk Level'; Property = 'Risk'; ColorProperty = 'Risk' }
        )
    }
    
    return $findingContent
}

function Build-MFAFindingsHtml {
    <#
    .SYNOPSIS
        Builds a structured findings summary for MFA enforcement.
    #>
    param(
        [object]$Result,
        [string]$DefaultMessage
    )

    if (-not $Result.Details) {
        return $DefaultMessage
    }

    $totalUsers = $Result.Details.TotalUsers
    $usersWithMfa = $Result.Details.UsersWithMFA
    $usersWithoutMfa = $Result.Details.UsersWithoutMFA
    $compliance = $Result.Details.CompliancePercentage
    $threshold = $Result.Details.Threshold

    $adoptionText = if ($null -ne $compliance) { "$compliance%" } else { "N/A" }
    $thresholdText = if ($null -ne $threshold) { "$threshold%" } else { "N/A" }

    $html = "<div class='mfa-summary'>"
    $html += "<div class='mfa-stat'><span class='mfa-label'>Adoption</span><span class='mfa-value'>$adoptionText</span></div>"
    $html += "<div class='mfa-stat'><span class='mfa-label'>Users With MFA</span><span class='mfa-value'>$usersWithMfa</span></div>"
    $html += "<div class='mfa-stat'><span class='mfa-label'>Users Without MFA</span><span class='mfa-value'>$usersWithoutMfa</span></div>"
    $html += "<div class='mfa-stat'><span class='mfa-label'>Target Threshold</span><span class='mfa-value'>$thresholdText</span></div>"
    $html += "</div>"

    if ($Result.UsersWithoutMFA -and $Result.UsersWithoutMFA.Count -gt 0) {
        $html += Build-ListedItemsHtml -Items $Result.UsersWithoutMFA -Title "Users without MFA" -ItemFormatter {
            param($user)
            $upnSafe = ConvertTo-HtmlSafe $user.UserPrincipalName
            $nameSafe = ConvertTo-HtmlSafe $user.DisplayName
            if (-not $nameSafe) { $nameSafe = "Unknown" }
            "<code>$upnSafe</code> - $nameSafe"
        } -MaxDisplay 15
    }
    else {
        $html += "<div class='mfa-note'>No users without MFA were detected.</div>"
    }

    return $html
}

function Build-RecommendationContentHtml {
    <#
    .SYNOPSIS
        Builds the recommendation content HTML.
    #>
    param(
        [object]$Result,
        [string]$DefaultRecommendation
    )
    
    $recommendationContent = $DefaultRecommendation
    
    if ($Result.CheckName -eq "Conditional Access Policies" -and $Result.Recommendations -and $Result.Recommendations.Count -gt 0) {
        # Map recommendation keywords to categories and priority
        $categoryMap = @{
            'legacy authentication'       = @{ Category = 'Authentication';     Priority = 'High' }
            'risk-based'                   = @{ Category = 'Risk Protection';    Priority = 'High' }
            'sign-in risk'                 = @{ Category = 'Risk Protection';    Priority = 'High' }
            'user risk'                    = @{ Category = 'Risk Protection';    Priority = 'High' }
            'Authentication Strength'      = @{ Category = 'Authentication';     Priority = 'High' }
            'MFA'                          = @{ Category = 'Authentication';     Priority = 'High' }
            'strong auth'                  = @{ Category = 'Authentication';     Priority = 'High' }
            'device compliance'            = @{ Category = 'Device Security';    Priority = 'Medium' }
            'hybrid Azure AD'             = @{ Category = 'Device Security';    Priority = 'Medium' }
            'named locations'              = @{ Category = 'Network Controls';   Priority = 'Medium' }
            'location-based'               = @{ Category = 'Network Controls';   Priority = 'Medium' }
            'untrusted'                    = @{ Category = 'Network Controls';   Priority = 'Medium' }
            'token protection'             = @{ Category = 'Token Security';     Priority = 'Medium' }
            'workload identit'             = @{ Category = 'Workload Identity';  Priority = 'Medium' }
            'service principal'            = @{ Category = 'Workload Identity';  Priority = 'Medium' }
            'app protection'               = @{ Category = 'App Protection';     Priority = 'Medium' }
            'approved client'              = @{ Category = 'App Protection';     Priority = 'Medium' }
            'guest'                        = @{ Category = 'Guest Access';       Priority = 'Medium' }
            'external user'                = @{ Category = 'Guest Access';       Priority = 'Medium' }
            'policy conflict'              = @{ Category = 'Policy Hygiene';     Priority = 'High' }
            'coverage gap'                 = @{ Category = 'Coverage';           Priority = 'High' }
            'report-only'                  = @{ Category = 'Policy Hygiene';     Priority = 'Low' }
            'exclusion'                    = @{ Category = 'Policy Hygiene';     Priority = 'High' }
            'session'                      = @{ Category = 'Session Controls';   Priority = 'Low' }
            'sign-in frequency'            = @{ Category = 'Session Controls';   Priority = 'Low' }
            'privileged'                   = @{ Category = 'Admin Protection';   Priority = 'High' }
        }
        
        $priorityOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        
        $recRows = @()
        foreach ($rec in $Result.Recommendations) {
            $matchedCategory = 'General'
            $matchedPriority = 'Medium'
            
            foreach ($keyword in $categoryMap.Keys) {
                if ($rec -match [regex]::Escape($keyword)) {
                    $matchedCategory = $categoryMap[$keyword].Category
                    $matchedPriority = $categoryMap[$keyword].Priority
                    break
                }
            }
            
            $recRows += [PSCustomObject]@{
                Text     = $rec
                Category = $matchedCategory
                Priority = $matchedPriority
                Order    = $priorityOrder[$matchedPriority]
            }
        }
        
        # Sort by priority
        $recRows = $recRows | Sort-Object Order
        
        $recommendationContent = "<strong>Actionable Recommendations ($($Result.Recommendations.Count)):</strong>"
        $recommendationContent += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
        $recommendationContent += "<tr style='background: var(--gray-100); font-weight: 600;'>"
        $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); width: 60px; text-align: center;'>#</td>"
        $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); width: 80px;'>Priority</td>"
        $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); width: 130px;'>Category</td>"
        $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>Recommendation</td>"
        $recommendationContent += "</tr>"
        
        $index = 1
        foreach ($row in $recRows) {
            $recSafe = ConvertTo-HtmlSafe $row.Text
            $catSafe = ConvertTo-HtmlSafe $row.Category
            $priSafe = ConvertTo-HtmlSafe $row.Priority
            
            $priorityColor = switch ($row.Priority) {
                'High'   { '#d13438' }
                'Medium' { '#8a6b0f' }
                'Low'    { '#0078d4' }
                default  { 'var(--gray-700)' }
            }
            $priorityBg = switch ($row.Priority) {
                'High'   { '#fde7e9' }
                'Medium' { '#fff4ce' }
                'Low'    { '#deecf9' }
                default  { 'var(--gray-100)' }
            }
            
            $recommendationContent += "<tr>"
            $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); text-align: center; font-weight: 600;'>$index</td>"
            $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300); background: $priorityBg; color: $priorityColor; font-weight: 600; text-align: center;'>$priSafe</td>"
            $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$catSafe</td>"
            $recommendationContent += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$recSafe</td>"
            $recommendationContent += "</tr>"
            $index++
        }
        
        $recommendationContent += "</table>"
    }
    
    return $recommendationContent
}

function Build-GenericFindingsTableHtml {
    <#
    .SYNOPSIS
        Builds a generic HTML table for findings with risk indicators.
    #>
    param(
        [object]$Result,
        [array]$Columns
    )
    
    $html = "<br><br><strong>$($Result.CheckName) Details:</strong><br>"
    $html += "<table style='width: 100%; margin-top: 10px; border-collapse: collapse; font-size: 13px;'>"
    
    # Header row
    $html += "<tr style='background: var(--gray-100); font-weight: 600;'>"
    foreach ($col in $Columns) {
        $html += "<td style='padding: 8px; border: 1px solid var(--gray-300);'>$($col.Name)</td>"
    }
    $html += "</tr>"
    
    # Data rows
    foreach ($finding in $Result.Findings) {
        $html += "<tr>"
        foreach ($col in $Columns) {
            $value = $finding.($col.Property)
            $valueSafe = ConvertTo-HtmlSafe $value
            
            $style = "padding: 8px; border: 1px solid var(--gray-300);"
            
            if ($col.ColorProperty) {
                $colorValue = $finding.($col.ColorProperty)
                $color = switch ($colorValue) {
                    'High' { 'var(--danger-color)' }
                    'Medium' { 'var(--warning-color)' }
                    'Low' { 'var(--success-color)' }
                    default { 'var(--gray-700)' }
                }
                $style += " color: $color; font-weight: 600;"
                
                $icon = switch ($colorValue) {
                    'High' { '🔴' }
                    'Medium' { '🟡' }
                    'Low' { '🟢' }
                    default { '⚪' }
                }
                $valueSafe = "$icon $valueSafe"
            }
            
            if ($col.Formatter) {
                $valueSafe = & $col.Formatter $value
            }
            
            $html += "<td style='$style'>$valueSafe</td>"
        }
        $html += "</tr>"
    }
    $html += "</table>"
    
    # Issues list if present
    if ($Result.Issues -and $Result.Issues.Count -gt 0) {
        $html += "<br><strong>Issues Identified ($($Result.Issues.Count)):</strong><br>"
        $html += "<ul style='margin: 8px 0 0 0; padding-left: 20px;'>"
        foreach ($issue in $Result.Issues) {
            $issueSafe = ConvertTo-HtmlSafe $issue
            $html += "<li style='color: var(--warning-color); margin-bottom: 4px;'>$issueSafe</li>"
        }
        $html += "</ul>"
    }
    
    return $html
}

#endregion

# Note: Functions are automatically available when dot-sourced
# No Export-ModuleMember needed for .ps1 files
