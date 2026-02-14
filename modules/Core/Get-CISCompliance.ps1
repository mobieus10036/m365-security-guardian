<#
.SYNOPSIS
    Maps assessment findings to CIS Microsoft 365 Foundations Benchmark controls.

.DESCRIPTION
    Provides functions to map security findings to CIS benchmark controls,
    calculate compliance percentages, and generate audit-ready reports.

.NOTES
    CIS Microsoft 365 Foundations Benchmark v3.1.0
    https://www.cisecurity.org/benchmark/microsoft_365
#>

#region Configuration

$script:CISBenchmark = $null
$script:MitreMapping = @{
    'T1078'     = 'Valid Accounts'
    'T1078.004' = 'Valid Accounts: Cloud Accounts'
    'T1110'     = 'Brute Force'
    'T1110.003' = 'Brute Force: Password Spraying'
    'T1133'     = 'External Remote Services'
    'T1528'     = 'Steal Application Access Token'
    'T1534'     = 'Internal Spearphishing'
    'T1537'     = 'Transfer Data to Cloud Account'
    'T1539'     = 'Steal Web Session Cookie'
    'T1550.001' = 'Use Alternate Authentication Material: Application Access Token'
    'T1557'     = 'Adversary-in-the-Middle'
    'T1566.001' = 'Phishing: Spearphishing Attachment'
    'T1566.002' = 'Phishing: Spearphishing Link'
    'T1114'     = 'Email Collection'
    'T1114.002' = 'Email Collection: Remote Email Collection'
    'T1114.003' = 'Email Collection: Email Forwarding Rule'
    'T1530'     = 'Data from Cloud Storage'
}

#endregion

#region Public Functions

function Initialize-CISBenchmark {
    <#
    .SYNOPSIS
        Loads the CIS benchmark mapping configuration.
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )
    
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot "..\config\cis-benchmark-mapping.json"
    }
    
    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "CIS benchmark mapping not found at: $ConfigPath"
        return $null
    }
    
    try {
        $script:CISBenchmark = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Verbose "Loaded CIS benchmark: $($script:CISBenchmark.benchmarkInfo.name) v$($script:CISBenchmark.benchmarkInfo.version)"
        return $script:CISBenchmark
    }
    catch {
        Write-Warning "Failed to load CIS benchmark mapping: $_"
        return $null
    }
}

function Get-CISControlStatus {
    <#
    .SYNOPSIS
        Maps an assessment finding to its CIS control status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AssessmentKey,
        
        [Parameter(Mandatory)]
        [PSCustomObject]$Finding
    )
    
    if (-not $script:CISBenchmark) {
        Initialize-CISBenchmark | Out-Null
    }
    
    if (-not $script:CISBenchmark) {
        return $null
    }
    
    # Find all CIS controls that map to this assessment
    $relatedControls = $script:CISBenchmark.controls | Where-Object { 
        $_.assessmentKey -eq $AssessmentKey 
    }
    
    if (-not $relatedControls) {
        return $null
    }
    
    $results = foreach ($control in $relatedControls) {
        $status = Get-ControlComplianceStatus -Control $control -Finding $Finding
        
        [PSCustomObject]@{
            ControlId    = $control.id
            Title        = $control.title
            Level        = $control.level
            Section      = $control.section
            Status       = $status.Status
            StatusReason = $status.Reason
            Rationale    = $control.rationale
            Remediation  = $control.remediation
            MitreAttack  = ($control.mitre | ForEach-Object { 
                "$_ ($($script:MitreMapping[$_]))" 
            }) -join '; '
            Impact       = $control.impact
            Automated    = $control.automated
            FindingData  = $Finding
        }
    }
    
    return $results
}

function Get-ControlComplianceStatus {
    <#
    .SYNOPSIS
        Determines the compliance status of a specific control based on finding data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Control,
        
        [Parameter(Mandatory)]
        [PSCustomObject]$Finding
    )
    
    $status = 'Unknown'
    $reason = 'Unable to determine compliance status'
    
    # Map finding status to CIS compliance
    switch ($Finding.Status) {
        'Pass' {
            $status = 'Compliant'
            $reason = $Finding.Description
        }
        'Fail' {
            $status = 'Non-Compliant'
            $reason = $Finding.Description
        }
        'Warning' {
            # Warnings may still be compliant depending on the control
            $status = 'Partially Compliant'
            $reason = $Finding.Description
        }
        'Info' {
            $status = 'Manual Review Required'
            $reason = $Finding.Description
        }
        'Error' {
            $status = 'Unable to Assess'
            $reason = "Assessment error: $($Finding.Description)"
        }
        default {
            $status = 'Unknown'
            $reason = 'No finding data available'
        }
    }
    
    # Apply control-specific logic for more accurate mapping
    switch ($Control.checkType) {
        'GlobalAdminCount' {
            if ($Finding.Details.GlobalAdminCount) {
                $count = $Finding.Details.GlobalAdminCount
                if ($count -ge 2 -and $count -le 4) {
                    $status = 'Compliant'
                    $reason = "Global admin count ($count) is within recommended range (2-4)"
                } else {
                    $status = 'Non-Compliant'
                    $reason = "Global admin count ($count) is outside recommended range (2-4)"
                }
            }
        }
        'AllUserMFAEnabled' {
            if ($Finding.Details.PercentWithMFA) {
                $pct = $Finding.Details.PercentWithMFA
                if ($pct -ge 100) {
                    $status = 'Compliant'
                    $reason = "100% of users have MFA enabled"
                } elseif ($pct -ge 90) {
                    $status = 'Partially Compliant'
                    $reason = "$pct% of users have MFA enabled (target: 100%)"
                } else {
                    $status = 'Non-Compliant'
                    $reason = "Only $pct% of users have MFA enabled (target: 100%)"
                }
            }
        }
        'LegacyAuthBlocked' {
            if ($Finding.Status -eq 'Pass') {
                $status = 'Compliant'
            } else {
                $status = 'Non-Compliant'
            }
        }
        'PIMEnabled' {
            if ($Finding.Details.PIMAvailable -eq $true) {
                $status = 'Compliant'
                $reason = "PIM is enabled and configured"
            } elseif ($Finding.Description -like '*P2*' -or $Finding.Description -like '*license*') {
                $status = 'Not Applicable'
                $reason = "PIM requires Entra ID P2 licensing"
            } else {
                $status = 'Non-Compliant'
            }
        }
    }
    
    return @{
        Status = $status
        Reason = $reason
    }
}

function Get-CISComplianceSummary {
    <#
    .SYNOPSIS
        Generates a summary of CIS benchmark compliance across all findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$AssessmentResults
    )
    
    if (-not $script:CISBenchmark) {
        Initialize-CISBenchmark | Out-Null
    }
    
    if (-not $script:CISBenchmark) {
        Write-Warning "CIS benchmark not loaded"
        return $null
    }
    
    $allControlStatuses = @()
    
    # Map each finding to its CIS controls
    foreach ($finding in $AssessmentResults) {
        $controlStatuses = Get-CISControlStatus -AssessmentKey $finding.CheckName -Finding $finding
        if ($controlStatuses) {
            $allControlStatuses += $controlStatuses
        }
    }
    
    # Calculate compliance by level
    $level1Controls = $allControlStatuses | Where-Object { $_.Level -eq 1 }
    $level2Controls = $allControlStatuses | Where-Object { $_.Level -eq 2 }
    
    $level1Compliant = ($level1Controls | Where-Object { $_.Status -eq 'Compliant' }).Count
    $level1Total = $level1Controls.Count
    $level1Pct = if ($level1Total -gt 0) { [math]::Round(($level1Compliant / $level1Total) * 100, 1) } else { 0 }
    
    $level2Compliant = ($level2Controls | Where-Object { $_.Status -eq 'Compliant' }).Count
    $level2Total = $level2Controls.Count
    $level2Pct = if ($level2Total -gt 0) { [math]::Round(($level2Compliant / $level2Total) * 100, 1) } else { 0 }
    
    # Group by section
    $bySection = $allControlStatuses | Group-Object Section | ForEach-Object {
        $sectionCompliant = ($_.Group | Where-Object { $_.Status -eq 'Compliant' }).Count
        $sectionTotal = $_.Group.Count
        [PSCustomObject]@{
            Section = $_.Name
            Compliant = $sectionCompliant
            Total = $sectionTotal
            Percentage = if ($sectionTotal -gt 0) { [math]::Round(($sectionCompliant / $sectionTotal) * 100, 1) } else { 0 }
        }
    }
    
    # Status distribution
    $statusCounts = $allControlStatuses | Group-Object Status | ForEach-Object {
        [PSCustomObject]@{
            Status = $_.Name
            Count = $_.Count
        }
    }
    
    # Get non-compliant controls for priority remediation
    $nonCompliant = $allControlStatuses | Where-Object { 
        $_.Status -eq 'Non-Compliant' 
    } | Sort-Object Level, ControlId
    
    # Get controls with MITRE mappings for threat context
    $threatMapped = $allControlStatuses | Where-Object { 
        $_.MitreAttack -and $_.Status -ne 'Compliant' 
    }
    
    return [PSCustomObject]@{
        BenchmarkName    = $script:CISBenchmark.benchmarkInfo.name
        BenchmarkVersion = $script:CISBenchmark.benchmarkInfo.version
        AssessmentDate   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        
        # Overall stats
        TotalControls    = $allControlStatuses.Count
        CompliantCount   = ($allControlStatuses | Where-Object { $_.Status -eq 'Compliant' }).Count
        NonCompliantCount = ($allControlStatuses | Where-Object { $_.Status -eq 'Non-Compliant' }).Count
        PartialCount     = ($allControlStatuses | Where-Object { $_.Status -eq 'Partially Compliant' }).Count
        ManualCount      = ($allControlStatuses | Where-Object { $_.Status -eq 'Manual Review Required' }).Count
        
        # By level
        Level1 = @{
            Compliant  = $level1Compliant
            Total      = $level1Total
            Percentage = $level1Pct
        }
        Level2 = @{
            Compliant  = $level2Compliant
            Total      = $level2Total
            Percentage = $level2Pct
        }
        
        # Detailed breakdowns
        BySection        = $bySection
        StatusDistribution = $statusCounts
        
        # Action items
        NonCompliantControls = $nonCompliant
        ThreatMappedFindings = $threatMapped
        
        # All control statuses for detailed reporting
        AllControls      = $allControlStatuses
    }
}

function Format-CISComplianceReport {
    <#
    .SYNOPSIS
        Formats CIS compliance summary for console output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ComplianceSummary
    )
    
    $output = @()
    
    $output += ""
    $output += "╔══════════════════════════════════════════════════════════════════════╗"
    $output += "║            CIS Microsoft 365 Foundations Benchmark                   ║"
    $output += "║                    Compliance Assessment                             ║"
    $output += "╚══════════════════════════════════════════════════════════════════════╝"
    $output += ""
    $output += "  Benchmark: $($ComplianceSummary.BenchmarkName) v$($ComplianceSummary.BenchmarkVersion)"
    $output += "  Assessed:  $($ComplianceSummary.AssessmentDate)"
    $output += ""
    $output += "  ┌─────────────────────────────────────────────────────────────────┐"
    $output += "  │  COMPLIANCE SUMMARY                                             │"
    $output += "  ├─────────────────────────────────────────────────────────────────┤"
    
    # Level 1 (Essential)
    $l1Bar = Get-ProgressBar -Percentage $ComplianceSummary.Level1.Percentage -Width 20
    $output += "  │  Level 1 (Essential):  $l1Bar $($ComplianceSummary.Level1.Percentage)% ($($ComplianceSummary.Level1.Compliant)/$($ComplianceSummary.Level1.Total))".PadRight(64) + "│"
    
    # Level 2 (Enhanced)
    $l2Bar = Get-ProgressBar -Percentage $ComplianceSummary.Level2.Percentage -Width 20
    $output += "  │  Level 2 (Enhanced):   $l2Bar $($ComplianceSummary.Level2.Percentage)% ($($ComplianceSummary.Level2.Compliant)/$($ComplianceSummary.Level2.Total))".PadRight(64) + "│"
    
    $output += "  └─────────────────────────────────────────────────────────────────┘"
    $output += ""
    
    # Status distribution
    $output += "  Status Distribution:"
    foreach ($status in $ComplianceSummary.StatusDistribution) {
        $icon = switch ($status.Status) {
            'Compliant' { if ($script:CheckMark) { $script:CheckMark } else { '+' } }
            'Non-Compliant' { if ($script:CrossMark) { $script:CrossMark } else { 'x' } }
            'Partially Compliant' { '~' }
            'Manual Review Required' { '?' }
            default { 'o' }
        }
        $output += "    $icon $($status.Status): $($status.Count)"
    }
    $output += ""
    
    # Section breakdown
    $output += "  Compliance by Section:"
    foreach ($section in ($ComplianceSummary.BySection | Sort-Object Section)) {
        $sectionBar = Get-ProgressBar -Percentage $section.Percentage -Width 15
        $output += "    $sectionBar $($section.Percentage.ToString().PadLeft(5))%  $($section.Section)"
    }
    $output += ""
    
    # Non-compliant controls (top priorities)
    if ($ComplianceSummary.NonCompliantControls.Count -gt 0) {
        $warnMark = if ($script:WarningMark) { $script:WarningMark } else { '!' }
        $output += "  $warnMark Non-Compliant Controls Requiring Remediation:"
        $topItems = $ComplianceSummary.NonCompliantControls | Select-Object -First 5
        foreach ($item in $topItems) {
            $levelTag = if ($item.Level -eq 1) { "[L1]" } else { "[L2]" }
            $output += "    $levelTag $($item.ControlId): $($item.Title)"
            if ($item.MitreAttack) {
                $output += "        MITRE: $($item.MitreAttack)"
            }
        }
        if ($ComplianceSummary.NonCompliantControls.Count -gt 5) {
            $remaining = $ComplianceSummary.NonCompliantControls.Count - 5
            $output += "    ... and $remaining more non-compliant controls"
        }
    }
    
    return $output -join "`n"
}

function Get-ProgressBar {
    param(
        [double]$Percentage,
        [int]$Width = 20
    )
    
    $filled = [int][math]::Floor(($Percentage / 100) * $Width)
    $empty = [int]($Width - $filled)

    # Explicitly cast to string - PowerShell doesn't support [char] * [int]
    [string]$fillChar = if ($script:BlockFull) { $script:BlockFull } else { '#' }
    [string]$emptyChar = if ($script:BlockLight) { $script:BlockLight } else { '-' }
    $bar = ($fillChar * $filled) + ($emptyChar * $empty)
    return "[$bar]"
}

function Export-CISComplianceReport {
    <#
    .SYNOPSIS
        Exports CIS compliance report to various formats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ComplianceSummary,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [ValidateSet('JSON', 'CSV', 'HTML')]
        [string[]]$Format = @('JSON', 'CSV')
    )
    
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    $baseDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    
    foreach ($fmt in $Format) {
        switch ($fmt) {
            'JSON' {
                $jsonPath = Join-Path $baseDir "${baseName}_CISCompliance.json"
                $exportData = @{
                    BenchmarkInfo = @{
                        Name = $ComplianceSummary.BenchmarkName
                        Version = $ComplianceSummary.BenchmarkVersion
                    }
                    AssessmentDate = $ComplianceSummary.AssessmentDate
                    Summary = @{
                        Level1Compliance = $ComplianceSummary.Level1
                        Level2Compliance = $ComplianceSummary.Level2
                        TotalControls = $ComplianceSummary.TotalControls
                        CompliantCount = $ComplianceSummary.CompliantCount
                        NonCompliantCount = $ComplianceSummary.NonCompliantCount
                    }
                    SectionBreakdown = $ComplianceSummary.BySection
                    Controls = $ComplianceSummary.AllControls | ForEach-Object {
                        @{
                            ControlId = $_.ControlId
                            Title = $_.Title
                            Level = $_.Level
                            Section = $_.Section
                            Status = $_.Status
                            StatusReason = $_.StatusReason
                            Remediation = $_.Remediation
                            MitreAttack = $_.MitreAttack
                            Impact = $_.Impact
                        }
                    }
                }
                $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                $chk = if ($script:CheckMark) { $script:CheckMark } else { '+' }
                Write-Information "  $chk CIS compliance JSON: $jsonPath" -InformationAction Continue
            }
            'CSV' {
                $csvPath = Join-Path $baseDir "${baseName}_CISCompliance.csv"
                $ComplianceSummary.AllControls | Select-Object `
                    ControlId, Title, Level, Section, Status, StatusReason, `
                    Remediation, MitreAttack, Impact, Automated |
                    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Information "  $chk CIS compliance CSV: $csvPath" -InformationAction Continue
            }
        }
    }
}

#endregion

# Export functions
$exportedFunctions = @(
    'Initialize-CISBenchmark',
    'Get-CISControlStatus',
    'Get-CISComplianceSummary',
    'Format-CISComplianceReport',
    'Export-CISComplianceReport'
)
