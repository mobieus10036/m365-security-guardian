<#
.SYNOPSIS
    Baseline comparison module for M365 Security Guardian.

.DESCRIPTION
    Provides functionality to save assessment baselines and compare current
    assessments against previous baselines to track security improvements
    or regressions over time.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.2.0
    Created with assistance from GitHub Copilot
#>

function Save-AssessmentBaseline {
    <#
    .SYNOPSIS
        Saves the current assessment results as a baseline.
    
    .PARAMETER Results
        The assessment results object to save as baseline.
    
    .PARAMETER SecurityScore
        The security score object from the assessment.
    
    .PARAMETER CISCompliance
        The CIS compliance object from the assessment.
    
    .PARAMETER BaselinePath
        Path where the baseline file should be saved.
    
    .PARAMETER BaselineName
        Optional name/label for the baseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$SecurityScore,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CISCompliance,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath,
        
        [Parameter(Mandatory = $false)]
        [string]$BaselineName = "Baseline"
    )
    
    try {
        $baseline = [PSCustomObject]@{
            Version = "1.0"
            Name = $BaselineName
            CreatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            CreatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            TenantId = $script:TenantId
            
            # Summary metrics
            Summary = [PSCustomObject]@{
                TotalChecks = $Results.Count
                PassedCount = ($Results | Where-Object { $_.Status -eq "Pass" }).Count
                WarningCount = ($Results | Where-Object { $_.Status -eq "Warning" }).Count
                FailCount = ($Results | Where-Object { $_.Status -eq "Fail" }).Count
                InfoCount = ($Results | Where-Object { $_.Status -eq "Info" }).Count
                CriticalCount = ($Results | Where-Object { $_.Severity -eq "Critical" -and $_.Status -in @("Fail", "Warning") }).Count
                HighCount = ($Results | Where-Object { $_.Severity -eq "High" -and $_.Status -in @("Fail", "Warning") }).Count
            }
            
            # Security Score
            SecurityScore = if ($SecurityScore) {
                [PSCustomObject]@{
                    Score = $SecurityScore.Score
                    Grade = $SecurityScore.Grade
                    Categories = $SecurityScore.CategoryScores
                }
            } else { $null }
            
            # CIS Compliance
            CISCompliance = if ($CISCompliance) {
                [PSCustomObject]@{
                    Level1Percentage = $CISCompliance.Level1Percentage
                    Level2Percentage = $CISCompliance.Level2Percentage
                    Level1Compliant = $CISCompliance.Level1Compliant
                    Level1Total = $CISCompliance.Level1Total
                    Level2Compliant = $CISCompliance.Level2Compliant
                    Level2Total = $CISCompliance.Level2Total
                }
            } else { $null }
            
            # Individual check results (normalized for comparison)
            Checks = $Results | ForEach-Object {
                [PSCustomObject]@{
                    CheckName = $_.CheckName
                    Category = $_.Category
                    Status = $_.Status
                    Severity = $_.Severity
                    Message = $_.Message
                    # Create a hash for quick comparison
                    CheckHash = [System.BitConverter]::ToString(
                        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                            [System.Text.Encoding]::UTF8.GetBytes("$($_.CheckName)|$($_.Category)")
                        )
                    ).Replace("-", "").Substring(0, 16)
                }
            }
        }
        
        # Save to file
        $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $BaselinePath -Encoding UTF8 -Force
        
        return [PSCustomObject]@{
            Success = $true
            Path = $BaselinePath
            Name = $BaselineName
            CheckCount = $Results.Count
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-LatestBaseline {
    <#
    .SYNOPSIS
        Gets the most recent baseline file from the baselines directory.
    
    .PARAMETER BaselinePath
        Path to the baselines directory.
    
    .OUTPUTS
        Path to the latest baseline file, or $null if no baselines exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BaselinePath = (Join-Path $PSScriptRoot "..\..\baselines")
    )
    
    try {
        if (-not (Test-Path $BaselinePath)) {
            return $null
        }
        
        $latestBaseline = Get-ChildItem -Path $BaselinePath -Filter "*.json" -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1
        
        if ($latestBaseline) {
            return $latestBaseline.FullName
        }
        
        return $null
    }
    catch {
        Write-Warning "Could not find latest baseline: $($_.Exception.Message)"
        return $null
    }
}

function Get-AssessmentBaseline {
    <#
    .SYNOPSIS
        Loads a previously saved baseline.
    
    .PARAMETER BaselinePath
        Path to the baseline file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselinePath
    )
    
    try {
        if (-not (Test-Path $BaselinePath)) {
            return [PSCustomObject]@{
                Success = $false
                Error = "Baseline file not found: $BaselinePath"
            }
        }
        
        $content = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
        
        # Validate baseline structure
        if (-not $content.Version -or -not $content.Checks) {
            return [PSCustomObject]@{
                Success = $false
                Error = "Invalid baseline file format"
            }
        }
        
        return [PSCustomObject]@{
            Success = $true
            Baseline = $content
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Compare-CheckChanges {
    <#
    .SYNOPSIS
        Compares individual check results between current and baseline assessments.
    
    .DESCRIPTION
        Analyzes assessment checks to identify improvements, regressions, unchanged items,
        new checks, and removed checks. Uses a priority system where Pass > Info > Warning > Fail.
    
    .PARAMETER CurrentResults
        Array of current assessment check results.
    
    .PARAMETER BaselineChecks
        Array of baseline check results.
    
    .OUTPUTS
        Hashtable with keys: Improvements, Regressions, Unchanged, NewChecks, RemovedChecks
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentResults,
        
        [Parameter(Mandatory = $true)]
        [array]$BaselineChecks
    )
    
    # Build lookup tables using composite key (CheckName|Category)
    $baselineHash = @{}
    foreach ($check in $BaselineChecks) {
        $key = "$($check.CheckName)|$($check.Category)"
        $baselineHash[$key] = $check
    }
    
    $currentHash = @{}
    foreach ($result in $CurrentResults) {
        $key = "$($result.CheckName)|$($result.Category)"
        $currentHash[$key] = $result
    }
    
    # Status priority for comparison (higher = better)
    # Pass=4: Check passed, no issues
    # Info=3: Informational, not a failure
    # Warning=2: Potential issue, needs attention
    # Fail=1: Check failed, security risk
    $statusPriority = @{
        "Pass" = 4
        "Info" = 3
        "Warning" = 2
        "Fail" = 1
    }
    
    $improvements = @()
    $regressions = @()
    $unchanged = @()
    $newChecks = @()
    $removedChecks = @()
    
    # Compare current checks against baseline
    foreach ($key in $currentHash.Keys) {
        $current = $currentHash[$key]
        
        if ($baselineHash.ContainsKey($key)) {
            $baselineCheck = $baselineHash[$key]
            $currentPriority = $statusPriority[$current.Status]
            $baselinePriority = $statusPriority[$baselineCheck.Status]
            
            if ($currentPriority -gt $baselinePriority) {
                # Check improved (e.g., Fail → Pass)
                $improvements += [PSCustomObject]@{
                    CheckName = $current.CheckName
                    Category = $current.Category
                    PreviousStatus = $baselineCheck.Status
                    CurrentStatus = $current.Status
                    PreviousSeverity = $baselineCheck.Severity
                    CurrentSeverity = $current.Severity
                    Change = "Improved"
                    Impact = if ($current.Status -eq "Pass" -and $baselineCheck.Status -eq "Fail") { "Major" } else { "Minor" }
                }
            }
            elseif ($currentPriority -lt $baselinePriority) {
                # Check regressed (e.g., Pass → Fail)
                $regressions += [PSCustomObject]@{
                    CheckName = $current.CheckName
                    Category = $current.Category
                    PreviousStatus = $baselineCheck.Status
                    CurrentStatus = $current.Status
                    PreviousSeverity = $baselineCheck.Severity
                    CurrentSeverity = $current.Severity
                    Change = "Regressed"
                    Impact = if ($current.Status -eq "Fail" -and $baselineCheck.Status -eq "Pass") { "Major" } else { "Minor" }
                }
            }
            else {
                # No change in status
                $unchanged += [PSCustomObject]@{
                    CheckName = $current.CheckName
                    Category = $current.Category
                    Status = $current.Status
                    Severity = $current.Severity
                }
            }
        }
        else {
            # New check not in baseline
            $newChecks += [PSCustomObject]@{
                CheckName = $current.CheckName
                Category = $current.Category
                Status = $current.Status
                Severity = $current.Severity
            }
        }
    }
    
    # Find removed checks (in baseline but not in current)
    foreach ($key in $baselineHash.Keys) {
        if (-not $currentHash.ContainsKey($key)) {
            $baselineCheck = $baselineHash[$key]
            $removedChecks += [PSCustomObject]@{
                CheckName = $baselineCheck.CheckName
                Category = $baselineCheck.Category
                Status = $baselineCheck.Status
                Severity = $baselineCheck.Severity
            }
        }
    }
    
    return @{
        Improvements = $improvements
        Regressions = $regressions
        Unchanged = $unchanged
        NewChecks = $newChecks
        RemovedChecks = $removedChecks
    }
}

function Compare-AssessmentToBaseline {
    <#
    .SYNOPSIS
        Compares current assessment results against a baseline.
    
    .PARAMETER CurrentResults
        The current assessment results.
    
    .PARAMETER CurrentSecurityScore
        The current security score.
    
    .PARAMETER CurrentCISCompliance
        The current CIS compliance results.
    
    .PARAMETER Baseline
        The baseline object to compare against.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CurrentSecurityScore,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CurrentCISCompliance,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Baseline
    )
    
    # Compare individual checks
    $checkComparison = Compare-CheckChanges -CurrentResults $CurrentResults -BaselineChecks $Baseline.Checks
    $improvements = $checkComparison.Improvements
    $regressions = $checkComparison.Regressions
    $unchanged = $checkComparison.Unchanged
    $newChecks = $checkComparison.NewChecks
    $removedChecks = $checkComparison.RemovedChecks
    
    # Calculate score deltas
    $scoreComparison = $null
    if ($CurrentSecurityScore -and $Baseline.SecurityScore) {
        $scoreDelta = [math]::Round($CurrentSecurityScore.Score - $Baseline.SecurityScore.Score, 1)
        
        # Compare categories
        $categoryComparisons = @()
        if ($CurrentSecurityScore.CategoryScores -and $Baseline.SecurityScore.Categories) {
            foreach ($cat in $CurrentSecurityScore.CategoryScores) {
                $baselineCat = $Baseline.SecurityScore.Categories | Where-Object { $_.Category -eq $cat.Category }
                if ($baselineCat) {
                    $catDelta = [math]::Round($cat.Score - $baselineCat.Score, 1)
                    $categoryComparisons += [PSCustomObject]@{
                        Category = $cat.Category
                        CurrentScore = $cat.Score
                        BaselineScore = $baselineCat.Score
                        Delta = $catDelta
                        Trend = if ($catDelta -gt 0) { "↑" } elseif ($catDelta -lt 0) { "↓" } else { "→" }
                    }
                }
            }
        }
        
        $scoreComparison = [PSCustomObject]@{
            CurrentScore = $CurrentSecurityScore.Score
            BaselineScore = $Baseline.SecurityScore.Score
            Delta = $scoreDelta
            CurrentGrade = $CurrentSecurityScore.Grade
            BaselineGrade = $Baseline.SecurityScore.Grade
            Trend = if ($scoreDelta -gt 0) { "Improving" } elseif ($scoreDelta -lt 0) { "Declining" } else { "Stable" }
            TrendIcon = if ($scoreDelta -gt 0) { "↑" } elseif ($scoreDelta -lt 0) { "↓" } else { "→" }
            CategoryComparisons = $categoryComparisons
        }
    }
    
    # CIS compliance comparison
    $cisComparison = $null
    if ($CurrentCISCompliance -and $Baseline.CISCompliance) {
        $l1Delta = [math]::Round($CurrentCISCompliance.Level1Percentage - $Baseline.CISCompliance.Level1Percentage, 1)
        $l2Delta = [math]::Round($CurrentCISCompliance.Level2Percentage - $Baseline.CISCompliance.Level2Percentage, 1)
        
        $cisComparison = [PSCustomObject]@{
            Level1 = [PSCustomObject]@{
                Current = $CurrentCISCompliance.Level1Percentage
                Baseline = $Baseline.CISCompliance.Level1Percentage
                Delta = $l1Delta
                Trend = if ($l1Delta -gt 0) { "↑" } elseif ($l1Delta -lt 0) { "↓" } else { "→" }
            }
            Level2 = [PSCustomObject]@{
                Current = $CurrentCISCompliance.Level2Percentage
                Baseline = $Baseline.CISCompliance.Level2Percentage
                Delta = $l2Delta
                Trend = if ($l2Delta -gt 0) { "↑" } elseif ($l2Delta -lt 0) { "↓" } else { "→" }
            }
        }
    }
    
    # Calculate days since baseline safely
    $daysSinceBaseline = 0
    try {
        if ($Baseline.CreatedAt) {
            $baselineDateTime = [datetime]::Parse($Baseline.CreatedAt)
            $daysSinceBaseline = [math]::Round(((Get-Date) - $baselineDateTime).TotalDays, 0)
        }
    }
    catch {
        $daysSinceBaseline = 0
    }
    
    # Build summary
    $comparison = [PSCustomObject]@{
        BaselineName = $Baseline.Name
        BaselineDate = $Baseline.CreatedAt
        ComparisonDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        DaysSinceBaseline = $daysSinceBaseline
        
        # Summary counts
        Summary = [PSCustomObject]@{
            TotalImprovements = $improvements.Count
            TotalRegressions = $regressions.Count
            TotalUnchanged = $unchanged.Count
            TotalChanges = $improvements.Count + $regressions.Count
            TotalChecksCompared = $improvements.Count + $regressions.Count + $unchanged.Count
            NewChecks = $newChecks.Count
            RemovedChecks = $removedChecks.Count
            MajorImprovements = ($improvements | Where-Object { $_.Impact -eq "Major" }).Count
            MajorRegressions = ($regressions | Where-Object { $_.Impact -eq "Major" }).Count
        }
        
        # Baseline summary for reference
        BaselineSummary = $Baseline.Summary
        
        # Current summary
        CurrentSummary = [PSCustomObject]@{
            TotalChecks = $CurrentResults.Count
            PassedCount = ($CurrentResults | Where-Object { $_.Status -eq "Pass" }).Count
            WarningCount = ($CurrentResults | Where-Object { $_.Status -eq "Warning" }).Count
            FailCount = ($CurrentResults | Where-Object { $_.Status -eq "Fail" }).Count
            InfoCount = ($CurrentResults | Where-Object { $_.Status -eq "Info" }).Count
        }
        
        # Score comparison
        SecurityScoreComparison = $scoreComparison
        
        # CIS comparison
        CISComplianceComparison = $cisComparison
        
        # Detailed changes
        Improvements = $improvements
        Regressions = $regressions
        Unchanged = $unchanged
        NewChecks = $newChecks
        RemovedChecks = $removedChecks
        
        # Overall trend
        OverallTrend = if ($improvements.Count -gt $regressions.Count) {
            "Improving"
        } elseif ($regressions.Count -gt $improvements.Count) {
            "Declining"
        } else {
            "Stable"
        }
    }
    
    return $comparison
}

function Format-BaselineComparison {
    <#
    .SYNOPSIS
        Formats the baseline comparison for console output.
    
    .PARAMETER Comparison
        The comparison object from Compare-AssessmentToBaseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Comparison
    )
    
    $output = @()
    
    # Header
    $output += ""
    $output += "╔══════════════════════════════════════════════════════════════════════╗"
    $output += "║              BASELINE COMPARISON                                     ║"
    $output += "╚══════════════════════════════════════════════════════════════════════╝"
    $output += ""
    $output += "  Baseline: $($Comparison.BaselineName) ($($Comparison.BaselineDate))"
    $output += "  Days since baseline: $($Comparison.DaysSinceBaseline)"
    $output += ""
    
    # Overall trend
    $trendIcon = switch ($Comparison.OverallTrend) {
        "Improving" { "↑" }
        "Declining" { "↓" }
        default { "→" }
    }
    $trendColor = switch ($Comparison.OverallTrend) {
        "Improving" { "Green" }
        "Declining" { "Red" }
        default { "Yellow" }
    }
    
    $output += "  ┌─────────────────────────────────────────────────────────────────┐"
    $output += "  │  OVERALL TREND: $trendIcon $($Comparison.OverallTrend.ToUpper().PadRight(45))│"
    $output += "  ├─────────────────────────────────────────────────────────────────┤"
    $output += "  │  Improvements: $($Comparison.Summary.TotalImprovements.ToString().PadRight(5)) ($($Comparison.Summary.MajorImprovements) major)                           │"
    $output += "  │  Regressions:  $($Comparison.Summary.TotalRegressions.ToString().PadRight(5)) ($($Comparison.Summary.MajorRegressions) major)                           │"
    $output += "  │  Unchanged:    $($Comparison.Summary.TotalUnchanged.ToString().PadRight(48))│"
    $output += "  └─────────────────────────────────────────────────────────────────┘"
    $output += ""
    
    # Security Score comparison
    if ($Comparison.SecurityScoreComparison) {
        $sc = $Comparison.SecurityScoreComparison
        $deltaStr = if ($sc.Delta -gt 0) { "+$($sc.Delta)%" } elseif ($sc.Delta -lt 0) { "$($sc.Delta)%" } else { "0%" }
        
        $output += "  Security Score:"
        $output += "    Baseline: $($sc.BaselineScore)% (Grade $($sc.BaselineGrade)) → Current: $($sc.CurrentScore)% (Grade $($sc.CurrentGrade))"
        $output += "    Change: $($sc.TrendIcon) $deltaStr"
        $output += ""
        
        if ($sc.CategoryComparisons -and $sc.CategoryComparisons.Count -gt 0) {
            $output += "  Category Changes:"
            foreach ($cat in $sc.CategoryComparisons) {
                $catDelta = if ($cat.Delta -gt 0) { "+$($cat.Delta)%" } elseif ($cat.Delta -lt 0) { "$($cat.Delta)%" } else { "0%" }
                $output += "    $($cat.Trend) $($cat.Category.PadRight(25)) $($cat.BaselineScore)% → $($cat.CurrentScore)% ($catDelta)"
            }
            $output += ""
        }
    }
    
    # CIS comparison
    if ($Comparison.CISComplianceComparison) {
        $cis = $Comparison.CISComplianceComparison
        $l1Delta = if ($cis.Level1.Delta -gt 0) { "+$($cis.Level1.Delta)%" } elseif ($cis.Level1.Delta -lt 0) { "$($cis.Level1.Delta)%" } else { "0%" }
        $l2Delta = if ($cis.Level2.Delta -gt 0) { "+$($cis.Level2.Delta)%" } elseif ($cis.Level2.Delta -lt 0) { "$($cis.Level2.Delta)%" } else { "0%" }
        
        $output += "  CIS Benchmark Compliance:"
        $output += "    Level 1: $($cis.Level1.Trend) $($cis.Level1.Baseline)% → $($cis.Level1.Current)% ($l1Delta)"
        $output += "    Level 2: $($cis.Level2.Trend) $($cis.Level2.Baseline)% → $($cis.Level2.Current)% ($l2Delta)"
        $output += ""
    }
    
    # Improvements
    if ($Comparison.Improvements.Count -gt 0) {
        $output += "  ✓ Improvements ($($Comparison.Improvements.Count)):"
        foreach ($imp in ($Comparison.Improvements | Select-Object -First 5)) {
            $output += "    • $($imp.CheckName): $($imp.PreviousStatus) → $($imp.CurrentStatus)"
        }
        if ($Comparison.Improvements.Count -gt 5) {
            $output += "    ... and $($Comparison.Improvements.Count - 5) more"
        }
        $output += ""
    }
    
    # Regressions
    if ($Comparison.Regressions.Count -gt 0) {
        $output += "  ✗ Regressions ($($Comparison.Regressions.Count)):"
        foreach ($reg in ($Comparison.Regressions | Select-Object -First 5)) {
            $output += "    • $($reg.CheckName): $($reg.PreviousStatus) → $($reg.CurrentStatus)"
        }
        if ($Comparison.Regressions.Count -gt 5) {
            $output += "    ... and $($Comparison.Regressions.Count - 5) more"
        }
        $output += ""
    }
    
    return $output -join "`n"
}

# Functions are automatically available when dot-sourced
