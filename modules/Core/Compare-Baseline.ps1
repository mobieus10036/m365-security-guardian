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

#region Module Constants

# Assessment check status values
$script:STATUS_PASS = "Pass"
$script:STATUS_INFO = "Info"
$script:STATUS_WARNING = "Warning"
$script:STATUS_FAIL = "Fail"

# Change impact levels
$script:IMPACT_MAJOR = "Major"
$script:IMPACT_MINOR = "Minor"

# Trend indicators
$script:TREND_IMPROVING = "Improving"
$script:TREND_DECLINING = "Declining"
$script:TREND_STABLE = "Stable"

# Status priority for comparison (higher = better)
# Used to determine if a check has improved, regressed, or remained unchanged
$script:STATUS_PRIORITY = @{
    $script:STATUS_PASS = 4      # Check passed, no security issues
    $script:STATUS_INFO = 3       # Informational, not a failure
    $script:STATUS_WARNING = 2    # Potential issue, needs attention
    $script:STATUS_FAIL = 1       # Check failed, security risk
}

#endregion

function Get-TrendIcon {
    <#
    .SYNOPSIS
        Calculates the trend icon based on delta value.
    
    .PARAMETER Delta
        The change value (current minus baseline).
        Positive values return "↑" (improving)
        Negative values return "↓" (declining)
        Zero returns "→" (stable)
    
    .OUTPUTS
        System.String - A single character trend icon
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [decimal]$Delta
    )
    
    if ($null -eq $Delta) {
        return "→"
    }
    
    if ($Delta -gt 0) {
        return "↑"
    }
    elseif ($Delta -lt 0) {
        return "↓"
    }
    else {
        return "→"
    }
}

function Save-AssessmentBaseline {
    <#
    .SYNOPSIS
        Saves the current assessment results as a baseline.
    
    .PARAMETER Results
        The assessment results object to save as baseline. Must not be empty.
    
    .PARAMETER SecurityScore
        The security score object from the assessment.
    
    .PARAMETER CISCompliance
        The CIS compliance object from the assessment.
    
    .PARAMETER BaselinePath
        Path where the baseline file should be saved. Must be a valid path.
    
    .PARAMETER BaselineName
        Optional name/label for the baseline.
    
    .PARAMETER TenantId
        The tenant ID for the baseline. If not provided, uses $script:TenantId from parent scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$Results,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$SecurityScore,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CISCompliance,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaselinePath,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$BaselineName = "Baseline",
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId = $script:TenantId
    )
    
    # Validate that Results is not empty
    if ($Results.Count -eq 0) {
        return [PSCustomObject]@{
            Success = $false
            Error = "Results array is empty"
        }
    }
    
    # Validate parent directory exists or can be created
    $parentDir = Split-Path -Parent $BaselinePath
    if (-not (Test-Path $parentDir)) {
        try {
            New-Item -ItemType Directory -Path $parentDir -Force -ErrorAction Stop | Out-Null
        }
        catch {
            return [PSCustomObject]@{
                Success = $false
                Error = "Cannot create baseline directory: $($_.Exception.Message)"
            }
        }
    }
    
    try {
        $baseline = [PSCustomObject]@{
            Version = "1.0"
            Name = $BaselineName
            CreatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            CreatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            TenantId = $TenantId
            
            # Summary metrics
            Summary = [PSCustomObject]@{
                TotalChecks = $Results.Count
                PassedCount = ($Results | Where-Object { $_.Status -eq $script:STATUS_PASS }).Count
                WarningCount = ($Results | Where-Object { $_.Status -eq $script:STATUS_WARNING }).Count
                FailCount = ($Results | Where-Object { $_.Status -eq $script:STATUS_FAIL }).Count
                InfoCount = ($Results | Where-Object { $_.Status -eq $script:STATUS_INFO }).Count
                CriticalCount = ($Results | Where-Object { $_.Severity -eq "Critical" -and $_.Status -in @($script:STATUS_FAIL, $script:STATUS_WARNING) }).Count
                HighCount = ($Results | Where-Object { $_.Severity -eq "High" -and $_.Status -in @($script:STATUS_FAIL, $script:STATUS_WARNING) }).Count
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

function Get-LatestBaselinePath {
    <#
    .SYNOPSIS
        Gets the most recent baseline file path from the baselines directory.
    
    .PARAMETER BaselinePath
        Path to the baselines directory.
    
    .OUTPUTS
        String: Full path to the latest baseline file, or $null if no baselines exist.
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
        Array of current assessment check results. Must not be empty.
    
    .PARAMETER BaselineChecks
        Array of baseline check results. Must not be null.
    
    .OUTPUTS
        Hashtable with keys: Improvements, Regressions, Unchanged, NewChecks, RemovedChecks
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$CurrentResults,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$BaselineChecks
    )
    
    # Validate baseline structure
    if ($null -eq $BaselineChecks -or $BaselineChecks.Count -eq 0) {
        throw "BaselineChecks cannot be null or empty"
    }
    
    if ($null -eq $CurrentResults -or $CurrentResults.Count -eq 0) {
        throw "CurrentResults cannot be null or empty"
    }
    
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
    
    # Use module-level status priority mapping
    $statusPriority = $script:STATUS_PRIORITY
    
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
                    Impact = if ($current.Status -eq $script:STATUS_PASS -and $baselineCheck.Status -eq $script:STATUS_FAIL) { $script:IMPACT_MAJOR } else { $script:IMPACT_MINOR }
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
                    Impact = if ($current.Status -eq $script:STATUS_FAIL -and $baselineCheck.Status -eq $script:STATUS_PASS) { $script:IMPACT_MAJOR } else { $script:IMPACT_MINOR }
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
        The current assessment results. Must not be empty.
    
    .PARAMETER CurrentSecurityScore
        The current security score.
    
    .PARAMETER CurrentCISCompliance
        The current CIS compliance results.
    
    .PARAMETER Baseline
        The baseline object to compare against. Must be valid with Checks array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$CurrentResults,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CurrentSecurityScore,
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CurrentCISCompliance,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$Baseline
    )
    
    # Validate baseline structure
    if ($null -eq $Baseline.Checks -or $Baseline.Checks.Count -eq 0) {
        throw "Baseline must contain a valid Checks array"
    }
    
    if ($null -eq $Baseline.Name) {
        throw "Baseline must have a Name property"
    }
    
    if ($CurrentResults.Count -eq 0) {
        throw "CurrentResults cannot be empty"
    }
    
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
            foreach ($category in $CurrentSecurityScore.CategoryScores) {
                $baselineCategory = $Baseline.SecurityScore.Categories | Where-Object { $_.Category -eq $category.Category }
                if ($baselineCategory) {
                    $categoryDelta = [math]::Round($category.Score - $baselineCategory.Score, 1)
                    $categoryComparisons += [PSCustomObject]@{
                        Category = $category.Category
                        CurrentScore = $category.Score
                        BaselineScore = $baselineCategory.Score
                        Delta = $categoryDelta
                        Trend = Get-TrendIcon -Delta $categoryDelta
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
            Trend = if ($scoreDelta -gt 0) { $script:TREND_IMPROVING } elseif ($scoreDelta -lt 0) { $script:TREND_DECLINING } else { $script:TREND_STABLE }
            TrendIcon = Get-TrendIcon -Delta $scoreDelta
            CategoryComparisons = $categoryComparisons
        }
    }
    
    # CIS compliance comparison
    $cisComparison = $null
    if ($CurrentCISCompliance -and $Baseline.CISCompliance) {
        $level1Delta = [math]::Round($CurrentCISCompliance.Level1Percentage - $Baseline.CISCompliance.Level1Percentage, 1)
        $level2Delta = [math]::Round($CurrentCISCompliance.Level2Percentage - $Baseline.CISCompliance.Level2Percentage, 1)
        
        $cisComparison = [PSCustomObject]@{
            Level1 = [PSCustomObject]@{
                Current = $CurrentCISCompliance.Level1Percentage
                Baseline = $Baseline.CISCompliance.Level1Percentage
                Delta = $level1Delta
                Trend = Get-TrendIcon -Delta $level1Delta
            }
            Level2 = [PSCustomObject]@{
                Current = $CurrentCISCompliance.Level2Percentage
                Baseline = $Baseline.CISCompliance.Level2Percentage
                Delta = $level2Delta
                Trend = Get-TrendIcon -Delta $level2Delta
            }
        }
    }
    
    # Calculate days since baseline safely
    $daysSinceBaseline = 0
    try {
        if ($null -ne $Baseline.CreatedAt -and -not [string]::IsNullOrWhiteSpace($Baseline.CreatedAt)) {
            $baselineDateTime = [datetime]::Parse($Baseline.CreatedAt)
            $daysSinceBaseline = [math]::Round(((Get-Date) - $baselineDateTime).TotalDays, 0)
        }
    }
    catch {
        Write-Warning "Could not parse baseline CreatedAt date '$($Baseline.CreatedAt)'. Setting days to 0."
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
            MajorImprovements = ($improvements | Where-Object { $_.Impact -eq $script:IMPACT_MAJOR }).Count
            MajorRegressions = ($regressions | Where-Object { $_.Impact -eq $script:IMPACT_MAJOR }).Count
        }
        
        # Baseline summary for reference
        BaselineSummary = $Baseline.Summary
        
        # Current summary
        CurrentSummary = [PSCustomObject]@{
            TotalChecks = $CurrentResults.Count
            PassedCount = ($CurrentResults | Where-Object { $_.Status -eq $script:STATUS_PASS }).Count
            WarningCount = ($CurrentResults | Where-Object { $_.Status -eq $script:STATUS_WARNING }).Count
            FailCount = ($CurrentResults | Where-Object { $_.Status -eq $script:STATUS_FAIL }).Count
            InfoCount = ($CurrentResults | Where-Object { $_.Status -eq $script:STATUS_INFO }).Count
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
            $script:TREND_IMPROVING
        } elseif ($regressions.Count -gt $improvements.Count) {
            $script:TREND_DECLINING
        } else {
            $script:TREND_STABLE
        }
    }
    
    return $comparison
}

function Format-DeltaString {
    <#
    .SYNOPSIS
        Formats a delta value as a string with + or - prefix.
    
    .PARAMETER Delta
        The delta value to format.
    
    .OUTPUTS
        System.String - Formatted delta string (e.g., "+5%", "-3%", "0%")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [decimal]$Delta
    )
    
    if ($null -eq $Delta) {
        return "0%"
    }
    
    if ($Delta -gt 0) {
        return "+$($Delta)%"
    }
    elseif ($Delta -lt 0) {
        return "$($Delta)%"
    }
    else {
        return "0%"
    }
}

function Format-ComparisonHeader {
    <#
    .SYNOPSIS
        Formats the header section of the baseline comparison.
    
    .PARAMETER BaselineName
        Name of the baseline.
    
    .PARAMETER BaselineDate
        Date of the baseline.
    
    .PARAMETER DaysSinceBaseline
        Number of days since the baseline was created.
    
    .OUTPUTS
        System.String[] - Array of formatted header lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineName,
        
        [Parameter(Mandatory = $true)]
        [string]$BaselineDate,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysSinceBaseline
    )
    
    $output = @()
    $output += ""
    $output += "╔══════════════════════════════════════════════════════════════════════╗"
    $output += "║              BASELINE COMPARISON                                     ║"
    $output += "╚══════════════════════════════════════════════════════════════════════╝"
    $output += ""
    $output += "  Baseline: $BaselineName ($BaselineDate)"
    $output += "  Days since baseline: $DaysSinceBaseline"
    $output += ""
    
    return $output
}

function Format-OverallTrendSection {
    <#
    .SYNOPSIS
        Formats the overall trend summary box.
    
    .PARAMETER OverallTrend
        The overall trend (Improving, Declining, Stable).
    
    .PARAMETER Summary
        The summary object containing improvement/regression counts.
    
    .OUTPUTS
        System.String[] - Array of formatted trend section lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OverallTrend,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Summary
    )
    
    $trendIcon = switch ($OverallTrend) {
        $script:TREND_IMPROVING { "↑" }
        $script:TREND_DECLINING { "↓" }
        default { "→" }
    }
    
    $output = @()
    $output += "  ┌─────────────────────────────────────────────────────────────────┐"
    $output += "  │  OVERALL TREND: $trendIcon $($OverallTrend.ToUpper().PadRight(45))│"
    $output += "  ├─────────────────────────────────────────────────────────────────┤"
    $output += "  │  Improvements: $($Summary.TotalImprovements.ToString().PadRight(5)) ($($Summary.MajorImprovements) major)                           │"
    $output += "  │  Regressions:  $($Summary.TotalRegressions.ToString().PadRight(5)) ($($Summary.MajorRegressions) major)                           │"
    $output += "  │  Unchanged:    $($Summary.TotalUnchanged.ToString().PadRight(48))│"
    $output += "  └─────────────────────────────────────────────────────────────────┘"
    $output += ""
    
    return $output
}

function Format-SecurityScoreSection {
    <#
    .SYNOPSIS
        Formats the security score comparison section.
    
    .PARAMETER SecurityScoreComparison
        The security score comparison object.
    
    .OUTPUTS
        System.String[] - Array of formatted security score lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$SecurityScoreComparison
    )
    
    if (-not $SecurityScoreComparison) {
        return @()
    }
    
    $output = @()
    $deltaStr = Format-DeltaString -Delta $SecurityScoreComparison.Delta
    
    $output += "  Security Score:"
    $output += "    Baseline: $($SecurityScoreComparison.BaselineScore)% (Grade $($SecurityScoreComparison.BaselineGrade)) → Current: $($SecurityScoreComparison.CurrentScore)% (Grade $($SecurityScoreComparison.CurrentGrade))"
    $output += "    Change: $($SecurityScoreComparison.TrendIcon) $deltaStr"
    $output += ""
    
    if ($SecurityScoreComparison.CategoryComparisons -and $SecurityScoreComparison.CategoryComparisons.Count -gt 0) {
        $output += "  Category Changes:"
        foreach ($category in $SecurityScoreComparison.CategoryComparisons) {
            $categoryDelta = Format-DeltaString -Delta $category.Delta
            $output += "    $($category.Trend) $($category.Category.PadRight(25)) $($category.BaselineScore)% → $($category.CurrentScore)% ($categoryDelta)"
        }
        $output += ""
    }
    
    return $output
}

function Format-CISComplianceSection {
    <#
    .SYNOPSIS
        Formats the CIS compliance comparison section.
    
    .PARAMETER CISComplianceComparison
        The CIS compliance comparison object.
    
    .OUTPUTS
        System.String[] - Array of formatted CIS compliance lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CISComplianceComparison
    )
    
    if (-not $CISComplianceComparison) {
        return @()
    }
    
    $output = @()
    $level1Delta = Format-DeltaString -Delta $CISComplianceComparison.Level1.Delta
    $level2Delta = Format-DeltaString -Delta $CISComplianceComparison.Level2.Delta
    
    $output += "  CIS Benchmark Compliance:"
    $output += "    Level 1: $($CISComplianceComparison.Level1.Trend) $($CISComplianceComparison.Level1.Baseline)% → $($CISComplianceComparison.Level1.Current)% ($level1Delta)"
    $output += "    Level 2: $($CISComplianceComparison.Level2.Trend) $($CISComplianceComparison.Level2.Baseline)% → $($CISComplianceComparison.Level2.Current)% ($level2Delta)"
    $output += ""
    
    return $output
}

function Format-ChangesSection {
    <#
    .SYNOPSIS
        Formats a list of improvements or regressions.
    
    .PARAMETER Changes
        Array of change objects (improvements or regressions).
    
    .PARAMETER Title
        Section title (e.g., "Improvements" or "Regressions").
    
    .PARAMETER Icon
        Icon to display (e.g., "✓" or "✗").
    
    .OUTPUTS
        System.String[] - Array of formatted change lines
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Changes,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$Icon
    )
    
    if ($Changes.Count -eq 0) {
        return @()
    }
    
    $output = @()
    $output += "  $Icon $Title ($($Changes.Count)):"
    
    foreach ($change in ($Changes | Select-Object -First 5)) {
        $output += "    • $($change.CheckName): $($change.PreviousStatus) → $($change.CurrentStatus)"
    }
    
    if ($Changes.Count -gt 5) {
        $output += "    ... and $($Changes.Count - 5) more"
    }
    
    $output += ""
    
    return $output
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
    
    $sections = @()
    
    # Build each section using helper functions
    $sections += Format-ComparisonHeader -BaselineName $Comparison.BaselineName -BaselineDate $Comparison.BaselineDate -DaysSinceBaseline $Comparison.DaysSinceBaseline
    $sections += Format-OverallTrendSection -OverallTrend $Comparison.OverallTrend -Summary $Comparison.Summary
    $sections += Format-SecurityScoreSection -SecurityScoreComparison $Comparison.SecurityScoreComparison
    $sections += Format-CISComplianceSection -CISComplianceComparison $Comparison.CISComplianceComparison
    $sections += Format-ChangesSection -Changes $Comparison.Improvements -Title "Improvements" -Icon "✓"
    $sections += Format-ChangesSection -Changes $Comparison.Regressions -Title "Regressions" -Icon "✗"
    
    return $sections -join "`n"
}

# Functions are automatically available when dot-sourced
