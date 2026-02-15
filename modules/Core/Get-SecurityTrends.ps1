<#
.SYNOPSIS
    Security trend tracking module for M365 Security Guardian.

.DESCRIPTION
    Provides functionality to track security posture over time, detect
    regressions, calculate improvement rates, and generate trend visualizations.
    Extends the baseline comparison feature with multi-point historical analysis.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 1.0.0
    Phase: 4 - Historical Trend Tracking
#>

#region Module Constants

$script:HISTORY_FILE_NAME = "assessment-history.json"
$script:HISTORY_VERSION = "1.0"
$script:MAX_HISTORY_ENTRIES = 100  # Keep last 100 assessments
$script:TREND_WINDOW_DEFAULT = 30  # Days to analyze for trends

# Trend direction indicators
$script:TREND_IMPROVING = "Improving"
$script:TREND_DECLINING = "Declining"
$script:TREND_STABLE = "Stable"
$script:TREND_INSUFFICIENT_DATA = "InsufficientData"

# Regression severity thresholds
$script:REGRESSION_CRITICAL_THRESHOLD = -10  # Score drop of 10+ points
$script:REGRESSION_WARNING_THRESHOLD = -5    # Score drop of 5+ points

#endregion

#region History Store Functions

function Get-HistoryStorePath {
    <#
    .SYNOPSIS
        Returns the path to the assessment history store.
    
    .PARAMETER BasePath
        Base directory for storing history. Defaults to baselines folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BasePath
    )
    
    if (-not $BasePath) {
        $BasePath = Join-Path $PSScriptRoot "..\..\baselines"
    }
    
    return Join-Path $BasePath $script:HISTORY_FILE_NAME
}

function Get-AssessmentHistory {
    <#
    .SYNOPSIS
        Retrieves the assessment history from the store.
    
    .PARAMETER HistoryPath
        Path to the history file.
    
    .PARAMETER TenantId
        Filter history to a specific tenant.
    
    .PARAMETER DaysBack
        Only return entries from the last N days.
    
    .OUTPUTS
        PSCustomObject with History array and metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HistoryPath,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 0
    )
    
    if (-not $HistoryPath) {
        $HistoryPath = Get-HistoryStorePath
    }
    
    if (-not (Test-Path $HistoryPath)) {
        return [PSCustomObject]@{
            Version = $script:HISTORY_VERSION
            TenantId = $TenantId
            Entries = @()
            EntryCount = 0
            FirstAssessment = $null
            LastAssessment = $null
        }
    }
    
    try {
        $historyData = Get-Content $HistoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $entries = @($historyData.Entries)
        
        # Filter by tenant if specified
        if ($TenantId) {
            $entries = @($entries | Where-Object { $_.TenantId -eq $TenantId })
        }
        
        # Filter by date if specified
        if ($DaysBack -gt 0) {
            $cutoffDate = (Get-Date).AddDays(-$DaysBack)
            $entries = @($entries | Where-Object { 
                [datetime]$_.Timestamp -ge $cutoffDate 
            })
        }
        
        # Sort by timestamp descending (newest first)
        $entries = @($entries | Sort-Object { [datetime]$_.Timestamp } -Descending)
        
        return [PSCustomObject]@{
            Version = $historyData.Version
            TenantId = $TenantId
            Entries = $entries
            EntryCount = $entries.Count
            FirstAssessment = if ($entries.Count -gt 0) { $entries[-1].Timestamp } else { $null }
            LastAssessment = if ($entries.Count -gt 0) { $entries[0].Timestamp } else { $null }
        }
    }
    catch {
        Write-Warning "Failed to read assessment history: $_"
        return [PSCustomObject]@{
            Version = $script:HISTORY_VERSION
            TenantId = $TenantId
            Entries = @()
            EntryCount = 0
            FirstAssessment = $null
            LastAssessment = $null
            Error = $_.Exception.Message
        }
    }
}

function Save-AssessmentToHistory {
    <#
    .SYNOPSIS
        Saves the current assessment to the history store.
    
    .DESCRIPTION
        Appends a snapshot of the current assessment to the history file,
        enabling trend tracking over time. Automatically prunes old entries
        beyond MAX_HISTORY_ENTRIES.
    
    .PARAMETER Results
        The assessment results array.
    
    .PARAMETER SecurityScore
        The security score object.
    
    .PARAMETER CISCompliance
        The CIS compliance object.
    
    .PARAMETER AttackChains
        The attack chain analysis object.
    
    .PARAMETER TenantId
        The tenant ID being assessed.
    
    .PARAMETER TenantName
        The tenant display name.
    
    .PARAMETER HistoryPath
        Path to the history file.
    
    .OUTPUTS
        PSCustomObject with Success status and entry details.
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
        
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$AttackChains,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantName,
        
        [Parameter(Mandatory = $false)]
        [string]$HistoryPath
    )
    
    if (-not $HistoryPath) {
        $HistoryPath = Get-HistoryStorePath
    }
    
    # Ensure directory exists
    $historyDir = Split-Path -Parent $HistoryPath
    if (-not (Test-Path $historyDir)) {
        New-Item -ItemType Directory -Path $historyDir -Force | Out-Null
    }
    
    # Create the history entry
    $entry = [PSCustomObject]@{
        Id = [guid]::NewGuid().ToString()
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        TenantId = $TenantId
        TenantName = $TenantName
        
        # Core metrics for trending
        Metrics = [PSCustomObject]@{
            SecurityScore = if ($SecurityScore) { 
                # Support both OverallScore and Score property names
                if ($SecurityScore.OverallScore) { $SecurityScore.OverallScore } 
                elseif ($SecurityScore.Score) { $SecurityScore.Score }
                else { $null }
            } else { $null }
            Grade = if ($SecurityScore) { 
                if ($SecurityScore.LetterGrade) { $SecurityScore.LetterGrade }
                elseif ($SecurityScore.Grade) { $SecurityScore.Grade }
                else { $null }
            } else { $null }
            TotalChecks = $Results.Count
            PassedCount = ($Results | Where-Object { $_.Status -eq "Pass" }).Count
            WarningCount = ($Results | Where-Object { $_.Status -eq "Warning" }).Count
            FailedCount = ($Results | Where-Object { $_.Status -eq "Fail" }).Count
            CriticalFindings = ($Results | Where-Object { $_.Severity -eq "Critical" -and $_.Status -in @("Fail", "Warning") }).Count
            HighFindings = ($Results | Where-Object { $_.Severity -eq "High" -and $_.Status -in @("Fail", "Warning") }).Count
        }
        
        # CIS compliance metrics
        CISMetrics = if ($CISCompliance) {
            [PSCustomObject]@{
                Level1Percentage = $CISCompliance.Level1.Percentage
                Level2Percentage = $CISCompliance.Level2.Percentage
                Level1Compliant = $CISCompliance.Level1.Compliant
                Level1Total = $CISCompliance.Level1.Total
            }
        } else { $null }
        
        # Attack chain metrics
        AttackChainMetrics = if ($AttackChains) {
            [PSCustomObject]@{
                EnabledChainCount = @($AttackChains.EnabledChains).Count
                TotalChains = $AttackChains.Summary.TotalChains
                CriticalChains = $AttackChains.Summary.CriticalCount
                HighChains = $AttackChains.Summary.HighCount
                RiskLevel = $AttackChains.Summary.RiskLevel
            }
        } else { $null }
        
        # Category scores for detailed trending
        CategoryScores = if ($SecurityScore -and $SecurityScore.CategoryScores) {
            $SecurityScore.CategoryScores | ForEach-Object {
                [PSCustomObject]@{
                    Category = $_.Category
                    Score = $_.Score
                }
            }
        } else { @() }
        
        # Check-level status for regression detection
        CheckStatuses = $Results | ForEach-Object {
            [PSCustomObject]@{
                CheckName = $_.CheckName
                Status = $_.Status
                Severity = $_.Severity
            }
        }
    }
    
    try {
        # Load existing history or create new
        $history = if (Test-Path $HistoryPath) {
            Get-Content $HistoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } else {
            @{
                Version = $script:HISTORY_VERSION
                CreatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                LastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                Entries = @()
            }
        }
        
        # Convert Entries to array if needed
        $entries = @($history.Entries)
        
        # Add new entry at the beginning (newest first)
        $entries = @($entry) + $entries
        
        # Prune old entries
        if ($entries.Count -gt $script:MAX_HISTORY_ENTRIES) {
            $entries = $entries[0..($script:MAX_HISTORY_ENTRIES - 1)]
        }
        
        # Create new history object with updated entries
        $updatedHistory = @{
            Version = if ($history.Version) { $history.Version } else { $script:HISTORY_VERSION }
            CreatedAt = if ($history.CreatedAt) { $history.CreatedAt } else { (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") }
            LastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
            Entries = $entries
        }
        
        # Save to file
        $updatedHistory | ConvertTo-Json -Depth 20 | Set-Content $HistoryPath -Encoding UTF8
        
        return [PSCustomObject]@{
            Success = $true
            EntryId = $entry.Id
            Timestamp = $entry.Timestamp
            HistoryPath = $HistoryPath
            TotalEntries = $entries.Count
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region Trend Analysis Functions

function Get-SecurityTrends {
    <#
    .SYNOPSIS
        Analyzes security posture trends over time.
    
    .DESCRIPTION
        Calculates trend direction, rate of change, regression alerts,
        and progress metrics based on historical assessment data.
    
    .PARAMETER HistoryPath
        Path to the history file.
    
    .PARAMETER TenantId
        Filter to a specific tenant.
    
    .PARAMETER DaysBack
        Number of days to analyze. Default: 30.
    
    .PARAMETER CompareToFirst
        Compare current state to first recorded assessment.
    
    .OUTPUTS
        PSCustomObject with comprehensive trend analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HistoryPath,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$CompareToFirst
    )
    
    $history = Get-AssessmentHistory -HistoryPath $HistoryPath -TenantId $TenantId -DaysBack $DaysBack
    
    if ($history.EntryCount -lt 2) {
        return [PSCustomObject]@{
            TenantId = $TenantId
            AnalysisPeriod = "$DaysBack days"
            DataPoints = $history.EntryCount
            TrendStatus = $script:TREND_INSUFFICIENT_DATA
            Message = "Minimum 2 assessments required for trend analysis"
            HasSufficientData = $false
        }
    }
    
    $entries = $history.Entries
    $latestEntry = $entries[0]
    $comparisonEntry = if ($CompareToFirst) { $entries[-1] } else { $entries[1] }
    $oldestEntry = $entries[-1]
    
    # Calculate score trend
    $currentScore = $latestEntry.Metrics.SecurityScore
    $previousScore = $comparisonEntry.Metrics.SecurityScore
    $firstScore = $oldestEntry.Metrics.SecurityScore
    
    $scoreDelta = if ($null -ne $currentScore -and $null -ne $previousScore) {
        $currentScore - $previousScore
    } else { 0 }
    
    $totalImprovement = if ($null -ne $currentScore -and $null -ne $firstScore) {
        $currentScore - $firstScore
    } else { 0 }
    
    # Determine trend direction
    $trendDirection = if ($scoreDelta -gt 2) {
        $script:TREND_IMPROVING
    } elseif ($scoreDelta -lt -2) {
        $script:TREND_DECLINING
    } else {
        $script:TREND_STABLE
    }
    
    # Calculate regression alerts
    $regressions = Get-RegressionAlerts -LatestEntry $latestEntry -PreviousEntry $comparisonEntry
    
    # Calculate category trends
    $categoryTrends = Get-CategoryTrends -Entries $entries
    
    # Calculate velocity (rate of change)
    $velocity = Get-TrendVelocity -Entries $entries
    
    # Build timeline for charts
    $timeline = Get-TrendTimeline -Entries $entries
    
    return [PSCustomObject]@{
        TenantId = $TenantId
        TenantName = $latestEntry.TenantName
        AnalysisPeriod = "$DaysBack days"
        DataPoints = $history.EntryCount
        FirstAssessment = $history.FirstAssessment
        LastAssessment = $history.LastAssessment
        HasSufficientData = $true
        
        # Current state
        CurrentScore = $currentScore
        CurrentGrade = $latestEntry.Metrics.Grade
        
        # Trend summary
        TrendDirection = $trendDirection
        ScoreDelta = [math]::Round($scoreDelta, 1)
        TotalImprovement = [math]::Round($totalImprovement, 1)
        ImprovementRate = $velocity.DailyRate
        
        # Detailed metrics
        MetricsTrend = [PSCustomObject]@{
            PassedChecks = [PSCustomObject]@{
                Current = $latestEntry.Metrics.PassedCount
                Previous = $comparisonEntry.Metrics.PassedCount
                Delta = $latestEntry.Metrics.PassedCount - $comparisonEntry.Metrics.PassedCount
            }
            FailedChecks = [PSCustomObject]@{
                Current = $latestEntry.Metrics.FailedCount
                Previous = $comparisonEntry.Metrics.FailedCount
                Delta = $latestEntry.Metrics.FailedCount - $comparisonEntry.Metrics.FailedCount
            }
            CriticalFindings = [PSCustomObject]@{
                Current = $latestEntry.Metrics.CriticalFindings
                Previous = $comparisonEntry.Metrics.CriticalFindings
                Delta = $latestEntry.Metrics.CriticalFindings - $comparisonEntry.Metrics.CriticalFindings
            }
        }
        
        # Regressions
        Regressions = $regressions
        HasRegressions = @($regressions.Items).Count -gt 0
        RegressionSeverity = $regressions.OverallSeverity
        
        # Category breakdown
        CategoryTrends = $categoryTrends
        
        # Velocity metrics
        Velocity = $velocity
        
        # Chart data
        Timeline = $timeline
    }
}

function Get-RegressionAlerts {
    <#
    .SYNOPSIS
        Detects security regressions between assessments.
    
    .PARAMETER LatestEntry
        The most recent assessment entry.
    
    .PARAMETER PreviousEntry
        The previous assessment entry to compare against.
    
    .OUTPUTS
        PSCustomObject with regression details.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$LatestEntry,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$PreviousEntry
    )
    
    $regressions = @()
    
    # Score regression check
    $scoreDelta = $LatestEntry.Metrics.SecurityScore - $PreviousEntry.Metrics.SecurityScore
    if ($scoreDelta -le $script:REGRESSION_CRITICAL_THRESHOLD) {
        $regressions += [PSCustomObject]@{
            Type = "ScoreRegression"
            Severity = "Critical"
            Message = "Security score dropped by $([math]::Abs($scoreDelta)) points"
            CurrentValue = $LatestEntry.Metrics.SecurityScore
            PreviousValue = $PreviousEntry.Metrics.SecurityScore
            Delta = $scoreDelta
        }
    }
    elseif ($scoreDelta -le $script:REGRESSION_WARNING_THRESHOLD) {
        $regressions += [PSCustomObject]@{
            Type = "ScoreRegression"
            Severity = "Warning"
            Message = "Security score dropped by $([math]::Abs($scoreDelta)) points"
            CurrentValue = $LatestEntry.Metrics.SecurityScore
            PreviousValue = $PreviousEntry.Metrics.SecurityScore
            Delta = $scoreDelta
        }
    }
    
    # Check-level regressions (Pass -> Fail or Warning)
    $previousChecks = @{}
    foreach ($check in $PreviousEntry.CheckStatuses) {
        $previousChecks[$check.CheckName] = $check
    }
    
    foreach ($currentCheck in $LatestEntry.CheckStatuses) {
        $previousCheck = $previousChecks[$currentCheck.CheckName]
        if ($previousCheck) {
            # Detect regression: was Pass, now Fail or Warning
            if ($previousCheck.Status -eq "Pass" -and $currentCheck.Status -in @("Fail", "Warning")) {
                $severity = if ($currentCheck.Severity -eq "Critical") { "Critical" } 
                           elseif ($currentCheck.Severity -eq "High") { "High" }
                           else { "Medium" }
                
                $regressions += [PSCustomObject]@{
                    Type = "CheckRegression"
                    Severity = $severity
                    CheckName = $currentCheck.CheckName
                    Message = "$($currentCheck.CheckName) changed from Pass to $($currentCheck.Status)"
                    PreviousStatus = $previousCheck.Status
                    CurrentStatus = $currentCheck.Status
                    CheckSeverity = $currentCheck.Severity
                }
            }
        }
    }
    
    # Attack chain regressions
    if ($LatestEntry.AttackChainMetrics -and $PreviousEntry.AttackChainMetrics) {
        $chainDelta = $LatestEntry.AttackChainMetrics.EnabledChainCount - $PreviousEntry.AttackChainMetrics.EnabledChainCount
        if ($chainDelta -gt 0) {
            $regressions += [PSCustomObject]@{
                Type = "AttackChainRegression"
                Severity = if ($LatestEntry.AttackChainMetrics.CriticalChains -gt $PreviousEntry.AttackChainMetrics.CriticalChains) { "Critical" } else { "High" }
                Message = "$chainDelta new attack chain(s) enabled"
                CurrentValue = $LatestEntry.AttackChainMetrics.EnabledChainCount
                PreviousValue = $PreviousEntry.AttackChainMetrics.EnabledChainCount
                Delta = $chainDelta
            }
        }
    }
    
    # Determine overall severity
    $overallSeverity = "None"
    if (@($regressions | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0) {
        $overallSeverity = "Critical"
    }
    elseif (@($regressions | Where-Object { $_.Severity -eq "High" }).Count -gt 0) {
        $overallSeverity = "High"
    }
    elseif (@($regressions | Where-Object { $_.Severity -in @("Warning", "Medium") }).Count -gt 0) {
        $overallSeverity = "Warning"
    }
    
    return [PSCustomObject]@{
        Items = $regressions
        Count = $regressions.Count
        OverallSeverity = $overallSeverity
        HasRegressions = $regressions.Count -gt 0
        HasCritical = @($regressions | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0
        CriticalCount = @($regressions | Where-Object { $_.Severity -eq "Critical" }).Count
        HighCount = @($regressions | Where-Object { $_.Severity -eq "High" }).Count
        WarningCount = @($regressions | Where-Object { $_.Severity -in @("Warning", "Medium") }).Count
    }
}

function Get-CategoryTrends {
    <#
    .SYNOPSIS
        Calculates trends for each security category.
    
    .PARAMETER Entries
        Array of history entries (newest first).
    
    .OUTPUTS
        Array of category trend objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entries
    )
    
    if ($Entries.Count -lt 2) {
        return @()
    }
    
    $latestEntry = $Entries[0]
    $previousEntry = $Entries[1]
    
    $categoryTrends = @()
    
    # Build lookup for previous categories
    $previousCategories = @{}
    foreach ($cat in $previousEntry.CategoryScores) {
        $previousCategories[$cat.Category] = $cat.Score
    }
    
    foreach ($currentCat in $latestEntry.CategoryScores) {
        $previousScore = $previousCategories[$currentCat.Category]
        $delta = if ($null -ne $previousScore) { $currentCat.Score - $previousScore } else { 0 }
        
        $trend = if ($delta -gt 2) { $script:TREND_IMPROVING }
                elseif ($delta -lt -2) { $script:TREND_DECLINING }
                else { $script:TREND_STABLE }
        
        $categoryTrends += [PSCustomObject]@{
            Category = $currentCat.Category
            CurrentScore = $currentCat.Score
            PreviousScore = $previousScore
            Delta = [math]::Round($delta, 1)
            Trend = $trend
            TrendIcon = switch ($trend) {
                $script:TREND_IMPROVING { "↑" }
                $script:TREND_DECLINING { "↓" }
                default { "→" }
            }
        }
    }
    
    return $categoryTrends
}

function Get-TrendVelocity {
    <#
    .SYNOPSIS
        Calculates the rate of security improvement/decline.
    
    .PARAMETER Entries
        Array of history entries (newest first).
    
    .OUTPUTS
        PSCustomObject with velocity metrics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entries
    )
    
    if ($Entries.Count -lt 2) {
        return [PSCustomObject]@{
            DailyRate = 0
            WeeklyRate = 0
            MonthlyProjection = 0
            DaysToTarget = $null
            TargetScore = 80
        }
    }
    
    $latestEntry = $Entries[0]
    $oldestEntry = $Entries[-1]
    
    $latestDate = [datetime]$latestEntry.Timestamp
    $oldestDate = [datetime]$oldestEntry.Timestamp
    $daysDiff = ($latestDate - $oldestDate).TotalDays
    
    if ($daysDiff -eq 0) { $daysDiff = 1 }
    
    $scoreDiff = $latestEntry.Metrics.SecurityScore - $oldestEntry.Metrics.SecurityScore
    $dailyRate = $scoreDiff / $daysDiff
    
    # Calculate days to reach target score (80%)
    $targetScore = 80
    $currentScore = $latestEntry.Metrics.SecurityScore
    $daysToTarget = if ($dailyRate -gt 0 -and $currentScore -lt $targetScore) {
        [math]::Ceiling(($targetScore - $currentScore) / $dailyRate)
    } elseif ($currentScore -ge $targetScore) {
        0
    } else {
        $null  # Not improving
    }
    
    return [PSCustomObject]@{
        DailyRate = [math]::Round($dailyRate, 3)
        WeeklyRate = [math]::Round($dailyRate * 7, 2)
        MonthlyProjection = [math]::Round($dailyRate * 30, 1)
        DaysToTarget = $daysToTarget
        TargetScore = $targetScore
        DataPointsAnalyzed = $Entries.Count
        PeriodDays = [math]::Round($daysDiff, 0)
    }
}

function Get-TrendTimeline {
    <#
    .SYNOPSIS
        Builds timeline data for trend charts.
    
    .PARAMETER Entries
        Array of history entries (newest first).
    
    .PARAMETER MaxPoints
        Maximum number of data points to return.
    
    .OUTPUTS
        PSCustomObject with chart-ready timeline data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Entries,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxPoints = 30
    )
    
    # Reverse to chronological order (oldest first) and limit points
    $chronological = @($Entries | Sort-Object { [datetime]$_.Timestamp })
    if ($chronological.Count -gt $MaxPoints) {
        # Sample evenly across the range
        $step = [math]::Ceiling($chronological.Count / $MaxPoints)
        $sampled = @()
        for ($i = 0; $i -lt $chronological.Count; $i += $step) {
            $sampled += $chronological[$i]
        }
        # Always include the latest
        if ($sampled[-1].Id -ne $chronological[-1].Id) {
            $sampled += $chronological[-1]
        }
        $chronological = $sampled
    }
    
    return [PSCustomObject]@{
        Labels = $chronological | ForEach-Object {
            ([datetime]$_.Timestamp).ToString("MMM dd")
        }
        SecurityScores = $chronological | ForEach-Object { $_.Metrics.SecurityScore }
        PassedCounts = $chronological | ForEach-Object { $_.Metrics.PassedCount }
        FailedCounts = $chronological | ForEach-Object { $_.Metrics.FailedCount }
        CriticalFindings = $chronological | ForEach-Object { $_.Metrics.CriticalFindings }
        DataPoints = $chronological.Count
    }
}

#endregion

#region Console Formatting

function Format-TrendConsole {
    <#
    .SYNOPSIS
        Formats trend analysis for console output.
    
    .PARAMETER Trends
        The trend analysis object from Get-SecurityTrends.
    
    .OUTPUTS
        Formatted string for console display.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Trends
    )
    
    $output = [System.Text.StringBuilder]::new()
    
    [void]$output.AppendLine("")
    [void]$output.AppendLine("╔══════════════════════════════════════════════════════════════════════╗")
    [void]$output.AppendLine("║                    SECURITY TREND ANALYSIS                           ║")
    [void]$output.AppendLine("╚══════════════════════════════════════════════════════════════════════╝")
    [void]$output.AppendLine("")
    
    if (-not $Trends.HasSufficientData) {
        [void]$output.AppendLine("  [!] $($Trends.Message)")
        [void]$output.AppendLine("      Run more assessments to enable trend tracking.")
        return $output.ToString()
    }
    
    # Trend direction with icon
    $trendIcon = switch ($Trends.TrendDirection) {
        $script:TREND_IMPROVING { "↑" }
        $script:TREND_DECLINING { "↓" }
        default { "→" }
    }
    $trendColor = switch ($Trends.TrendDirection) {
        $script:TREND_IMPROVING { "Green" }
        $script:TREND_DECLINING { "Red" }
        default { "Yellow" }
    }
    
    [void]$output.AppendLine("  Trend Direction: $trendIcon $($Trends.TrendDirection.ToUpper())")
    [void]$output.AppendLine("  Analysis Period: $($Trends.AnalysisPeriod) ($($Trends.DataPoints) data points)")
    [void]$output.AppendLine("")
    
    # Score summary
    $deltaSign = if ($Trends.ScoreDelta -ge 0) { "+" } else { "" }
    [void]$output.AppendLine("  Current Score: $($Trends.CurrentScore)% (Grade: $($Trends.CurrentGrade))")
    [void]$output.AppendLine("  Change: $deltaSign$($Trends.ScoreDelta) pts | Total Improvement: $deltaSign$($Trends.TotalImprovement) pts")
    [void]$output.AppendLine("")
    
    # Velocity
    if ($Trends.Velocity.DaysToTarget -and $Trends.Velocity.DaysToTarget -gt 0) {
        [void]$output.AppendLine("  Improvement Rate: $($Trends.Velocity.WeeklyRate) pts/week")
        [void]$output.AppendLine("  Days to 80% Target: ~$($Trends.Velocity.DaysToTarget) days")
    }
    elseif ($Trends.CurrentScore -ge 80) {
        [void]$output.AppendLine("  ✓ Target score (80%) achieved!")
    }
    else {
        [void]$output.AppendLine("  ! Score not improving - remediation actions needed")
    }
    [void]$output.AppendLine("")
    
    # Regressions
    if ($Trends.HasRegressions) {
        [void]$output.AppendLine("  ⚠ REGRESSIONS DETECTED ($($Trends.Regressions.Count)):")
        foreach ($reg in $Trends.Regressions.Items | Select-Object -First 5) {
            $severity = $reg.Severity.ToUpper()
            [void]$output.AppendLine("    [$severity] $($reg.Message)")
        }
        if ($Trends.Regressions.Count -gt 5) {
            [void]$output.AppendLine("    ... and $($Trends.Regressions.Count - 5) more")
        }
        [void]$output.AppendLine("")
    }
    
    # Category trends
    [void]$output.AppendLine("  Category Trends:")
    foreach ($cat in $Trends.CategoryTrends) {
        $deltaStr = if ($cat.Delta -ge 0) { "+$($cat.Delta)" } else { "$($cat.Delta)" }
        [void]$output.AppendLine("    $($cat.TrendIcon) $($cat.Category): $($cat.CurrentScore)% ($deltaStr)")
    }
    
    return $output.ToString()
}

#endregion

#region Exports

# Export functions only when loaded as a module
if ($MyInvocation.MyCommand.ScriptBlock.Module) {
    Export-ModuleMember -Function @(
        'Get-AssessmentHistory',
        'Save-AssessmentToHistory',
        'Get-SecurityTrends',
        'Get-RegressionAlerts',
        'Get-CategoryTrends',
        'Get-TrendVelocity',
        'Get-TrendTimeline',
        'Format-TrendConsole',
        'Get-HistoryStorePath'
    )
}

#endregion
