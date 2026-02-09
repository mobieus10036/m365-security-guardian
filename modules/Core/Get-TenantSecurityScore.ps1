<#
.SYNOPSIS
    Calculates an overall Tenant Security Score based on assessment results.

.DESCRIPTION
    Aggregates all assessment findings into a weighted security score (0-100)
    with letter grade (A-F) and category breakdowns. Provides actionable
    prioritization for remediation efforts.

.PARAMETER AssessmentResults
    Array of assessment results from all modules.

.PARAMETER Config
    Configuration object containing risk weights.

.OUTPUTS
    PSCustomObject containing:
    - OverallScore (0-100)
    - LetterGrade (A-F)
    - CategoryScores (breakdown by security domain)
    - TopPriorities (highest impact remediation items)
    - QuickWins (low effort, high impact fixes)

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.1.0
    Created with assistance from GitHub Copilot
#>

function Get-TenantSecurityScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$AssessmentResults,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    # Default risk weights if not configured
    $defaultWeights = @{
        # Identity & Access (35% of total)
        "MFA Enforcement" = 12
        "Privileged Account Security" = 10
        "Privileged Identity Management (PIM)" = 8
        "Legacy Authentication" = 5
        
        # Conditional Access & Policies (25% of total)
        "Conditional Access Policies" = 15
        "External Sharing Configuration" = 10
        
        # Application Security (20% of total)
        "Application Permission Audit" = 12
        "Microsoft Secure Score" = 8
        
        # Email & Communication (15% of total)
        "Email Authentication (SPF/DKIM/DMARC)" = 8
        "Mailbox Auditing" = 4
        "Email Security Configuration" = 3
        
        # Licensing & Governance (5% of total)
        "License Optimization" = 5
    }

    # Use configured weights or defaults (convert PSCustomObject to hashtable if needed)
    $weights = $defaultWeights
    if ($Config -and $Config.Scoring -and $Config.Scoring.RiskWeights) {
        $configWeights = $Config.Scoring.RiskWeights
        # Convert PSCustomObject to hashtable if necessary
        if ($configWeights -is [System.Management.Automation.PSCustomObject]) {
            $weights = @{}
            $configWeights.PSObject.Properties | ForEach-Object {
                $weights[$_.Name] = $_.Value
            }
        } elseif ($configWeights -is [hashtable]) {
            $weights = $configWeights
        }
    }

    # Severity multipliers (how much a failure impacts the score)
    $severityMultipliers = @{
        "Critical" = 1.0    # Full weight deduction
        "High" = 0.75       # 75% weight deduction
        "Medium" = 0.5      # 50% weight deduction
        "Low" = 0.25        # 25% weight deduction
        "Info" = 0.0        # No deduction
    }

    # Status scoring
    $statusScores = @{
        "Pass" = 1.0        # Full points
        "Warning" = 0.5     # Half points
        "Fail" = 0.0        # No points
        "Info" = 1.0        # Neutral - full points (informational only)
    }

    # Initialize category tracking
    $categoryScores = @{
        "Identity & Access" = @{ Earned = 0; Possible = 0; Checks = @() }
        "Conditional Access" = @{ Earned = 0; Possible = 0; Checks = @() }
        "Application Security" = @{ Earned = 0; Possible = 0; Checks = @() }
        "Email Security" = @{ Earned = 0; Possible = 0; Checks = @() }
        "Governance" = @{ Earned = 0; Possible = 0; Checks = @() }
    }

    # Map checks to categories
    $checkCategoryMap = @{
        "MFA Enforcement" = "Identity & Access"
        "Privileged Account Security" = "Identity & Access"
        "Privileged Identity Management (PIM)" = "Identity & Access"
        "Legacy Authentication" = "Identity & Access"
        "Conditional Access Policies" = "Conditional Access"
        "External Sharing Configuration" = "Conditional Access"
        "Application Permission Audit" = "Application Security"
        "Microsoft Secure Score" = "Application Security"
        "Email Authentication (SPF/DKIM/DMARC)" = "Email Security"
        "Mailbox Auditing" = "Email Security"
        "Email Security Configuration" = "Email Security"
        "License Optimization" = "Governance"
    }

    # Calculate scores
    $totalEarned = 0
    $totalPossible = 0
    $priorityItems = @()
    $quickWins = @()

    foreach ($result in $AssessmentResults) {
        $checkName = $result.CheckName
        $weight = if ($weights.ContainsKey($checkName)) { $weights[$checkName] } else { 5 }
        $category = if ($checkCategoryMap.ContainsKey($checkName)) { $checkCategoryMap[$checkName] } else { "Governance" }
        
        # Get status score
        $statusScore = if ($statusScores.ContainsKey($result.Status)) { 
            $statusScores[$result.Status] 
        } else { 0.5 }

        # Calculate points
        $possiblePoints = $weight
        $earnedPoints = $weight * $statusScore

        # Apply severity adjustment for failed/warning items
        if ($result.Status -in @('Fail', 'Warning')) {
            $severityMult = if ($severityMultipliers.ContainsKey($result.Severity)) {
                $severityMultipliers[$result.Severity]
            } else { 0.5 }
            
            # Higher severity = lower earned points
            $earnedPoints = $weight * (1 - $severityMult) * (1 - $statusScore)
        }

        $totalEarned += $earnedPoints
        $totalPossible += $possiblePoints

        # Update category scores
        if ($categoryScores.ContainsKey($category)) {
            $categoryScores[$category].Earned += $earnedPoints
            $categoryScores[$category].Possible += $possiblePoints
            $categoryScores[$category].Checks += [PSCustomObject]@{
                CheckName = $checkName
                Status = $result.Status
                Severity = $result.Severity
                Score = [math]::Round(($earnedPoints / $possiblePoints) * 100, 1)
            }
        }

        # Identify priority items (failed checks with high weight)
        if ($result.Status -eq 'Fail') {
            $impactScore = $weight * $severityMultipliers[$result.Severity]
            $priorityItems += [PSCustomObject]@{
                CheckName = $checkName
                Category = $category
                Severity = $result.Severity
                ImpactScore = $impactScore
                Message = $result.Message
                Recommendation = $result.Recommendation
                DocumentationUrl = $result.DocumentationUrl
                PotentialGain = [math]::Round($impactScore, 1)
            }
        }

        # Identify quick wins (warning status, medium/low severity, high weight)
        if ($result.Status -eq 'Warning' -and $result.Severity -in @('Medium', 'Low')) {
            $quickWins += [PSCustomObject]@{
                CheckName = $checkName
                Category = $category
                Severity = $result.Severity
                Message = $result.Message
                Recommendation = $result.Recommendation
                EffortLevel = "Low"
                PotentialGain = [math]::Round($weight * 0.5, 1)
            }
        }
    }

    # Calculate overall score
    $overallScore = if ($totalPossible -gt 0) {
        [math]::Round(($totalEarned / $totalPossible) * 100, 1)
    } else { 0 }

    # Determine letter grade
    $letterGrade = switch ($overallScore) {
        { $_ -ge 90 } { "A" }
        { $_ -ge 80 } { "B" }
        { $_ -ge 70 } { "C" }
        { $_ -ge 60 } { "D" }
        default { "F" }
    }

    # Grade description
    $gradeDescription = switch ($letterGrade) {
        "A" { "Excellent - Your tenant follows security best practices" }
        "B" { "Good - Minor improvements recommended" }
        "C" { "Fair - Several security gaps should be addressed" }
        "D" { "Poor - Significant security risks require attention" }
        "F" { "Critical - Immediate action required to secure tenant" }
    }

    # Calculate category percentages
    $categoryBreakdown = @()
    foreach ($cat in $categoryScores.Keys) {
        $catData = $categoryScores[$cat]
        $catScore = if ($catData.Possible -gt 0) {
            [math]::Round(($catData.Earned / $catData.Possible) * 100, 1)
        } else { 100 }
        
        $catGrade = switch ($catScore) {
            { $_ -ge 90 } { "A" }
            { $_ -ge 80 } { "B" }
            { $_ -ge 70 } { "C" }
            { $_ -ge 60 } { "D" }
            default { "F" }
        }

        $categoryBreakdown += [PSCustomObject]@{
            Category = $cat
            Score = $catScore
            Grade = $catGrade
            ChecksEvaluated = $catData.Checks.Count
            PassedChecks = ($catData.Checks | Where-Object { $_.Status -eq 'Pass' }).Count
            FailedChecks = ($catData.Checks | Where-Object { $_.Status -eq 'Fail' }).Count
            Details = $catData.Checks
        }
    }

    # Sort priorities by impact
    $topPriorities = $priorityItems | Sort-Object -Property ImpactScore -Descending | Select-Object -First 5
    $topQuickWins = $quickWins | Sort-Object -Property PotentialGain -Descending | Select-Object -First 5

    # Calculate potential score improvement
    $potentialImprovement = ($topPriorities | Measure-Object -Property PotentialGain -Sum).Sum
    $potentialScore = [math]::Min(100, $overallScore + $potentialImprovement)

    # Build summary statistics
    $summary = @{
        TotalChecks = $AssessmentResults.Count
        PassedChecks = ($AssessmentResults | Where-Object { $_.Status -eq 'Pass' }).Count
        WarningChecks = ($AssessmentResults | Where-Object { $_.Status -eq 'Warning' }).Count
        FailedChecks = ($AssessmentResults | Where-Object { $_.Status -eq 'Fail' }).Count
        CriticalFindings = ($AssessmentResults | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighFindings = ($AssessmentResults | Where-Object { $_.Severity -eq 'High' }).Count
    }

    return [PSCustomObject]@{
        OverallScore = $overallScore
        LetterGrade = $letterGrade
        GradeDescription = $gradeDescription
        PotentialScore = $potentialScore
        PotentialImprovement = [math]::Round($potentialImprovement, 1)
        CategoryBreakdown = $categoryBreakdown
        TopPriorities = $topPriorities
        QuickWins = $topQuickWins
        Summary = $summary
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TenantId = (Get-MgContext).TenantId
    }
}

function Format-SecurityScoreDisplay {
    <#
    .SYNOPSIS
        Formats the security score for console display.
    .DESCRIPTION
        Uses Write-Host for colorized output in interactive sessions.
        Adapts bullet characters based on host environment detection.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ScoreData
    )

    $gradeColor = switch ($ScoreData.LetterGrade) {
        "A" { "Green" }
        "B" { "Green" }
        "C" { "Yellow" }
        "D" { "Red" }
        "F" { "Red" }
    }

    $bullet = if ($script:Bullet) { $script:Bullet } else { '*' }
    $warnMark = if ($script:WarningMark) { $script:WarningMark } else { '!' }

    Write-Host ""
    Write-Host "+=============================================================+" -ForegroundColor Cyan
    Write-Host "|              TENANT SECURITY SCORE                           |" -ForegroundColor Cyan
    Write-Host "+=============================================================+" -ForegroundColor Cyan
    Write-Host "|                                                              |" -ForegroundColor Cyan
    Write-Host "|     Score: " -ForegroundColor Cyan -NoNewline
    Write-Host "$($ScoreData.OverallScore)%" -ForegroundColor $gradeColor -NoNewline
    Write-Host "     Grade: " -ForegroundColor Cyan -NoNewline
    Write-Host "$($ScoreData.LetterGrade)" -ForegroundColor $gradeColor -NoNewline
    Write-Host "                              |" -ForegroundColor Cyan
    Write-Host "|                                                              |" -ForegroundColor Cyan
    Write-Host "|     $($ScoreData.GradeDescription.PadRight(50))     |" -ForegroundColor Cyan
    Write-Host "|                                                              |" -ForegroundColor Cyan
    Write-Host "+=============================================================+" -ForegroundColor Cyan
    Write-Host "|  Category Breakdown:                                         |" -ForegroundColor Cyan
    
    foreach ($cat in $ScoreData.CategoryBreakdown) {
        $catColor = switch ($cat.Grade) {
            "A" { "Green" }
            "B" { "Green" }
            "C" { "Yellow" }
            "D" { "Red" }
            "F" { "Red" }
        }
        $catLine = "    $($cat.Category.PadRight(25)) $($cat.Score.ToString().PadLeft(5))% ($($cat.Grade))"
        Write-Host "|  " -ForegroundColor Cyan -NoNewline
        Write-Host $catLine.PadRight(58) -ForegroundColor $catColor -NoNewline
        Write-Host "|" -ForegroundColor Cyan
    }
    
    Write-Host "+=============================================================+" -ForegroundColor Cyan
    Write-Host "|  Summary:                                                    |" -ForegroundColor Cyan
    Write-Host "|    Passed: $($ScoreData.Summary.PassedChecks.ToString().PadLeft(3))  |  Warnings: $($ScoreData.Summary.WarningChecks.ToString().PadLeft(3))  |  Failed: $($ScoreData.Summary.FailedChecks.ToString().PadLeft(3))         |" -ForegroundColor Cyan
    
    if ($ScoreData.Summary.CriticalFindings -gt 0) {
        Write-Host "|    $warnMark Critical Findings: $($ScoreData.Summary.CriticalFindings)                                      |" -ForegroundColor Red
    }
    
    Write-Host "+=============================================================+" -ForegroundColor Cyan
    Write-Host ""

    if ($ScoreData.TopPriorities.Count -gt 0) {
        Write-Host "  Top Priorities to Address:" -ForegroundColor Yellow
        $rank = 1
        foreach ($priority in $ScoreData.TopPriorities) {
            Write-Host "    $rank. [$($priority.Severity)] $($priority.CheckName) (+$($priority.PotentialGain) pts)" -ForegroundColor Yellow
            $rank++
        }
        Write-Host ""
    }

    if ($ScoreData.QuickWins.Count -gt 0) {
        Write-Host "  Quick Wins (Low Effort):" -ForegroundColor Green
        foreach ($win in $ScoreData.QuickWins) {
            Write-Host "    $bullet $($win.CheckName) (+$($win.PotentialGain) pts)" -ForegroundColor Green
        }
        Write-Host ""
    }
}
