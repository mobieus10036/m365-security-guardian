<#
.SYNOPSIS
    Retrieves and analyzes Microsoft Secure Score for the tenant.

.DESCRIPTION
    Gets the current Microsoft Secure Score, compares against maximum possible,
    identifies top improvement actions, and provides actionable recommendations.

.PARAMETER Config
    Configuration object (reserved for future use).

.OUTPUTS
    PSCustomObject containing Secure Score assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
#>

function Test-SecureScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Retrieving Microsoft Secure Score..."

        # Get the latest Secure Score
        # Use SilentlyContinue to suppress verbose HTTP errors, then check for null
        $secureScores = Get-MgSecuritySecureScore -Top 1 -ErrorAction SilentlyContinue -ErrorVariable secureScoreError
        
        # If we have an error, throw it to the catch block with a clean message
        if ($secureScoreError) {
            throw $secureScoreError[0].Exception
        }

        if ($null -eq $secureScores -or @($secureScores).Count -eq 0) {
            return [PSCustomObject]@{
                CheckName = "Microsoft Secure Score"
                Category = "Security"
                Status = "Info"
                Severity = "Info"
                Message = "Unable to retrieve Secure Score data"
                Details = @{}
                Recommendation = "Ensure you have SecurityEvents.Read.All permission"
                DocumentationUrl = "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score"
                RemediationSteps = @()
            }
        }

        $latestScore = $secureScores | Select-Object -First 1
        $currentScore = [math]::Round($latestScore.CurrentScore, 1)
        $maxScore = [math]::Round($latestScore.MaxScore, 1)
        $scorePercentage = if ($maxScore -gt 0) { 
            [math]::Round(($currentScore / $maxScore) * 100, 1) 
        } else { 0 }

        # Get control scores for breakdown
        $controlScores = $latestScore.ControlScores
        
        # Categorize control scores
        $identityControls = @($controlScores | Where-Object { $_.ControlCategory -eq 'Identity' })
        $dataControls = @($controlScores | Where-Object { $_.ControlCategory -eq 'Data' })
        $deviceControls = @($controlScores | Where-Object { $_.ControlCategory -eq 'Device' })
        $appsControls = @($controlScores | Where-Object { $_.ControlCategory -eq 'Apps' })
        $infrastructureControls = @($controlScores | Where-Object { $_.ControlCategory -eq 'Infrastructure' })

        # Calculate category scores
        $categoryBreakdown = @()
        
        foreach ($category in @('Identity', 'Data', 'Device', 'Apps', 'Infrastructure')) {
            $categoryControls = @($controlScores | Where-Object { $_.ControlCategory -eq $category })
            if ($categoryControls.Count -gt 0) {
                $catCurrent = ($categoryControls | Measure-Object -Property Score -Sum).Sum
                $catMax = ($categoryControls | Measure-Object -Property MaxScore -Sum).Sum
                $catPercent = if ($catMax -gt 0) { [math]::Round(($catCurrent / $catMax) * 100, 1) } else { 0 }
                
                $categoryBreakdown += [PSCustomObject]@{
                    Category = $category
                    CurrentScore = [math]::Round($catCurrent, 1)
                    MaxScore = [math]::Round($catMax, 1)
                    Percentage = $catPercent
                    ControlCount = $categoryControls.Count
                }
            }
        }

        # Get improvement actions (controls not at max score)
        $improvementActions = @()
        foreach ($control in $controlScores) {
            $gap = $control.MaxScore - $control.Score
            if ($gap -gt 0) {
                $improvementActions += [PSCustomObject]@{
                    ControlName = $control.ControlName
                    Category = $control.ControlCategory
                    CurrentScore = [math]::Round($control.Score, 1)
                    MaxScore = [math]::Round($control.MaxScore, 1)
                    PointsAvailable = [math]::Round($gap, 1)
                    Description = $control.Description
                }
            }
        }

        # Sort by points available (biggest impact first)
        $topImprovements = $improvementActions | Sort-Object -Property PointsAvailable -Descending | Select-Object -First 10

        # Determine status based on score percentage
        $status = "Pass"
        $severity = "Low"

        if ($scorePercentage -lt 40) {
            $status = "Fail"
            $severity = "Critical"
        }
        elseif ($scorePercentage -lt 60) {
            $status = "Fail"
            $severity = "High"
        }
        elseif ($scorePercentage -lt 75) {
            $status = "Warning"
            $severity = "Medium"
        }
        elseif ($scorePercentage -lt 85) {
            $status = "Warning"
            $severity = "Low"
        }

        $message = "Secure Score: $currentScore / $maxScore ($scorePercentage%)"
        
        # Add top improvement action to message
        if ($topImprovements.Count -gt 0) {
            $topAction = $topImprovements[0]
            $message += ". Top action: $($topAction.ControlName) (+$($topAction.PointsAvailable) pts)"
        }

        # Build recommendations list
        $recommendations = @()
        if ($topImprovements.Count -gt 0) {
            $recommendations += "Top improvement actions to increase your score:"
            $rank = 1
            foreach ($action in ($topImprovements | Select-Object -First 5)) {
                $recommendations += "$rank. $($action.ControlName) [$($action.Category)] - +$($action.PointsAvailable) points available"
                $rank++
            }
        }

        # Build recommendation string based on actual score percentage
        $recommendationText = if ($scorePercentage -ge 85) {
            "Excellent! Your Secure Score is well optimized. Continue monitoring for new recommendations."
        }
        elseif ($scorePercentage -ge 75) {
            "Good progress! Review the top improvement actions to further strengthen your security posture."
        }
        elseif ($scorePercentage -ge 60) {
            "Your Secure Score needs attention. Prioritize the improvement actions listed below."
        }
        else {
            "Critical: Your Secure Score ($scorePercentage%) is below recommended levels. Immediate action is required."
        }
        
        # Append top actions to recommendation text
        if ($topImprovements.Count -gt 0) {
            $actionList = ($topImprovements | Select-Object -First 5 | ForEach-Object { 
                "$($_.ControlName) (+$($_.PointsAvailable) pts)" 
            }) -join "; "
            $recommendationText += " Top 5 actions: $actionList"
        }

        return [PSCustomObject]@{
            CheckName = "Microsoft Secure Score"
            Category = "Security"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                CurrentScore = $currentScore
                MaxScore = $maxScore
                ScorePercentage = $scorePercentage
                ScoreDate = $latestScore.CreatedDateTime
                TotalControls = $controlScores.Count
                ControlsAtMax = ($controlScores | Where-Object { $_.Score -eq $_.MaxScore }).Count
                ControlsNeedingWork = $improvementActions.Count
            }
            CategoryBreakdown = $categoryBreakdown
            TopImprovementActions = $topImprovements
            Recommendations = $recommendations
            Recommendation = $recommendationText
            DocumentationUrl = "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score"
            RemediationSteps = @(
                "1. Navigate to Microsoft 365 Defender portal > Secure Score"
                "2. Review the Improvement Actions tab for detailed guidance"
                "3. Filter by category (Identity, Data, Device, Apps) to focus efforts"
                "4. Click each action for step-by-step implementation guidance"
                "5. Use 'To address' filter to see actions you can implement"
                "6. Mark actions as 'Planned' to track progress"
                "7. Re-assess weekly to track score improvements"
            )
        }
    }
    catch {
        # Check if this is a licensing issue (403) vs actual permission problem
        $errorMsg = $_.Exception.Message
        $isLicenseIssue = $errorMsg -match "403|Forbidden|not have valid roles"
        
        $message = if ($isLicenseIssue) {
            "Secure Score API requires Microsoft 365 E5 or E5 Security license"
        } else {
            "Unable to retrieve Secure Score: $($_.Exception.Message)"
        }
        
        $recommendation = if ($isLicenseIssue) {
            "Microsoft Secure Score API is only available with E5 licensing. Your custom Tenant Security Score provides similar insights."
        } else {
            "Verify Microsoft Graph permissions: SecurityEvents.Read.All, SecurityActions.Read.All"
        }
        
        return [PSCustomObject]@{
            CheckName = "Microsoft Secure Score"
            Category = "Security"
            Status = "Info"
            Severity = "Info"
            Message = $message
            Details = @{ 
                Error = $_.Exception.Message
                LicenseRequired = $isLicenseIssue
            }
            Recommendation = $recommendation
            DocumentationUrl = "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score"
            RemediationSteps = @()
        }
    }
}
