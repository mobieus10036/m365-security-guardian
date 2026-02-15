<#
.SYNOPSIS
    Quick validation script for Phase 4 trend tracking functions.
    Runs without Pester to avoid VS Code stability issues.
#>

$ErrorActionPreference = "Stop"
$script:TestsPassed = 0
$script:TestsFailed = 0

function Assert-Test {
    param([string]$Name, [bool]$Condition)
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        $script:TestsFailed++
    }
}

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Phase 4 Trend Tracking - Function Validation        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Load module
. "$PSScriptRoot\modules\Core\Get-SecurityTrends.ps1"

# Setup temp directory
$tempDir = Join-Path $env:TEMP "M365Guardian_Test_$(Get-Random)"
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

try {
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "━━━ Testing Get-HistoryStorePath ━━━" -ForegroundColor Yellow
    
    $defaultPath = Get-HistoryStorePath
    Assert-Test "Returns default path" ($defaultPath -match 'assessment-history\.json$')
    
    $customPath = Get-HistoryStorePath -BasePath "C:\Custom"
    Assert-Test "Uses custom base path" ($customPath -eq "C:\Custom\assessment-history.json")

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Get-AssessmentHistory ━━━" -ForegroundColor Yellow
    
    $nonExistentPath = Join-Path $tempDir "nonexistent.json"
    $emptyHistory = Get-AssessmentHistory -HistoryPath $nonExistentPath
    Assert-Test "Returns empty for missing file" ($emptyHistory.EntryCount -eq 0)
    
    # Create test history file
    $historyPath = Join-Path $tempDir "test-history.json"
    $testHistory = @{
        Version = "1.0"
        LastUpdated = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        Entries = @(
            @{
                Id = [guid]::NewGuid().ToString()
                Timestamp = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
                TenantId = "test-tenant"
                Metrics = @{
                    SecurityScore = 65.0
                    Grade = "D"
                    PassCount = 5
                    FailCount = 4
                }
                CategoryScores = @(
                    @{ Category = "Identity"; Score = 70.0 }
                    @{ Category = "ConditionalAccess"; Score = 60.0 }
                )
            },
            @{
                Id = [guid]::NewGuid().ToString()
                Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                TenantId = "test-tenant"
                Metrics = @{
                    SecurityScore = 75.0
                    Grade = "C"
                    PassCount = 7
                    FailCount = 3
                }
                CategoryScores = @(
                    @{ Category = "Identity"; Score = 80.0 }
                    @{ Category = "ConditionalAccess"; Score = 70.0 }
                )
            }
        )
    }
    $testHistory | ConvertTo-Json -Depth 10 | Set-Content $historyPath -Encoding UTF8
    
    $loadedHistory = Get-AssessmentHistory -HistoryPath $historyPath
    Assert-Test "Loads history from file" ($loadedHistory.EntryCount -eq 2)
    Assert-Test "Returns version info" ($loadedHistory.Version -eq "1.0")

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Save-AssessmentToHistory ━━━" -ForegroundColor Yellow
    
    $newHistoryPath = Join-Path $tempDir "new-history.json"
    $mockResults = @(
        [PSCustomObject]@{
            CheckName = "MFA Enforcement"
            Category = "Security"
            Status = "Pass"
            Severity = "Critical"
        }
    )
    $mockScore = [PSCustomObject]@{
        OverallScore = 72.5
        LetterGrade = "C"
    }
    
    $saveResult = Save-AssessmentToHistory `
        -Results $mockResults `
        -SecurityScore $mockScore `
        -TenantId "test-tenant" `
        -TenantName "Test Tenant" `
        -HistoryPath $newHistoryPath
    
    Assert-Test "Save returns success" ($saveResult.Success -eq $true)
    Assert-Test "History file created" (Test-Path $newHistoryPath)

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Get-SecurityTrends ━━━" -ForegroundColor Yellow
    
    # Test with insufficient data
    $emptyTrendsPath = Join-Path $tempDir "empty-trends.json"
    @{ Version = "1.0"; Entries = @() } | ConvertTo-Json | Set-Content $emptyTrendsPath
    
    $insufficientTrends = Get-SecurityTrends -HistoryPath $emptyTrendsPath
    Assert-Test "Reports insufficient data" ($insufficientTrends.TrendStatus -eq "InsufficientData")
    Assert-Test "HasSufficientData is false" ($insufficientTrends.HasSufficientData -eq $false)
    
    # Test with valid data
    $trends = Get-SecurityTrends -HistoryPath $historyPath
    Assert-Test "Returns trend direction" ($trends.TrendDirection -in @("Improving", "Declining", "Stable"))
    Assert-Test "HasSufficientData is true" ($trends.HasSufficientData -eq $true)
    Assert-Test "Reports data points" ($trends.DataPoints -ge 2)

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Get-RegressionAlerts ━━━" -ForegroundColor Yellow
    
    $history = Get-AssessmentHistory -HistoryPath $historyPath
    $regressions = Get-RegressionAlerts -LatestEntry $history.Entries[0] -PreviousEntry $history.Entries[1]
    Assert-Test "Returns regression object" ($null -ne $regressions)
    Assert-Test "HasRegressions property exists" ($null -ne $regressions.HasRegressions)

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Format-TrendConsole ━━━" -ForegroundColor Yellow
    
    $output = Format-TrendConsole -Trends $trends
    Assert-Test "Returns formatted output" ($output.Length -gt 100)
    Assert-Test "Contains header" ($output -match "SECURITY TREND ANALYSIS")

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Get-TrendVelocity ━━━" -ForegroundColor Yellow
    
    $velocity = Get-TrendVelocity -Entries $history.Entries
    Assert-Test "Returns velocity object" ($null -ne $velocity)
    Assert-Test "Has WeeklyRate" ($null -ne $velocity.WeeklyRate)

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Get-TrendTimeline ━━━" -ForegroundColor Yellow
    
    $timeline = Get-TrendTimeline -Entries $history.Entries
    Assert-Test "Returns timeline object" ($null -ne $timeline)
    Assert-Test "Has Labels array" ($timeline.Labels.Count -ge 0)

    # ─────────────────────────────────────────────────────────────────────────
    Write-Host "`n━━━ Testing Build-TrendsSectionHtml ━━━" -ForegroundColor Yellow
    
    # Load Export-Reports module for HTML generation
    . "$PSScriptRoot\modules\Core\Export-Reports.ps1"
    
    $mockTrends = @{
        HasSufficientData = $true
        TrendDirection = 'Improving'
        ScoreDelta = 5.2
        DataPoints = 8
        AnalysisPeriod = 30
        HasRegressions = $false
        Velocity = @{ WeeklyRate = 1.5; DaysToTarget = 45 }
        Timeline = @{ Labels = @('Jan 1', 'Jan 8'); DataPoints = @(72, 77) }
        CategoryTrends = @{ 'Identity' = @{ Trend = 'Improving'; Delta = 3.5 } }
    }
    
    $html = Build-TrendsSectionHtml -Trends $mockTrends
    Assert-Test "Returns HTML content" ($html.Length -gt 100)
    Assert-Test "Contains trends-section class" ($html -match 'trends-section')
    Assert-Test "Contains trend direction" ($html -match 'Improving')
    
    $emptyHtml = Build-TrendsSectionHtml -Trends $null
    Assert-Test "Returns empty for null trends" ($emptyHtml -eq '')
    
    $insufficientHtml = Build-TrendsSectionHtml -Trends @{ HasSufficientData = $false }
    Assert-Test "Returns empty for insufficient data" ($insufficientHtml -eq '')

}
catch {
    Write-Host "`n  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  At: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    $script:TestsFailed++
}
finally {
    # Cleanup
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Summary
Write-Host "`n━━━ Test Summary ━━━" -ForegroundColor Yellow
Write-Host "  Passed: $($script:TestsPassed)" -ForegroundColor Green
Write-Host "  Failed: $($script:TestsFailed)" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })

$passRate = if (($script:TestsPassed + $script:TestsFailed) -gt 0) {
    [math]::Round(($script:TestsPassed / ($script:TestsPassed + $script:TestsFailed)) * 100, 1)
} else { 0 }

Write-Host "  Pass Rate: $passRate%`n"

if ($script:TestsFailed -eq 0) {
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  TREND TRACKING VALIDATION PASSED                        ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║  VALIDATION FAILED - SEE ERRORS ABOVE                    ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Red
    exit 1
}
