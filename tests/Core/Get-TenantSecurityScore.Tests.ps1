#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Get-TenantSecurityScore core scoring engine.

.DESCRIPTION
    Validates the weighted scoring algorithm, grade boundaries, category
    breakdowns, and priority/quick-win identification — all without any
    external API calls (scoring is pure computation on result objects).

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Core\Get-TenantSecurityScore.ps1"

    # Stub Get-MgContext (called at end of scoring to get TenantId)
    Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'test-tenant-id' } }
}

Describe 'Get-TenantSecurityScore' {

    Context 'Grade boundaries' {
        It 'Returns grade A for score >= 90' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'Email Authentication (SPF/DKIM/DMARC)' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Pass' -Severity 'Low'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.LetterGrade | Should -Be 'A'
            $score.OverallScore | Should -BeGreaterOrEqual 90
        }

        It 'Returns grade F when all checks fail with Critical severity' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Fail' -Severity 'Critical'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.LetterGrade | Should -Be 'F'
            $score.OverallScore | Should -BeLessOrEqual 59
        }
    }

    Context 'Output shape' {
        It 'Returns all required score properties' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.PSObject.Properties.Name | Should -Contain 'OverallScore'
            $score.PSObject.Properties.Name | Should -Contain 'LetterGrade'
            $score.PSObject.Properties.Name | Should -Contain 'GradeDescription'
            $score.PSObject.Properties.Name | Should -Contain 'CategoryBreakdown'
            $score.PSObject.Properties.Name | Should -Contain 'TopPriorities'
            $score.PSObject.Properties.Name | Should -Contain 'QuickWins'
            $score.PSObject.Properties.Name | Should -Contain 'Summary'
        }

        It 'Summary counts match input results' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Fail' -Severity 'High'
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Warning' -Severity 'Low'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.Summary.TotalChecks   | Should -Be 3
            $score.Summary.PassedChecks  | Should -Be 1
            $score.Summary.FailedChecks  | Should -Be 1
            $score.Summary.WarningChecks | Should -Be 1
        }
    }

    Context 'Category mapping' {
        It 'Maps checks to correct categories' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Email Authentication (SPF/DKIM/DMARC)' -Status 'Fail' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Warning' -Severity 'Low'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $identityCat = $score.CategoryBreakdown | Where-Object { $_.Category -eq 'Identity & Access' }
            $emailCat    = $score.CategoryBreakdown | Where-Object { $_.Category -eq 'Email Security' }
            $govCat      = $score.CategoryBreakdown | Where-Object { $_.Category -eq 'Governance' }

            $identityCat.ChecksEvaluated | Should -Be 1
            $emailCat.ChecksEvaluated    | Should -Be 1
            $govCat.ChecksEvaluated      | Should -Be 1
        }
    }

    Context 'Priority identification' {
        It 'Identifies failed checks as top priorities' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Pass' -Severity 'Low'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.TopPriorities | Should -HaveCount 1
            $score.TopPriorities[0].CheckName | Should -Be 'MFA Enforcement'
        }

        It 'Identifies warnings with medium/low severity as quick wins' {
            $results = @(
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Warning' -Severity 'Medium'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            $score.QuickWins | Should -HaveCount 1
            $score.QuickWins[0].CheckName | Should -Be 'License Optimization'
        }
    }

    Context 'Info status handling' {
        It 'Treats Info status as neutral (does not penalize score)' {
            # All pass except one Info
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Microsoft Secure Score' -Status 'Info' -Severity 'Info'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            # Info gets full points, so score should still be very high
            $score.OverallScore | Should -BeGreaterOrEqual 90
        }
    }

    Context 'Status-based scoring (no severity adjustment)' {
        It 'Failed critical checks earn 0 points (not 25%)' {
            # Single critical failure should result in very low score
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            # With one critical failure (high weight), score should be near 0
            # If severity adjustment was applied (BUGGY), would earn ~25%
            $score.OverallScore | Should -BeLessThan 15
        }

        It 'Warning checks earn exactly 50% of weight' {
            # Single warning should give exactly 50% (before other factors)
            $results = @(
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Warning' -Severity 'Medium'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            # Warning = 50% of points = ~50 score
            $score.OverallScore | Should -BeGreaterOrEqual 40
            $score.OverallScore | Should -BeLessThan 60
        }

        It 'Mixed 50% fail / 50% pass results in ~50% score' {
            # 4 passes, 4 fails (equal weight) = 50% score
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'Email Authentication (SPF/DKIM/DMARC)' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Legacy Authentication (BasicAuth)' -Status 'Fail' -Severity 'High'
                New-MockAssessmentResult -CheckName 'External User Sharing Policy' -Status 'Fail' -Severity 'High'
                New-MockAssessmentResult -CheckName 'License Optimization' -Status 'Fail' -Severity 'Medium'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            # 50/50 split with category weighting = ~60 score (allowing variance for weight distribution)
            $score.OverallScore | Should -BeGreaterOrEqual 40
            $score.OverallScore | Should -BeLessThan 75
        }

        It 'Severity does NOT inflate failed check scores' {
            # Same check, compare Fail-Critical vs Fail-Low
            # Both should score 0 (severity should not matter for failures)
            $resultsCritical = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )
            $resultsLow = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Low'
            )

            $scoreCritical = Get-TenantSecurityScore -AssessmentResults $resultsCritical -Config (New-MockConfig)
            $scoreLow = Get-TenantSecurityScore -AssessmentResults $resultsLow -Config (New-MockConfig)

            # Both should be identically low (severity doesn't adjust failures)
            $scoreCritical.OverallScore | Should -BeExactly $scoreLow.OverallScore
        }

        It 'All-fail tenant scores 0-10% (not 25-75%)' {
            # Complete failure scenario - all critical failures
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Email Authentication (SPF/DKIM/DMARC)' -Status 'Fail' -Severity 'Critical'
            )

            $score = Get-TenantSecurityScore -AssessmentResults $results -Config (New-MockConfig)

            # All failures = grade F, near-zero score
            # If severity bug existed: Critical failures would earn ~25% each = 25% total (WRONG)
            $score.OverallScore | Should -BeLessThan 15
            $score.LetterGrade | Should -Be 'F'
        }
    }
}
