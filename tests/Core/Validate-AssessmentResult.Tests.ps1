#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Validate-AssessmentResult schema validation module.

.DESCRIPTION
    Validates that the schema validation functions properly enforce
    assessment result object contracts and catch invalid outputs
    before they reach the reporting layer.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Core\Validate-AssessmentResult.ps1"
}

Describe 'Validate-AssessmentResult' {

    Context 'Valid assessment results' {
        It 'Accepts a completely valid result' {
            $result = New-MockAssessmentResult -CheckName 'Test Check' -Status 'Pass' -Severity 'Critical'
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $true
        }

        It 'Accepts all valid Status values' {
            foreach ($status in @('Pass', 'Warning', 'Fail', 'Info')) {
                $result = New-MockAssessmentResult -CheckName 'Test' -Status $status -Severity 'Critical'
                $valid = Test-AssessmentResultSchema -Result $result
                $valid | Should -Be $true
            }
        }

        It 'Accepts all valid Severity values' {
            foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
                $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity $severity
                $valid = Test-AssessmentResultSchema -Result $result
                $valid | Should -Be $true
            }
        }

        It 'Accepts all valid Category values' {
            foreach ($category in @('Security', 'Exchange', 'Licensing')) {
                $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical' -Category $category
                $valid = Test-AssessmentResultSchema -Result $result
                $valid | Should -Be $true
            }
        }

        It 'Accepts empty RemediationSteps array' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.RemediationSteps = @()
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $true
        }
    }

    Context 'Invalid result violations' {
        It 'Rejects result missing CheckName property' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.PSObject.Properties.Remove('CheckName')
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with null CheckName' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.CheckName = $null
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with empty CheckName' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.CheckName = ''
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects invalid Status value' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Status = 'Broken'
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects invalid Severity value' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Severity = 'Urgent'
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects invalid Category value' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Category = 'Fraud'
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with null Message' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Message = $null
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with null Recommendation' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Recommendation = $null
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with null DocumentationUrl' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.DocumentationUrl = $null
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with null Details' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Details = $null
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }

        It 'Rejects result with non-array RemediationSteps' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.RemediationSteps = 'Single string'
            $valid = Test-AssessmentResultSchema -Result $result
            $valid | Should -Be $false
        }
    }

    Context 'Strict mode' {
        It 'Throws on schema violation in strict mode' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Status = 'Invalid'
            { Test-AssessmentResultSchema -Result $result -Strict $true } | Should -Throw
        }

        It 'Returns false on violation in non-strict mode' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Status = 'Invalid'
            $valid = Test-AssessmentResultSchema -Result $result -Strict $false
            $valid | Should -Be $false
        }
    }

    Context 'Assert-AssessmentResult pipeline' {
        It 'Passes valid result through pipeline' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $piped = $result | Assert-AssessmentResult
            $piped.CheckName | Should -Be 'Test'
        }

        It 'Throws on invalid result in pipeline' {
            $result = New-MockAssessmentResult -CheckName 'Test' -Status 'Pass' -Severity 'Critical'
            $result.Status = 'Invalid'
            { $result | Assert-AssessmentResult } | Should -Throw
        }
    }

    Context 'Schema contract documentation' {
        It 'Returns schema documentation string' {
            $schema = Get-AssessmentSchemaContract
            $schema | Should -Match 'REQUIRED PROPERTIES'
            $schema | Should -Match 'CheckName'
            $schema | Should -Match 'Status'
            $schema | Should -Match 'Severity'
        }
    }
}
