#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Test-SSPRConfiguration assessment module.

.DESCRIPTION
    Validates SSPR check logic by mocking Microsoft Graph authorization policy data.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Security\Test-SSPRConfiguration.ps1"
}

Describe 'Test-SSPRConfiguration' {

    Context 'Result contract' {
        It 'Returns an object with all required properties' {
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowedToUseSspr = $true
                }
            }

            $result = Test-SSPRConfiguration -Config (New-MockConfig)

            Assert-AssessmentResult $result
            $result.CheckName | Should -Be 'Self-Service Password Reset (SSPR)'
            $result.Category | Should -Be 'Security'
        }
    }

    Context 'Status logic' {
        It 'Returns Pass when SSPR is enabled' {
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowedToUseSspr = $true
                }
            }

            $result = Test-SSPRConfiguration -Config (New-MockConfig)

            $result.Status | Should -Be 'Pass'
            $result.Severity | Should -Be 'Low'
            $result.Details.SsprEnabled | Should -Be $true
        }

        It 'Returns Warning when SSPR is disabled' {
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowedToUseSspr = $false
                }
            }

            $result = Test-SSPRConfiguration -Config (New-MockConfig)

            $result.Status | Should -Be 'Warning'
            $result.Severity | Should -Be 'Medium'
            $result.Details.SsprEnabled | Should -Be $false
        }
    }

    Context 'Error handling' {
        It 'Returns Info status on Graph API error (never throws)' {
            Mock Get-MgPolicyAuthorizationPolicy { throw 'Insufficient privileges' }

            $result = Test-SSPRConfiguration -Config (New-MockConfig)

            $result.Status | Should -Be 'Info'
            $result.Severity | Should -Be 'Info'
            $result.Message | Should -BeLike '*Unable to assess*'
        }
    }
}
