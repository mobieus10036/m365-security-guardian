#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Test-MFAConfiguration assessment module.

.DESCRIPTION
    Validates MFA check logic by mocking Microsoft Graph API calls.
    Demonstrates the standard pattern for testing assessment modules:
      1. Dot-source the module under test
      2. Mock all external cmdlets (Graph, EXO, etc.)
      3. Assert the result conforms to the contract
      4. Test status/severity logic at threshold boundaries

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    # Load test helpers and the module under test
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Security\Test-MFAConfiguration.ps1"

    # Stub the Get-AuthRegistrationDetails helper (defined in orchestrator)
    function Get-AuthRegistrationDetails { return @() }
}

Describe 'Test-MFAConfiguration' {

    BeforeEach {
        $script:Config = New-MockConfig
    }

    Context 'Result contract' {
        It 'Returns an object with all required properties' {
            # Arrange: 1 user with MFA
            Mock Get-MgUser {
                @(New-MockUser -UserPrincipalName 'user1@contoso.com' -AccountEnabled $true)
            }
            $authDetails = @(
                New-MockAuthRegistration -UserPrincipalName 'user1@contoso.com' -IsMfaRegistered $true
            )

            # Act
            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            # Assert
            Assert-AssessmentResult $result
            $result.Category | Should -Be 'Security'
        }
    }

    Context 'Status logic at threshold boundaries' {
        It 'Returns Pass when MFA adoption >= threshold (95%)' {
            # Arrange: 20 users, 19 with MFA = 95%
            $users = 1..20 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..19 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }
            # user20 has NO MFA (not in auth details)

            # Act
            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            # Assert
            $result.Status | Should -Be 'Pass'
            $result.Details.CompliancePercentage | Should -Be 95.0
        }

        It 'Returns Warning when MFA adoption is 75-94%' {
            # Arrange: 10 users, 8 with MFA = 80%
            $users = 1..10 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..8 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            # Act
            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            # Assert
            $result.Status | Should -Be 'Warning'
        }

        It 'Returns Fail when MFA adoption < 75%' {
            # Arrange: 10 users, 5 with MFA = 50%
            $users = 1..10 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..5 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            # Act
            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            # Assert
            $result.Status | Should -Be 'Fail'
            $result.Severity | Should -BeIn @('High', 'Critical')
        }
    }

    Context 'Severity logic' {
        It 'Returns Critical severity when MFA adoption < 50%' {
            $users = 1..10 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..3 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            $result.Severity | Should -Be 'Critical'
        }

        It 'Returns Low severity when MFA adoption >= 90%' {
            $users = 1..10 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..9 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            $result.Severity | Should -Be 'Low'
        }
    }

    Context 'UsersWithoutMFA detail property' {
        It 'Populates UsersWithoutMFA with correct user objects' {
            $users = @(
                New-MockUser -UserPrincipalName 'has.mfa@contoso.com' -DisplayName 'Has MFA'
                New-MockUser -UserPrincipalName 'no.mfa@contoso.com'  -DisplayName 'No MFA'
            )
            Mock Get-MgUser { $users }

            $authDetails = @(
                New-MockAuthRegistration -UserPrincipalName 'has.mfa@contoso.com' -IsMfaRegistered $true
            )

            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails $authDetails

            $result.UsersWithoutMFA | Should -HaveCount 1
            $result.UsersWithoutMFA[0].UserPrincipalName | Should -Be 'no.mfa@contoso.com'
        }
    }

    Context 'Edge cases' {
        It 'Returns Info status when no enabled users exist' {
            Mock Get-MgUser { @() }

            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails @()

            $result.Status   | Should -Be 'Info'
            $result.Severity | Should -Be 'Info'
        }

        It 'Returns Info status on Graph API error (never throws)' {
            Mock Get-MgUser { throw 'Insufficient privileges' }

            $result = Test-MFAConfiguration -Config $script:Config -AuthRegistrationDetails @()

            $result.Status   | Should -Be 'Info'
            $result.Severity | Should -Be 'Info'
            $result.Message  | Should -BeLike '*Unable to assess*'
        }

        It 'Uses default threshold when Config is null' {
            # 20 users, 19 with MFA = 95% (meets default threshold of 95)
            $users = 1..20 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..19 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            $result = Test-MFAConfiguration -Config $null -AuthRegistrationDetails $authDetails

            $result.Status | Should -Be 'Pass'
            $result.Details.Threshold | Should -Be 95
        }

        It 'Respects custom threshold from Config' {
            $customConfig = New-MockConfig -MFAThreshold 80
            # 10 users, 8 with MFA = 80% (meets custom threshold)
            $users = 1..10 | ForEach-Object { New-MockUser -UserPrincipalName "user$_@contoso.com" }
            Mock Get-MgUser { $users }

            $authDetails = 1..8 | ForEach-Object {
                New-MockAuthRegistration -UserPrincipalName "user$_@contoso.com" -IsMfaRegistered $true
            }

            $result = Test-MFAConfiguration -Config $customConfig -AuthRegistrationDetails $authDetails

            $result.Status | Should -Be 'Pass'
            $result.Details.Threshold | Should -Be 80
        }
    }
}
