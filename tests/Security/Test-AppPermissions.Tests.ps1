#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Test-AppPermissions assessment module.

.DESCRIPTION
    Validates application permission audit logic, including phase-1 app category
    segmentation for Enterprise Applications, Microsoft Applications, and Managed Identities.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Security\Test-AppPermissions.ps1"
}

Describe 'Test-AppPermissions' {

    Context 'Result contract' {
        It 'Returns an object with all required properties' {
            Mock Get-MgServicePrincipal {
                @(
                    [PSCustomObject]@{
                        Id = 'sp-contract'
                        DisplayName = 'Contract Test App'
                        AppId = '44444444-4444-4444-4444-444444444444'
                        ServicePrincipalType = 'Application'
                        AccountEnabled = $true
                        CreatedDateTime = (Get-Date).AddDays(-5)
                        SignInAudience = 'AzureADMyOrg'
                        AppRoles = @()
                        Oauth2PermissionScopes = @()
                        Tags = @()
                        PublisherName = 'Contoso Ltd'
                        AppOwnerOrganizationId = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
                    }
                )
            }
            Mock Get-MgOauth2PermissionGrant { @() }
            Mock Get-MgServicePrincipalAppRoleAssignment { @() }
            Mock Get-MgApplication { @() }
            Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*authorizationPolicy' } {
                [PSCustomObject]@{
                    defaultUserRolePermissions = [PSCustomObject]@{
                        permissionGrantPoliciesAssigned = @()
                    }
                }
            }
            Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*adminConsentRequestPolicy' } {
                [PSCustomObject]@{ isEnabled = $true }
            }

            $result = Test-AppPermissions -Config (New-MockConfig)

            Assert-AssessmentResult $result
            $result.CheckName | Should -Be 'Application Permissions Audit'
            $result.Category | Should -Be 'Security'
        }
    }

    Context 'Category segmentation' {
        It 'Classifies and segments risky apps across enterprise, Microsoft, and managed identity categories' {
            $servicePrincipals = @(
                [PSCustomObject]@{
                    Id = 'sp-enterprise'
                    DisplayName = 'Contoso CRM'
                    AppId = '11111111-1111-1111-1111-111111111111'
                    ServicePrincipalType = 'Application'
                    AccountEnabled = $true
                    CreatedDateTime = (Get-Date).AddDays(-90)
                    SignInAudience = 'AzureADMyOrg'
                    AppRoles = @()
                    Oauth2PermissionScopes = @()
                    Tags = @()
                    PublisherName = 'Contoso Ltd'
                    AppOwnerOrganizationId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                },
                [PSCustomObject]@{
                    Id = 'sp-microsoft'
                    DisplayName = 'Microsoft Graph'
                    AppId = '22222222-2222-2222-2222-222222222222'
                    ServicePrincipalType = 'Application'
                    AccountEnabled = $true
                    CreatedDateTime = (Get-Date).AddDays(-120)
                    SignInAudience = 'AzureADMyOrg'
                    AppRoles = @()
                    Oauth2PermissionScopes = @()
                    Tags = @('WindowsAzureActiveDirectoryIntegratedApp')
                    PublisherName = 'Microsoft Services'
                    AppOwnerOrganizationId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
                },
                [PSCustomObject]@{
                    Id = 'sp-managed-identity'
                    DisplayName = 'mi-payroll-worker'
                    AppId = '33333333-3333-3333-3333-333333333333'
                    ServicePrincipalType = 'ManagedIdentity'
                    AccountEnabled = $true
                    CreatedDateTime = (Get-Date).AddDays(-30)
                    SignInAudience = 'AzureADMyOrg'
                    AppRoles = @()
                    Oauth2PermissionScopes = @()
                    Tags = @()
                    PublisherName = $null
                    AppOwnerOrganizationId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
                }
            )

            $oauthGrants = @(
                [PSCustomObject]@{ ClientId = 'sp-enterprise'; Scope = 'Directory.ReadWrite.All'; ConsentType = 'AllPrincipals' },
                [PSCustomObject]@{ ClientId = 'sp-microsoft'; Scope = 'Directory.ReadWrite.All'; ConsentType = 'AllPrincipals' },
                [PSCustomObject]@{ ClientId = 'sp-managed-identity'; Scope = 'Directory.ReadWrite.All'; ConsentType = 'AllPrincipals' }
            )

            Mock Get-MgServicePrincipal { $servicePrincipals }
            Mock Get-MgOauth2PermissionGrant { $oauthGrants }
            Mock Get-MgServicePrincipalAppRoleAssignment { @() }
            Mock Get-MgApplication { @() }

            Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*authorizationPolicy' } {
                [PSCustomObject]@{
                    defaultUserRolePermissions = [PSCustomObject]@{
                        permissionGrantPoliciesAssigned = @()
                    }
                }
            }

            Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*adminConsentRequestPolicy' } {
                [PSCustomObject]@{ isEnabled = $true }
            }

            $result = Test-AppPermissions -Config (New-MockConfig)

            Assert-AssessmentResult $result
            $result.Details.TotalAnalyzedServicePrincipals | Should -Be 3
            $result.Details.EnterpriseApplications | Should -Be 1
            $result.Details.MicrosoftApplications | Should -Be 1
            $result.Details.ManagedIdentities | Should -Be 1

            $result.RiskyApps | Should -HaveCount 3
            $result.RiskyEnterpriseApps | Should -HaveCount 1
            $result.RiskyMicrosoftApplications | Should -HaveCount 1
            $result.RiskyManagedIdentities | Should -HaveCount 1

            ($result.RiskyEnterpriseApps[0].AppCategory) | Should -Be 'Enterprise Application'
            ($result.RiskyMicrosoftApplications[0].AppCategory) | Should -Be 'Microsoft Application'
            ($result.RiskyManagedIdentities[0].AppCategory) | Should -Be 'Managed Identity'
        }
    }

    Context 'Error handling' {
        It 'Returns Info status when Graph retrieval fails' {
            Mock Get-MgServicePrincipal { throw 'Graph unavailable' }

            $result = Test-AppPermissions -Config (New-MockConfig)

            $result.Status | Should -Be 'Info'
            $result.Severity | Should -Be 'Info'
            $result.Message | Should -BeLike '*Unable to audit application permissions*'
        }
    }
}
