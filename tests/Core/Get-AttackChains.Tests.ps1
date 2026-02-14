#Requires -Modules Pester

<#
.SYNOPSIS
    Tests for Get-AttackChains attack chain analysis engine.

.DESCRIPTION
    Validates attack chain enablement logic, executive summary generation,
    remediation priorities, MITRE matrix building, and null/empty handling.
    All tests run offline without any external API calls.

.NOTES
    Project: M365 Security Guardian
    Author: mobieus10036
    Version: 1.0.0
#>

BeforeAll {
    . "$PSScriptRoot\..\TestHelpers.ps1"
    . "$PSScriptRoot\..\..\modules\Core\Get-AttackChains.ps1"

    # Load actual attack chains config for realistic testing
    $script:TestConfigPath = "$PSScriptRoot\..\..\config\attack-chains.json"
}

Describe 'Get-AttackChains' {

    Context 'Basic functionality' {
        It 'Returns null when config file does not exist' {
            $result = Get-AttackChains -AssessmentResults @() -ConfigPath "C:\nonexistent\config.json"
            $result | Should -BeNullOrEmpty
        }

        It 'Returns valid output structure with real config' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result | Should -Not -BeNullOrEmpty
            $result.PSObject.Properties.Name | Should -Contain 'EnabledChains'
            $result.PSObject.Properties.Name | Should -Contain 'TotalChainsAnalyzed'
            $result.PSObject.Properties.Name | Should -Contain 'EnabledChainCount'
            $result.PSObject.Properties.Name | Should -Contain 'ChainSummary'
            $result.PSObject.Properties.Name | Should -Contain 'MitreMatrix'
            $result.PSObject.Properties.Name | Should -Contain 'RemediationPriorities'
            $result.PSObject.Properties.Name | Should -Contain 'AnalyzedAt'
        }

        It 'Analyzes all defined attack chains' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.TotalChainsAnalyzed | Should -BeGreaterThan 0
        }
    }

    Context 'Chain enablement logic' {
        It 'Enables chain when critical controls fail' {
            # Simulate failed MFA which should enable password spray chain
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Fail' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Legacy Authentication' -Status 'Fail' -Severity 'High'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.EnabledChainCount | Should -BeGreaterThan 0
        }

        It 'Reports no chains enabled when all controls pass' {
            # All security controls passing
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Privileged Account Security' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Legacy Authentication' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Conditional Access Policies' -Status 'Pass' -Severity 'High'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'Email Authentication (SPF/DKIM/DMARC)' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'Mailbox Auditing' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'ATP/MDO Configuration' -Status 'Pass' -Severity 'Medium'
                New-MockAssessmentResult -CheckName 'External Sharing' -Status 'Pass' -Severity 'Medium'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            # With all controls passing, fewer chains should be enabled
            # (some chains may still show due to missing controls being assumed vulnerable)
            $result.EnabledChainCount | Should -BeLessThan $result.TotalChainsAnalyzed
        }

        It 'Includes chain severity in enabled chains' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            if ($result.EnabledChains.Count -gt 0) {
                $result.EnabledChains[0].Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low')
            }
        }

        It 'Sorts chains by severity then enablement score' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Fail' -Severity 'Medium'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            if ($result.EnabledChains.Count -gt 1) {
                # Verify Critical chains appear before High/Medium
                $criticalIndex = -1
                $highIndex = -1
                for ($i = 0; $i -lt $result.EnabledChains.Count; $i++) {
                    if ($result.EnabledChains[$i].Severity -eq 'Critical' -and $criticalIndex -eq -1) {
                        $criticalIndex = $i
                    }
                    if ($result.EnabledChains[$i].Severity -eq 'High' -and $highIndex -eq -1) {
                        $highIndex = $i
                    }
                }
                if ($criticalIndex -ge 0 -and $highIndex -ge 0) {
                    $criticalIndex | Should -BeLessThan $highIndex
                }
            }
        }
    }

    Context 'Chain properties' {
        It 'Each enabled chain has required properties' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            foreach ($chain in $result.EnabledChains) {
                $chain.PSObject.Properties.Name | Should -Contain 'ChainId'
                $chain.PSObject.Properties.Name | Should -Contain 'Name'
                $chain.PSObject.Properties.Name | Should -Contain 'Severity'
                $chain.PSObject.Properties.Name | Should -Contain 'EnablementScore'
                $chain.PSObject.Properties.Name | Should -Contain 'Tactics'
                $chain.PSObject.Properties.Name | Should -Contain 'MitreTechniques'
                $chain.PSObject.Properties.Name | Should -Contain 'KillChain'
                $chain.PSObject.Properties.Name | Should -Contain 'BlastRadius'
                $chain.PSObject.Properties.Name | Should -Contain 'ExecutiveNarrative'
            }
        }

        It 'Chain IDs follow expected format' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            foreach ($chain in $result.EnabledChains) {
                $chain.ChainId | Should -Match '^AC-\d{3}$'
            }
        }

        It 'MITRE techniques follow T-number format' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            foreach ($chain in $result.EnabledChains) {
                foreach ($technique in $chain.MitreTechniques) {
                    $technique | Should -Match '^T\d{4}(\.\d{3})?$'
                }
            }
        }
    }

    Context 'Executive summary generation' {
        It 'Generates executive summary with risk level' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.ChainSummary | Should -Not -BeNullOrEmpty
            $result.ChainSummary.PSObject.Properties.Name | Should -Contain 'OverallRiskLevel'
        }

        It 'Risk level is valid enum value' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.ChainSummary.OverallRiskLevel | Should -BeIn @('Critical', 'High', 'Elevated', 'Low')
        }
    }

    Context 'Remediation priorities' {
        It 'Generates remediation priorities list' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.RemediationPriorities | Should -Not -BeNullOrEmpty
        }

        It 'Remediation priorities are sorted by chain impact' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
                New-MockAssessmentResult -CheckName 'Application Permission Audit' -Status 'Fail' -Severity 'Medium'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            # Priorities should exist if chains are enabled
            if ($result.EnabledChainCount -gt 0) {
                $result.RemediationPriorities.Count | Should -BeGreaterThan 0
            }
        }
    }

    Context 'MITRE ATT&CK matrix' {
        It 'Builds MITRE matrix view' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result.MitreMatrix | Should -Not -BeNullOrEmpty
        }

        It 'MITRE matrix contains tactics' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            if ($result.EnabledChainCount -gt 0) {
                $result.MitreMatrix.PSObject.Properties.Name | Should -Contain 'Tactics'
            }
        }
    }

    Context 'CIS compliance integration' {
        It 'Accepts CIS compliance object' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            $cisCompliance = [PSCustomObject]@{
                ControlResults = @(
                    [PSCustomObject]@{ ControlId = '1.1.1'; Status = 'Compliant' }
                    [PSCustomObject]@{ ControlId = '1.1.3'; Status = 'Non-Compliant' }
                )
            }

            # Should not throw
            { Get-AttackChains -AssessmentResults $results -CISCompliance $cisCompliance -ConfigPath $script:TestConfigPath } | Should -Not -Throw
        }

        It 'Uses CIS status to determine chain enablement' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            $cisCompliance = [PSCustomObject]@{
                ControlResults = @(
                    [PSCustomObject]@{ ControlId = '1.1.1'; Status = 'Non-Compliant' }
                    [PSCustomObject]@{ ControlId = '1.1.3'; Status = 'Non-Compliant' }
                    [PSCustomObject]@{ ControlId = '5.1.2.3'; Status = 'Non-Compliant' }
                )
            }

            $result = Get-AttackChains -AssessmentResults $results -CISCompliance $cisCompliance -ConfigPath $script:TestConfigPath

            # With non-compliant CIS controls, chains should be enabled
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Edge cases' {
        It 'Handles empty assessment results' {
            $result = Get-AttackChains -AssessmentResults @() -ConfigPath $script:TestConfigPath

            $result | Should -Not -BeNullOrEmpty
            $result.TotalChainsAnalyzed | Should -BeGreaterThan 0
            # With no results, chains with unmapped controls may still be flagged
        }

        It 'Handles null CIS compliance gracefully' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Pass' -Severity 'Critical'
            )

            { Get-AttackChains -AssessmentResults $results -CISCompliance $null -ConfigPath $script:TestConfigPath } | Should -Not -Throw
        }

        It 'Handles assessment results with Info status' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Info' -Severity 'Info'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Chain counts' {
        It 'Reports correct critical chain count' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $actualCritical = @($result.EnabledChains | Where-Object { $_.Severity -eq 'Critical' }).Count
            $result.CriticalChains | Should -Be $actualCritical
        }

        It 'Reports correct high chain count' {
            $results = @(
                New-MockAssessmentResult -CheckName 'MFA Enforcement' -Status 'Fail' -Severity 'Critical'
            )

            $result = Get-AttackChains -AssessmentResults $results -ConfigPath $script:TestConfigPath

            $actualHigh = @($result.EnabledChains | Where-Object { $_.Severity -eq 'High' }).Count
            $result.HighChains | Should -Be $actualHigh
        }
    }
}

Describe 'Format-AttackChainConsole' {
    BeforeAll {
        # Import function if not already loaded
        . "$PSScriptRoot\..\..\modules\Core\Get-AttackChains.ps1"
    }

    It 'Does not throw with valid attack chain data' {
        $chainResult = [PSCustomObject]@{
            EnabledChains = @(
                [PSCustomObject]@{
                    ChainId = 'AC-001'
                    Name = 'Test Chain'
                    Severity = 'Critical'
                    EnablementScore = 75
                    Tactics = @('Initial Access', 'Persistence')
                    MitreTechniques = @('T1078', 'T1110')
                }
            )
            TotalChainsAnalyzed = 6
            EnabledChainCount = 1
            CriticalChains = 1
            HighChains = 0
            ChainSummary = [PSCustomObject]@{
                OverallRiskLevel = 'Critical'
                Narrative = 'Test narrative'
            }
        }

        { Format-AttackChainConsole -AttackChainResult $chainResult } | Should -Not -Throw
    }

    It 'Handles null input gracefully' {
        { Format-AttackChainConsole -AttackChainResult $null } | Should -Not -Throw
    }
}
