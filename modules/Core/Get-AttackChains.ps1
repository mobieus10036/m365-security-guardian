<#
.SYNOPSIS
    Analyzes assessment results to identify enabled attack chains.

.DESCRIPTION
    Maps security findings to real-world attack patterns, calculating
    which exploitation paths are enabled by the tenant's current
    security posture. Produces executive-ready risk narratives.

.PARAMETER AssessmentResults
    Array of assessment results from all modules.

.PARAMETER CISCompliance
    CIS compliance mapping results (optional, enhances accuracy).

.PARAMETER ConfigPath
    Path to attack-chains.json configuration file.

.OUTPUTS
    PSCustomObject containing:
    - EnabledChains (attack chains enabled by current misconfigurations)
    - ChainSummary (executive summary of risk posture)
    - MitreMatrix (techniques exploitable in tenant)
    - RemediationPriorities (ordered list of fixes to break chains)

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.2.0
    Created with assistance from GitHub Copilot
#>

function Get-AttackChains {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$AssessmentResults,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$CISCompliance,

        [Parameter(Mandatory = $false)]
        [string]$ConfigPath
    )

    # Load attack chain definitions
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $PSScriptRoot "..\..\config\attack-chains.json"
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Warning "Attack chain definitions not found at: $ConfigPath"
        return $null
    }

    try {
        $chainConfig = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Warning "Failed to load attack chain configuration: $_"
        return $null
    }

    # Build lookup for assessment results by CheckName
    $resultLookup = @{}
    foreach ($result in $AssessmentResults) {
        $resultLookup[$result.CheckName] = $result
    }

    # Build CIS compliance lookup if available
    $cisLookup = @{}
    if ($CISCompliance -and $CISCompliance.ControlResults) {
        foreach ($control in $CISCompliance.ControlResults) {
            $cisLookup[$control.ControlId] = $control
        }
    }

    # Analyze each attack chain
    $enabledChains = @()
    $allMitreTechniques = @{}
    
    foreach ($chain in $chainConfig.attackChains) {
        $chainAnalysis = Invoke-ChainAnalysis -Chain $chain -ResultLookup $resultLookup -CISLookup $cisLookup
        
        if ($chainAnalysis.IsEnabled) {
            $enabledChains += [PSCustomObject]@{
                ChainId             = $chain.id
                Name                = $chain.name
                Severity            = $chain.severity
                EnablementScore     = $chainAnalysis.EnablementScore
                EnabledConditions   = $chainAnalysis.EnabledConditions
                MissingControls     = $chainAnalysis.MissingControls
                Tactics             = $chain.tactics
                MitreTechniques     = $chain.mitreTechniques
                KillChain           = $chain.killChainPhases
                BlastRadius         = $chain.blastRadius
                ExecutiveNarrative  = $chain.executiveNarrative
                RemediationPriority = $chain.remediationPriority
                EstimatedFixTime    = $chain.estimatedRemediationTime
                References          = $chain.references
            }
            
            # Aggregate MITRE techniques
            foreach ($technique in $chain.mitreTechniques) {
                if (-not $allMitreTechniques.ContainsKey($technique)) {
                    $allMitreTechniques[$technique] = @{
                        Technique = $technique
                        Chains    = @()
                    }
                }
                $allMitreTechniques[$technique].Chains += $chain.id
            }
        }
    }

    # Sort by severity and enablement score
    $sortedChains = $enabledChains | Sort-Object -Property @{Expression = {
        switch ($_.Severity) {
            'Critical' { 0 }
            'High'     { 1 }
            'Medium'   { 2 }
            'Low'      { 3 }
            default    { 4 }
        }
    }}, @{Expression = { $_.EnablementScore }; Descending = $true }

    # Generate executive summary
    $summary = Get-ChainExecutiveSummary -EnabledChains $sortedChains -TotalChains $chainConfig.attackChains.Count

    # Generate remediation priorities (which fixes break the most chains)
    $remediationPriorities = Get-RemediationPriorities -EnabledChains $sortedChains

    # Build MITRE matrix view
    $mitreMatrix = Get-MitreMatrixView -EnabledChains $sortedChains -TacticsMapping $chainConfig.tacticsMapping

    return [PSCustomObject]@{
        EnabledChains         = $sortedChains
        TotalChainsAnalyzed   = $chainConfig.attackChains.Count
        EnabledChainCount     = $sortedChains.Count
        CriticalChains        = @($sortedChains | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighChains            = @($sortedChains | Where-Object { $_.Severity -eq 'High' }).Count
        ChainSummary          = $summary
        MitreMatrix           = $mitreMatrix
        RemediationPriorities = $remediationPriorities
        AnalyzedAt            = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

function Invoke-ChainAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Chain,

        [Parameter(Mandatory = $true)]
        [hashtable]$ResultLookup,

        [Parameter(Mandatory = $false)]
        [hashtable]$CISLookup
    )

    $enabledConditions = @()
    $missingControls = @()
    $totalWeight = 0
    $enabledWeight = 0

    foreach ($condition in $Chain.enablingConditions) {
        $totalWeight += $condition.weight
        $controlId = $condition.controlId
        
        # Check CIS compliance first
        $isEnabled = $false
        if ($CISLookup.ContainsKey($controlId)) {
            $cisControl = $CISLookup[$controlId]
            if ($cisControl.Status -in @('Non-Compliant', 'Partial')) {
                $isEnabled = $true
            }
        }
        else {
            # Fallback to assessment result mapping
            # Map CIS control sections to assessment check names
            $assessmentKey = Get-AssessmentKeyFromCIS -ControlId $controlId
            if ($assessmentKey -and $ResultLookup.ContainsKey($assessmentKey)) {
                $result = $ResultLookup[$assessmentKey]
                if ($result.Status -in @('Fail', 'Warning')) {
                    $isEnabled = $true
                }
            }
            else {
                # Control not assessed - assume potential vulnerability
                $isEnabled = $true
                $missingControls += $controlId
            }
        }

        if ($isEnabled) {
            $enabledWeight += $condition.weight
            $enabledConditions += [PSCustomObject]@{
                ControlId = $controlId
                Condition = $condition.condition
                Weight    = $condition.weight
            }
        }
    }

    # Chain is considered "enabled" if more than 50% of weighted conditions are met
    $enablementScore = if ($totalWeight -gt 0) { [math]::Round(($enabledWeight / $totalWeight) * 100, 1) } else { 0 }
    $isEnabled = $enablementScore -ge 50

    return [PSCustomObject]@{
        IsEnabled         = $isEnabled
        EnablementScore   = $enablementScore
        EnabledConditions = $enabledConditions
        MissingControls   = $missingControls
    }
}

function Get-AssessmentKeyFromCIS {
    [CmdletBinding()]
    param(
        [string]$ControlId
    )

    # Map CIS control IDs to assessment CheckNames
    $mapping = @{
        '1.1.1'   = 'Conditional Access Policies'
        '1.1.3'   = 'Privileged Account Security'
        '1.2.1'   = 'MFA Enforcement'
        '1.2.2'   = 'MFA Enforcement'
        '2.1.2'   = 'Application Permissions Audit'
        '2.1.3'   = 'Application Permissions Audit'
        '2.1.4'   = 'Application Permissions Audit'
        '5.1.1.1' = 'Legacy Authentication Blocking'
        '5.1.2.1' = 'Conditional Access Policies'
        '5.1.2.2' = 'Conditional Access Policies'
        '5.1.2.3' = 'Conditional Access Policies'
        '5.1.2.4' = 'Conditional Access Policies'
        '5.1.2.5' = 'Conditional Access Policies'
        '5.1.5.1' = 'Privileged Identity Management (PIM)'
        '6.2.1'   = 'Mailbox Auditing'
        '6.5.1'   = 'Email Authentication (SPF/DKIM/DMARC)'
        '6.5.2'   = 'Email Authentication (SPF/DKIM/DMARC)'
        '6.5.3'   = 'Email Authentication (SPF/DKIM/DMARC)'
        '7.2.1'   = 'External Sharing Configuration'
        '7.2.2'   = 'External Sharing Configuration'
        '7.2.3'   = 'External Sharing Configuration'
    }

    return $mapping[$ControlId]
}

function Get-ChainExecutiveSummary {
    [CmdletBinding()]
    param(
        [array]$EnabledChains,
        [int]$TotalChains
    )

    $criticalCount = @($EnabledChains | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($EnabledChains | Where-Object { $_.Severity -eq 'High' }).Count

    $riskLevel = if ($criticalCount -gt 0) {
        'Critical'
    } elseif ($highCount -gt 0) {
        'High'
    } elseif ($EnabledChains.Count -gt 0) {
        'Elevated'
    } else {
        'Low'
    }

    $narrative = @()
    $narrative += "ATTACK CHAIN RISK ASSESSMENT"
    $narrative += "============================"
    $narrative += ""
    $narrative += "Overall Risk Level: $riskLevel"
    $narrative += "Enabled Attack Chains: $($EnabledChains.Count) of $TotalChains analyzed"
    $narrative += ""

    if ($criticalCount -gt 0) {
        $narrative += "! CRITICAL: $criticalCount attack chain(s) could lead to full tenant compromise"
    }
    if ($highCount -gt 0) {
        $narrative += "! HIGH: $highCount attack chain(s) could result in significant data breach"
    }

    $narrative += ""
    $narrative += "Top Threats:"
    
    $topThreats = $EnabledChains | Select-Object -First 3
    foreach ($threat in $topThreats) {
        $narrative += "  - [$($threat.Severity)] $($threat.Name)"
        $narrative += "    Enablement: $($threat.EnablementScore)% | Fix Time: $($threat.EstimatedFixTime)"
    }

    return [PSCustomObject]@{
        OverallRiskLevel = $riskLevel
        EnabledChainCount = $EnabledChains.Count
        TotalChains = $TotalChains
        CriticalChains = $criticalCount
        HighChains = $highCount
        Narrative = $narrative -join "`n"
    }
}

function Get-RemediationPriorities {
    [CmdletBinding()]
    param(
        [array]$EnabledChains
    )

    # Count how many chains each control enables
    $controlImpact = @{}
    
    foreach ($chain in $EnabledChains) {
        $severityMultiplier = switch ($chain.Severity) {
            'Critical' { 4 }
            'High'     { 3 }
            'Medium'   { 2 }
            'Low'      { 1 }
            default    { 1 }
        }
        
        foreach ($condition in $chain.EnabledConditions) {
            $controlId = $condition.ControlId
            if (-not $controlImpact.ContainsKey($controlId)) {
                $controlImpact[$controlId] = [PSCustomObject]@{
                    ControlId = $controlId
                    ChainsAffected = @()
                    TotalImpact = 0
                }
            }
            $controlImpact[$controlId].ChainsAffected += $chain.ChainId
            $controlImpact[$controlId].TotalImpact += $condition.Weight * $severityMultiplier
        }
    }

    # Sort by impact (fixing this control breaks the most/worst chains)
    $priorities = $controlImpact.Values | 
        Sort-Object -Property TotalImpact -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                ControlId       = $_.ControlId
                ChainsAffected  = $_.ChainsAffected.Count
                ChainIds        = $_.ChainsAffected -join ', '
                ImpactScore     = $_.TotalImpact
            }
        }

    return $priorities
}

function Get-MitreMatrixView {
    [CmdletBinding()]
    param(
        [array]$EnabledChains,
        [PSCustomObject]$TacticsMapping
    )

    $tacticCoverage = @{}
    $techniqueCoverage = @{}

    foreach ($chain in $EnabledChains) {
        foreach ($tactic in $chain.Tactics) {
            if (-not $tacticCoverage.ContainsKey($tactic)) {
                $tacticCoverage[$tactic] = @{
                    Tactic = $tactic
                    TacticId = if ($TacticsMapping.$tactic) { $TacticsMapping.$tactic } else { 'Unknown' }
                    Chains = @()
                }
            }
            $tacticCoverage[$tactic].Chains += $chain.ChainId
        }

        foreach ($technique in $chain.MitreTechniques) {
            if (-not $techniqueCoverage.ContainsKey($technique)) {
                $techniqueCoverage[$technique] = @{
                    TechniqueId = $technique
                    Chains = @()
                }
            }
            $techniqueCoverage[$technique].Chains += $chain.ChainId
        }
    }

    return [PSCustomObject]@{
        Tactics              = $tacticCoverage.Values | Sort-Object -Property { $_.Chains.Count } -Descending
        Techniques           = $techniqueCoverage.Values | Sort-Object -Property { $_.Chains.Count } -Descending
        TacticsExploitable    = $tacticCoverage.Values | Sort-Object -Property { $_.Chains.Count } -Descending
        TechniquesExploitable = $techniqueCoverage.Values | Sort-Object -Property { $_.Chains.Count } -Descending
        TotalTactics         = $tacticCoverage.Count
        TotalTechniques      = $techniqueCoverage.Count
    }
}

function Format-AttackChainConsole {
    <#
    .SYNOPSIS
        Formats attack chain results for console output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$AttackChainResults
    )

    if (-not $AttackChainResults) {
        return ""
    }

    $output = @()
    $output += ""
    $output += "╔══════════════════════════════════════════════════════════════════════╗"
    $output += "║                    ATTACK CHAIN ANALYSIS                             ║"
    $output += "╚══════════════════════════════════════════════════════════════════════╝"
    $output += ""

    $criticalCount = $AttackChainResults.CriticalChains
    $highCount = $AttackChainResults.HighChains
    $totalEnabled = $AttackChainResults.EnabledChainCount
    $totalAnalyzed = $AttackChainResults.TotalChainsAnalyzed

    # Risk level indicator
    $riskLevel = if ($criticalCount -gt 0) { 'CRITICAL' }
                 elseif ($highCount -gt 0) { 'HIGH' }
                 elseif ($totalEnabled -gt 0) { 'ELEVATED' }
                 else { 'LOW' }

    $riskColor = switch ($riskLevel) {
        'CRITICAL' { '!' }
        'HIGH'     { '!' }
        'ELEVATED' { '~' }
        'LOW'      { '+' }
    }

    $output += "  [$riskColor] Attack Chain Risk: $riskLevel"
    $output += "  Enabled Chains: $totalEnabled of $totalAnalyzed analyzed"
    
    if ($criticalCount -gt 0) {
        $output += "  ! Critical Chains: $criticalCount (immediate action required)"
    }
    if ($highCount -gt 0) {
        $output += "  ! High-Risk Chains: $highCount"
    }

    $output += ""
    $output += "  Enabled Attack Chains:"
    
    foreach ($chain in $AttackChainResults.EnabledChains) {
        $severityBadge = switch ($chain.Severity) {
            'Critical' { '[!!!]' }
            'High'     { '[!!]' }
            'Medium'   { '[!]' }
            'Low'      { '[~]' }
        }
        $output += "    $severityBadge $($chain.Name)"
        $output += "        Tactics: $($chain.Tactics -join ' → ')"
        $output += "        Enablement: $($chain.EnablementScore)% | Fix Time: $($chain.EstimatedFixTime)"
    }

    if ($AttackChainResults.RemediationPriorities.Count -gt 0) {
        $output += ""
        $output += "  Top Remediation Priorities (breaks most chains):"
        $top3 = $AttackChainResults.RemediationPriorities | Select-Object -First 3
        foreach ($priority in $top3) {
            $output += "    → Control $($priority.ControlId): Affects $($priority.ChainsAffected) chain(s)"
        }
    }

    $output += ""

    return $output -join "`n"
}

# Export functions only when loaded as a module
if ($MyInvocation.MyCommand.ScriptBlock.Module) {
    Export-ModuleMember -Function Get-AttackChains, Format-AttackChainConsole
}
