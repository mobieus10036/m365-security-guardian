<#
.SYNOPSIS
    Tests SPF, DKIM, and DMARC email authentication configuration.

.DESCRIPTION
    Validates email authentication records for domain security and
    anti-spoofing protection. Performs actual DNS lookups to validate
    SPF and DMARC records.

.PARAMETER Config
    Configuration object.

.OUTPUTS
    PSCustomObject containing assessment results.

.NOTES
    Project: M365 Security Guardian
    Repository: https://github.com/mobieus10036/m365-security-guardian
    Author: mobieus10036
    Version: 3.0.0
    Created with assistance from GitHub Copilot
    Updated: 2025-11-09 - Added DNS validation for SPF and DMARC
#>

function Test-SPFDKIMDmarc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Config
    )

    try {
        Write-Verbose "Analyzing SPF, DKIM, DMARC configuration..."

        # Get accepted domains (exclude internal relay domains)
        $domains = Get-AcceptedDomain -ErrorAction SilentlyContinue | Where-Object { $_.DomainType -ne 'InternalRelay' }
        
        if ($null -eq $domains) {
            return [PSCustomObject]@{
                CheckName = "Email Authentication (SPF/DKIM/DMARC)"
                Category = "Exchange"
                Status = "Info"
                Severity = "Info"
                Message = "Unable to retrieve accepted domains"
                Details = @{}
                Recommendation = "Verify Exchange Online connection"
                DocumentationUrl = "https://learn.microsoft.com/defender-office-365/email-authentication-about"
                RemediationSteps = @()
            }
        }

        # Initialize counters
        $totalDomains = @($domains).Count
        $spfValid = 0
        $spfMissing = 0
        $spfInvalid = 0
        $dmarcValid = 0
        $dmarcMissing = 0
        $dmarcWeak = 0
        $dkimEnabled = 0
        
        $domainDetails = @()
        $issues = @()

        # Check each domain
        foreach ($domain in $domains) {
            $domainName = $domain.DomainName
            Write-Verbose "Checking domain: $domainName"
            
            $domainResult = [PSCustomObject]@{
                Domain = $domainName
                SPF = "Not Checked"
                SPFRecord = ""
                DKIM = "Not Checked"
                DMARC = "Not Checked"
                DMARCRecord = ""
                DMARCPolicy = ""
            }

            # Check SPF
            try {
                $spfRecord = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Strings -like "v=spf1*" } | 
                    Select-Object -First 1
                
                if ($spfRecord) {
                    $spfString = $spfRecord.Strings -join ""
                    $domainResult.SPFRecord = $spfString
                    
                    # Validate SPF includes Microsoft
                    if ($spfString -match "include:spf\.protection\.outlook\.com" -or 
                        $spfString -match "include:spf\.protection\.office365\.com") {
                        $domainResult.SPF = "Valid"
                        $spfValid++
                    }
                    else {
                        $domainResult.SPF = "Invalid (Missing Microsoft)"
                        $spfInvalid++
                        $issues += "$domainName - SPF exists but doesn't include Microsoft servers"
                    }
                }
                else {
                    $domainResult.SPF = "Missing"
                    $spfMissing++
                    $issues += "$domainName - No SPF record found"
                }
            }
            catch {
                $domainResult.SPF = "DNS Lookup Failed"
                Write-Verbose "SPF lookup failed for $domainName : $_"
            }

            # Check DKIM
            try {
                $dkimConfig = Get-DkimSigningConfig -Identity $domainName -ErrorAction SilentlyContinue
                if ($dkimConfig -and $dkimConfig.Enabled) {
                    $domainResult.DKIM = "Enabled"
                    $dkimEnabled++
                }
                else {
                    $domainResult.DKIM = "Disabled"
                    $issues += "$domainName - DKIM not enabled"
                }
            }
            catch {
                $domainResult.DKIM = "Check Failed"
                Write-Verbose "DKIM check failed for $domainName : $_"
            }

            # Check DMARC
            try {
                $dmarcDomain = "_dmarc.$domainName"
                $dmarcRecord = Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Strings -like "v=DMARC1*" } | 
                    Select-Object -First 1
                
                if ($dmarcRecord) {
                    $dmarcString = $dmarcRecord.Strings -join ""
                    $domainResult.DMARCRecord = $dmarcString
                    
                    # Extract policy
                    if ($dmarcString -match "p=([^;]+)") {
                        $policy = $matches[1]
                        $domainResult.DMARCPolicy = $policy
                        
                        if ($policy -eq "reject" -or $policy -eq "quarantine") {
                            $domainResult.DMARC = "Valid (Policy: $policy)"
                            $dmarcValid++
                        }
                        else {
                            $domainResult.DMARC = "Weak (Policy: $policy)"
                            $dmarcWeak++
                            $issues += "$domainName - DMARC policy is weak ($policy)"
                        }
                    }
                    else {
                        $domainResult.DMARC = "Invalid Format"
                        $dmarcMissing++
                    }
                }
                else {
                    $domainResult.DMARC = "Missing"
                    $dmarcMissing++
                    $issues += "$domainName - No DMARC record found"
                }
            }
            catch {
                $domainResult.DMARC = "DNS Lookup Failed"
                Write-Verbose "DMARC lookup failed for $domainName : $_"
            }

            $domainDetails += $domainResult
        }

        # Calculate percentages
        $spfPercentage = if ($totalDomains -gt 0) { [math]::Round(($spfValid / $totalDomains) * 100, 1) } else { 0 }
        $dkimPercentage = if ($totalDomains -gt 0) { [math]::Round(($dkimEnabled / $totalDomains) * 100, 1) } else { 0 }
        $dmarcPercentage = if ($totalDomains -gt 0) { [math]::Round(($dmarcValid / $totalDomains) * 100, 1) } else { 0 }

        # Determine overall status
        $status = "Pass"
        $severity = "Low"

        if ($spfMissing -gt 0 -or $dmarcMissing -gt 0 -or $dkimEnabled -eq 0) {
            $status = "Fail"
            $severity = "High"
        }
        elseif ($spfInvalid -gt 0 -or $dmarcWeak -gt 0 -or $dkimEnabled -lt $totalDomains) {
            $status = "Warning"
            $severity = "Medium"
        }

        # Build summary message
        $message = "Email Authentication Status: "
        $message += "SPF Valid: $spfValid/$totalDomains ($spfPercentage%), "
        $message += "DKIM Enabled: $dkimEnabled/$totalDomains ($dkimPercentage%), "
        $message += "DMARC Enforced: $dmarcValid/$totalDomains ($dmarcPercentage%)"

        if ($spfMissing -gt 0) { $message += " | $spfMissing domain(s) missing SPF" }
        if ($spfInvalid -gt 0) { $message += " | $spfInvalid domain(s) have invalid SPF" }
        if ($dmarcMissing -gt 0) { $message += " | $dmarcMissing domain(s) missing DMARC" }
        if ($dmarcWeak -gt 0) { $message += " | $dmarcWeak domain(s) have weak DMARC policy" }

        return [PSCustomObject]@{
            CheckName = "Email Authentication (SPF/DKIM/DMARC)"
            Category = "Exchange"
            Status = $status
            Severity = $severity
            Message = $message
            Details = @{
                TotalDomains = $totalDomains
                SPFValid = $spfValid
                SPFMissing = $spfMissing
                SPFInvalid = $spfInvalid
                SPFPercentage = $spfPercentage
                DKIMEnabled = $dkimEnabled
                DKIMPercentage = $dkimPercentage
                DMARCValid = $dmarcValid
                DMARCMissing = $dmarcMissing
                DMARCWeak = $dmarcWeak
                DMARCPercentage = $dmarcPercentage
                DomainDetails = $domainDetails
                Issues = $issues
            }
            DomainDetails = $domainDetails
            Recommendation = if ($status -eq "Pass") {
                "All domains have proper email authentication configured. Continue monitoring DMARC reports."
            } elseif ($status -eq "Warning") {
                "Some domains need attention. Review domain details and strengthen policies where needed."
            } else {
                "Critical: Multiple domains are missing email authentication. Implement SPF, DKIM, and DMARC immediately to prevent spoofing."
            }
            DocumentationUrl = "https://learn.microsoft.com/defender-office-365/email-authentication-about"
            RemediationSteps = @(
                "SPF: Add TXT record 'v=spf1 include:spf.protection.outlook.com -all' to domain DNS"
                "DKIM: Enable DKIM signing in Exchange admin center for each domain"
                "DKIM: Add CNAME records (selector1._domainkey and selector2._domainkey) provided by Microsoft to domain DNS"
                "DMARC: Add TXT record '_dmarc' with policy (start with 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com' for monitoring)"
                "Monitor DMARC reports for 2-4 weeks to identify legitimate sources"
                "Gradually enforce DMARC policy: Update to 'p=quarantine' for 2-4 weeks"
                "Final enforcement: Update to 'p=reject' once all legitimate sources are verified"
                "Documentation: https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure"
            )
        }
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "Email Authentication (SPF/DKIM/DMARC)"
            Category = "Exchange"
            Status = "Info"
            Severity = "Info"
            Message = "Unable to assess email authentication: $_"
            Details = @{ Error = $_.Exception.Message }
            Recommendation = "Ensure Exchange Online PowerShell is connected and DNS resolution is available"
            DocumentationUrl = "https://learn.microsoft.com/defender-office-365/email-authentication-about"
            RemediationSteps = @()
        }
    }
}
