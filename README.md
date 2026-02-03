# M365 Security Assessment 🛡️

**Official GitHub repository:** [https://github.com/mobieus10036/m365-security-assessment](https://github.com/mobieus10036/m365-security-assessment)

**Rapid, actionable Microsoft 365 security assessment for modern enterprises.**

![Version](https://img.shields.io/badge/version-3.1.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/github/license/mobieus10036/m365-security-assessment)

---

## ✨ What's New in v3.1.0

- **📊 Baseline Comparison** - Track security progress over time by comparing against saved baselines
- **🏛️ CIS Benchmark Mapping** - Maps findings to CIS Microsoft 365 Foundations Benchmark v3.1.0
- **🎯 MITRE ATT&CK Integration** - Each CIS control includes relevant MITRE technique IDs
- **📈 Dual Compliance Levels** - Separate compliance percentages for CIS Level 1 (Essential) and Level 2 (Enhanced)
- **🔐 Certificate Auth Auto-Load** - Save auth config once, run without parameters
- **🧹 Connection Cleanup** - Automatically clears stale connections before each run
- **📈 Enhanced Reporting** - CIS compliance and baseline comparison in HTML reports

---

## Features

### 🎯 Tenant Security Score
- Overall security posture score (0-100) with letter grade (A-F)
- Category breakdown: Identity & Access, Conditional Access, Application Security, Email Security, Governance
- **Top Priorities** - Highest impact remediation items ranked by potential score improvement
- **Quick Wins** - Low-effort, high-impact fixes for immediate security gains
- Weighted scoring based on actual security impact

### 🏛️ CIS Microsoft 365 Benchmark Compliance
- Maps all findings to **CIS Microsoft 365 Foundations Benchmark v3.1.0**
- Separate compliance tracking for **Level 1 (Essential)** and **Level 2 (Enhanced)** controls
- 24 CIS controls assessed across 5 security domains
- **MITRE ATT&CK technique mappings** for each control
- Audit-ready reports for compliance frameworks (SOC 2, ISO 27001, etc.)

### 🔍 Security Assessments
| Module | Checks |
|--------|--------|
| **Identity** | MFA adoption, Privileged accounts, PIM configuration, Legacy auth |
| **Conditional Access** | Policy coverage, Risk-based policies, Device compliance, Location controls |
| **Applications** | High-risk permissions, Credential expiry, Multi-tenant apps, OAuth grants |
| **Email** | SPF/DKIM/DMARC validation, Mailbox auditing, Anti-spam/malware policies |
| **Licensing** | Inactive license detection, Optimization opportunities |

### 📄 Report Outputs
- **HTML** - Interactive dashboard with filtering and export
- **JSON** - Machine-readable for automation and SIEM integration
- **CSV** - Spreadsheet-compatible for analysis and sharing
- **CIS Compliance** - Dedicated JSON/CSV exports for audit tools

---

## Quickstart

```powershell
git clone https://github.com/mobieus10036/m365-security-assessment.git
cd m365-security-assessment
.\Install-Prerequisites.ps1
.\Start-M365Assessment.ps1
```

---

## Authentication

The tool supports multiple authentication methods:

| Method | Best For | Command |
|--------|----------|---------|
| **Certificate** ⭐ | Recommended - Reliable & automated | `.\Start-M365Assessment.ps1` (after setup) |
| **DeviceCode** | Terminal use, multi-tenant | `.\Start-M365Assessment.ps1 -AuthMethod DeviceCode` |
| **Interactive** | Quick browser-based runs | `.\Start-M365Assessment.ps1 -AuthMethod Interactive` |
| **ManagedIdentity** | Azure-hosted (VMs, Functions) | `.\Start-M365Assessment.ps1 -AuthMethod ManagedIdentity` |

### 🔐 Certificate Authentication Setup (Recommended)

Certificate auth provides the most reliable experience, especially in VS Code or embedded terminals.

```powershell
# Run the setup script to create app registration with certificate
.\Setup-AppRegistration-CLI.ps1

# After setup, simply run without parameters - auth config auto-loads
.\Start-M365Assessment.ps1
```

The setup creates:
- Entra ID App Registration with required permissions
- Self-signed certificate (valid 1 year)
- `.auth-config.ps1` file with saved credentials

### Multi-Tenant Assessments (Consultants)

```powershell
# Assess a specific tenant
.\Start-M365Assessment.ps1 -TenantId "contoso.onmicrosoft.com" -AuthMethod DeviceCode
```

### Required API Permissions

For app-only (Certificate/ManagedIdentity) authentication:

**Microsoft Graph (Application)**
| Permission | Purpose |
|------------|---------|
| `User.Read.All` | MFA status, user enumeration |
| `Directory.Read.All` | Privileged roles, group membership |
| `Policy.Read.All` | Conditional Access policies |
| `Organization.Read.All` | Tenant information |
| `AuditLog.Read.All` | Sign-in logs, last sign-in dates |
| `SecurityEvents.Read.All` | Microsoft Secure Score (E5 only) |
| `Application.Read.All` | App permissions audit |
| `RoleManagement.Read.All` | PIM configuration |
| `RoleManagement.Read.Directory` | Directory role assignments |
| `SharePointTenantSettings.Read.All` | External sharing configuration |

---

## Security Score

The assessment calculates an **overall Tenant Security Score**:

| Grade | Score Range | Description |
|-------|-------------|-------------|
| **A** | 90-100% | Excellent - Your tenant follows security best practices |
| **B** | 80-89% | Good - Minor improvements recommended |
| **C** | 70-79% | Fair - Several security gaps should be addressed |
| **D** | 60-69% | Poor - Significant security risks require attention |
| **F** | 0-59% | Critical - Immediate action required |

### Category Weights
| Category | Weight | Key Checks |
|----------|--------|------------|
| Identity & Access | 30% | MFA, Privileged Accounts, PIM, Legacy Auth |
| Conditional Access | 25% | CA Policies, External Sharing |
| Application Security | 20% | App Permissions, Secure Score |
| Email Security | 15% | SPF/DKIM/DMARC, Mailbox Auditing |
| Governance | 10% | License Optimization |

---

## CIS Benchmark Mapping

All findings are mapped to the **CIS Microsoft 365 Foundations Benchmark v3.1.0**:

```
╔══════════════════════════════════════════════════════════════════════╗
║            CIS Microsoft 365 Foundations Benchmark                   ║
║                    Compliance Assessment                             ║
╚══════════════════════════════════════════════════════════════════════╝

  Level 1 (Essential):  [███░░░░░░░░░░░░░░░░░] 19% (4/21)
  Level 2 (Enhanced):   [██████░░░░░░░░░░░░░░] 33.3% (1/3)

  ⚠ Non-Compliant Controls:
    [L1] 1.2.1: MFA for administrative roles - MITRE: T1078, T1110
    [L1] 5.1.1.1: Block legacy authentication - MITRE: T1110.003
```

### Sections Covered
- **Section 1** - Account/Authentication (MFA, Password Policies)
- **Section 2** - Application Permissions (OAuth, Consent Workflow)
- **Section 5** - Conditional Access (Risk Policies, Device Compliance)
- **Section 6** - Exchange Online (Email Auth, Auditing)
- **Section 7** - SharePoint and OneDrive (External Sharing)

---

## 📊 Baseline Comparison

Track security progress over time by comparing assessments against saved baselines:

### Saving a Baseline

```powershell
# Save current assessment as baseline
.\Start-M365Assessment.ps1 -SaveBaseline

# Save with a custom name (e.g., before a security project)
.\Start-M365Assessment.ps1 -SaveBaseline -BaselineName "Pre-ZeroTrust"

# Baselines are saved to the 'baselines' folder by default
```

### Comparing to a Baseline

```powershell
# Compare current state to a baseline
.\Start-M365Assessment.ps1 -CompareToBaseline "Pre-ZeroTrust"

# Or use the full path
.\Start-M365Assessment.ps1 -CompareToBaseline ".\baselines\Pre-ZeroTrust_20250201_100000.json"
```

### Comparison Output

The comparison shows:
- **Overall Trend** - Improving, Declining, or Stable
- **Score Deltas** - Changes in Security Score and CIS compliance percentages
- **Improvements** - Checks that moved from Fail/Warning to Pass
- **Regressions** - Checks that worsened since baseline

```
╔══════════════════════════════════════════════════════════════════════╗
║                    Baseline Comparison                               ║
╚══════════════════════════════════════════════════════════════════════╝

  📊 Comparing to: Pre-ZeroTrust (2025-02-01 10:00)
  
  Overall Trend: ↑ IMPROVING
  
  Security Score: 35.6% → 52.3% (+16.7 pts)
  CIS Level 1:    19%   → 38%   (+19%)
  CIS Level 2:    33%   → 50%   (+17%)
  
  ✅ Improvements (3):
     • MFA Configuration: Fail → Pass
     • Legacy Authentication: Warning → Pass
     • Conditional Access Policies: Fail → Warning
  
  ❌ Regressions (0): None
```

### Baseline Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-SaveBaseline` | Save current results as baseline | `.\Start-M365Assessment.ps1 -SaveBaseline` |
| `-BaselineName` | Custom label for the baseline | `-BaselineName "Q1-2025"` |
| `-CompareToBaseline` | Path or name of baseline to compare | `-CompareToBaseline "Q1-2025"` |
| `-BaselinePath` | Directory for baseline files | `-BaselinePath "C:\Audits\Baselines"` |

---

## Configuration

Customize the assessment in `config/assessment-config.json`:

```json
{
  "Scoring": {
    "Enabled": true,
    "DisplayInConsole": true,
    "RiskWeights": {
      "MFA Enforcement": 12,
      "Conditional Access Policies": 15,
      "Email Authentication": 6
    }
  },
  "CISBenchmark": {
    "Enabled": true,
    "DisplayInConsole": true,
    "Version": "3.1.0",
    "IncludeLevels": ["Level1", "Level2"]
  }
}
```

---

## Output Files

Each assessment generates timestamped reports:

| File | Description |
|------|-------------|
| `M365Guardian_*.html` | Interactive HTML dashboard |
| `M365Guardian_*.json` | Full assessment data |
| `M365Guardian_*.csv` | All findings for spreadsheets |
| `*_SecurityScore.json` | Detailed scoring breakdown |
| `*_CISCompliance.json` | CIS benchmark mapping |
| `*_CISCompliance.csv` | CIS controls for audit tools |
| `*_UsersWithoutMFA.csv` | Users requiring MFA enrollment |
| `*_PrivilegedAccounts.csv` | Privileged account inventory |
| `*_ConditionalAccessPolicies.csv` | CA policy details |
| `*_DomainEmailAuth.csv` | SPF/DKIM/DMARC per domain |

---

## Requirements

- **PowerShell 5.1+** (Windows PowerShell or PowerShell 7)
- **Microsoft Graph PowerShell SDK** v2.x
- **ExchangeOnlineManagement** module v3.x
- **Azure CLI** (for app registration setup only)

Install prerequisites:
```powershell
.\Install-Prerequisites.ps1
```

---

## Troubleshooting

### "DeviceCodeCredential authentication failed" errors
Use certificate authentication instead of device code:
```powershell
.\Setup-AppRegistration-CLI.ps1  # Run once
.\Start-M365Assessment.ps1       # Auto-uses certificate
```

### "Secure Score API requires E5 license"
Microsoft Secure Score API is only available with E5 licensing. The custom Tenant Security Score provides similar insights without E5.

### Exchange Online connection issues
The tool automatically uses device code flow for Exchange to avoid WAM broker issues in VS Code terminals.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Roadmap

- [ ] Historical Trend Tracking (compare assessments over time)
- [ ] Identity Protection Integration
- [ ] Defender for Office 365 Checks
- [ ] Power Platform Security Assessment
- [ ] Teams Security Assessment
- [ ] Multi-Tenant Summary Dashboard

> **Note:** This tool is intentionally **assessment-only**. It identifies and prioritizes security gaps but does not make changes to your tenant. Remediation must be performed manually by qualified administrators who understand the business impact of each change.

---

**Mobieus Rapid Assessment Suite** — Accelerate your Microsoft 365 security insights.
