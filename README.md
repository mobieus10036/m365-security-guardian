# M365 Security Guardian

**Rapid, actionable Microsoft 365 security assessment for modern enterprises.**

[![Version](https://img.shields.io/badge/version-3.1.0-blue)](https://github.com/mobieus10036/m365-security-guardian/releases)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://docs.microsoft.com/powershell/)
[![License](https://img.shields.io/github/license/mobieus10036/m365-security-guardian)](LICENSE)

---

## What's New in v3.1.0

- **Baseline Comparison** — Track security progress over time
- **CIS Benchmark Mapping** — Maps findings to CIS Microsoft 365 Foundations Benchmark v3.1.0
- **MITRE ATT&CK Integration** — Each CIS control includes relevant technique IDs
- **Dual Compliance Levels** — Separate compliance for CIS L1 (Essential) and L2 (Enhanced)
- **Interactive Auth (Default)** — Browser sign-in with no Azure setup required
- **Connection Cleanup** — Automatically clears stale connections before each run

---

## Features

### Tenant Security Score

- Overall security posture score (0–100) with letter grade (A–F)
- Category breakdown: Identity, Conditional Access, Applications, Email, Governance
- **Top Priorities** — Highest-impact remediation items
- **Quick Wins** — Low-effort, high-impact fixes
- Weighted scoring based on actual security impact

### CIS Microsoft 365 Benchmark Compliance

- Maps all findings to **CIS Microsoft 365 Foundations Benchmark v3.1.0**
- Separate tracking for **Level 1 (Essential)** and **Level 2 (Enhanced)** controls
- 24 CIS controls assessed across 5 security domains
- MITRE ATT&CK technique mappings for each control
- Audit-ready reports for compliance frameworks

### Security Assessments

| Module | Checks |
| ------ | ------ |
| **Identity** | MFA adoption, Privileged accounts, PIM configuration, Legacy auth |
| **Conditional Access** | Policy coverage, Risk-based policies, Device compliance |
| **Applications** | High-risk permissions, Credential expiry, OAuth grants |
| **Email** | SPF/DKIM/DMARC validation, Mailbox auditing |
| **Licensing** | Inactive license detection, Optimization opportunities |

### Report Outputs

- **HTML** — Interactive dashboard with filtering and export
- **JSON** — Machine-readable for automation and SIEM integration
- **CSV** — Spreadsheet-compatible for analysis
- **CIS Compliance** — Dedicated exports for audit tools

---

## Quickstart

```powershell
git clone https://github.com/mobieus10036/m365-security-guardian.git
cd m365-security-guardian
.\Install-Prerequisites.ps1
.\Start-M365Assessment.ps1
```

---

## Authentication

The tool uses **Interactive browser sign-in** by default — no Azure setup required. Your browser opens, you sign in, and the assessment runs with your delegated permissions.

| Method | Best For | Example |
| ------ | -------- | ------- |
| **Interactive** ⭐ | Default — browser sign-in, no setup | `.\Start-M365Assessment.ps1` |
| **DeviceCode** | Terminal-only environments | `.\Start-M365Assessment.ps1 -AuthMethod DeviceCode` |
| **Certificate** | Automation with app registration | `.\Start-M365Assessment.ps1 -AuthMethod Certificate -ClientId "app-id" -TenantId "tenant-id" -CertificateThumbprint "thumbprint"` |
| **ManagedIdentity** | Azure-hosted (VMs, Functions) | `.\Start-M365Assessment.ps1 -AuthMethod ManagedIdentity` |

### Assessing Other Tenants

To assess a different tenant, pass the `-TenantId` parameter:

```powershell
.\Start-M365Assessment.ps1 -TenantId "other.onmicrosoft.com"
```

---

## Required Permissions

This tool requires specific permissions in Microsoft Entra ID and Exchange Online. **Global Administrator is not required** — the permissions below are sufficient.

### Permission Summary

**Microsoft Graph API (Delegated Permissions):**

When you sign in interactively, the tool requests these scopes on your behalf:

- `User.Read.All` - Read user profiles and MFA status
- `Directory.Read.All` - Read directory data and privileged roles
- `Policy.Read.All` - Read Conditional Access and auth policies
- `Organization.Read.All` - Read tenant information
- `AuditLog.Read.All` - Read sign-in logs and legacy auth detection
- `Application.Read.All` - Audit app permissions
- `RoleManagement.Read.Directory` - Read PIM and role assignments
- `SharePointTenantSettings.Read.All` - Read external sharing config
- `SecurityEvents.Read.All` - Read Secure Score (E5 license required)

> You may be prompted to consent to these permissions on first run. An admin can pre-consent for the organization via the Microsoft Graph PowerShell enterprise app.

**Exchange Online Role:**

- **View-Only Organization Management** (recommended) - Read-only access to all Exchange settings
- Alternative: Security Reader, Compliance Management, or Global Reader

### What Happens Without Certain Permissions?

The tool gracefully handles missing permissions:

| Missing Permission | Result |
| ------------------ | ------ |
| `SecurityEvents.Read.All` | Secure Score check shows "E5 license required" |
| `RoleManagement.Read.All` | PIM check shows "P2 license required" |
| `SharePointTenantSettings.Read.All` | External sharing check skipped |
| Exchange role not assigned | Exchange checks show connection error |

> 📋 **For detailed permission mappings, setup instructions, and troubleshooting, see [PERMISSIONS.md](PERMISSIONS.md)**

---

## Security Score

The assessment calculates an **overall Tenant Security Score**:

| Grade | Score Range | Description |
| ----- | ----------- | ----------- |
| **A** | 90-100% | Excellent - Your tenant follows security best practices |
| **B** | 80-89% | Good - Minor improvements recommended |
| **C** | 70-79% | Fair - Several security gaps should be addressed |
| **D** | 60-69% | Poor - Significant security risks require attention |
| **F** | 0-59% | Critical - Immediate action required |

### Category Weights

| Category | Weight | Key Checks |
| -------- | ------ | ---------- |
| Identity & Access | 30% | MFA, Privileged Accounts, PIM, Legacy Auth |
| Conditional Access | 25% | CA Policies, External Sharing |
| Application Security | 20% | App Permissions, Secure Score |
| Email Security | 15% | SPF/DKIM/DMARC, Mailbox Auditing |
| Governance | 10% | License Optimization |

---

## CIS Benchmark Mapping

All findings are mapped to the **CIS Microsoft 365 Foundations Benchmark v3.1.0**:

```text
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

## Baseline Comparison

Track security progress over time by comparing assessments against saved baselines.

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

```text
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
| --------- | ----------- | ------- |
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
| ---- | ----------- |
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

- **PowerShell 7.0+** (install via `winget install Microsoft.PowerShell` or <https://aka.ms/powershell>)
- **Microsoft Graph PowerShell SDK** v2.x
- **ExchangeOnlineManagement** module v3.x

### Supported Environments

| Environment | Status |
| ----------- | ------ |
| **PowerShell 7+ (pwsh)** | Fully supported |
| **Windows Terminal** | Fully supported |
| **VS Code Integrated Terminal** | Fully supported |

Install prerequisites:

```powershell
.\Install-Prerequisites.ps1
```

---

## Linting

Markdown linting is enforced by the rules in [.markdownlint.json](.markdownlint.json). Key rules include:

- `MD022` - Headings surrounded by blank lines
- `MD031` - Fenced code blocks surrounded by blank lines
- `MD032` - Lists surrounded by blank lines
- `MD034` - No bare URLs

Run lint locally (example using markdownlint-cli2):

```powershell
npx markdownlint-cli2 "**/*.md"
```

---

## Troubleshooting

### Browser does not open for sign-in

If Interactive auth fails to open a browser, try DeviceCode as a fallback:

```powershell
.\Start-M365Assessment.ps1 -AuthMethod DeviceCode
```

### "Secure Score API requires E5 license"

Microsoft Secure Score API is only available with E5 licensing. The custom Tenant Security Score provides similar insights without E5.

### Exchange Online connection issues

Exchange Online uses Interactive browser sign-in by default. If you experience issues, try using DeviceCode auth which forces the device code flow for Exchange:

```powershell
.\Start-M365Assessment.ps1 -AuthMethod DeviceCode
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Roadmap

- [ ] Historical trend tracking
- [ ] Identity Protection integration
- [ ] Defender for Office 365 checks
- [ ] Power Platform security assessment
- [ ] Teams security assessment

> **Note:** This tool is intentionally **assessment-only**. It identifies and prioritizes security gaps but does not make changes to your tenant. Remediation must be performed by qualified administrators who understand the business impact.

---

**M365 Security Guardian** — Accelerate your Microsoft 365 security insights.
