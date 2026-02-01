# M365 Security Assessment 🛡️

**Official GitHub repository:** [https://github.com/mobieus10036/m365-security-assessment](https://github.com/mobieus10036/m365-security-assessment)

**Rapid, actionable Microsoft 365 security assessment for modern enterprises.**

![Build Status](https://img.shields.io/github/workflow/status/mobieus10036/m365-security-guardian/CI)
![License](https://img.shields.io/github/license/mobieus10036/m365-security-guardian)

---

## Features

- **🎯 Tenant Security Score** - Overall security posture score (0-100) with letter grade (A-F)
- Assesses Microsoft 365 security posture across Identity, Conditional Access, Applications, and Email
- Identifies critical risks and misconfigurations with severity-based prioritization
- **Top Priorities** - Highest impact remediation items ranked by potential score improvement
- **Quick Wins** - Low-effort, high-impact fixes for immediate security gains
- Category breakdown showing scores for Identity & Access, Conditional Access, App Security, and more
- Generates professional HTML, JSON, and CSV reports
- Easy to run, modular PowerShell code

---

## Quickstart

```powershell
git clone https://github.com/mobieus10036/m365-security-guardian.git
cd m365-security-guardian
./Start-M365Assessment.ps1
```

## Authentication

The tool supports multiple authentication methods for different scenarios:

| Method | Best For | Command |
|--------|----------|---------|
| **DeviceCode** (default) | Terminal/console use, multi-tenant | `./Start-M365Assessment.ps1` |
| **Interactive** | Quick runs with browser | `./Start-M365Assessment.ps1 -AuthMethod Interactive` |
| **Certificate** | Scheduled automation | `./Start-M365Assessment.ps1 -AuthMethod Certificate -ClientId "..." -TenantId "..." -CertificateThumbprint "..."` |
| **ManagedIdentity** | Azure-hosted (VMs, Functions) | `./Start-M365Assessment.ps1 -AuthMethod ManagedIdentity` |

### Multi-Tenant Assessments (Consultants)

```powershell
# Assess a specific tenant using device code flow
./Start-M365Assessment.ps1 -TenantId "contoso.onmicrosoft.com" -AuthMethod DeviceCode
```

### Automated/Scheduled Assessments

For unattended runs, create an App Registration with the required API permissions:

**Required Microsoft Graph Application Permissions:**
- `User.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`
- `Organization.Read.All`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.All`

```powershell
# Certificate-based authentication
./Start-M365Assessment.ps1 -AuthMethod Certificate `
    -ClientId "your-app-id" `
    -TenantId "your-tenant-id" `
    -CertificateThumbprint "your-cert-thumbprint"
```

## Security Score

The assessment now calculates an **overall Tenant Security Score** providing:

| Grade | Score Range | Description |
|-------|-------------|-------------|
| A | 90-100% | Excellent - Your tenant follows security best practices |
| B | 80-89% | Good - Minor improvements recommended |
| C | 70-79% | Fair - Several security gaps should be addressed |
| D | 60-69% | Poor - Significant security risks require attention |
| F | 0-59% | Critical - Immediate action required |

### Category Breakdown
- **Identity & Access** - MFA, Privileged Accounts, PIM, Legacy Auth
- **Conditional Access** - CA Policies, External Sharing
- **Application Security** - App Permissions, Microsoft Secure Score
- **Email Security** - SPF/DKIM/DMARC, Mailbox Auditing
- **Governance** - License Optimization

### Configuration

Customize scoring weights in `config/assessment-config.json`:

```json
{
  "Scoring": {
    "Enabled": true,
    "DisplayInConsole": true,
    "RiskWeights": {
      "MFA Enforcement": 12,
      "Conditional Access Policies": 15
    }
  }
}
```

## Methodology

- Enumerates resources via Microsoft Graph and PowerShell
- Evaluates against Microsoft 365 security best practices
- Weighted scoring based on security impact
- Actionable findings with remediation guidance

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License

---

Mobieus Rapid Assessment Suite — Accelerate your Azure security and cost insights.
