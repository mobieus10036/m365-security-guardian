# M365 Security Guardian

A PowerShell toolkit for checking Microsoft 365 security settings and configurations.

> **Note**: I'm still learning PowerShell and development. This project was built with heavy assistance from GitHub Copilot, Microsoft documentation, and community examples. If you spot issues or have suggestions, please let me know!

## What This Does

This toolkit checks your Microsoft 365 tenant for common security issues and configuration problems. It generates reports showing what's configured correctly and what needs attention.

**Main checks include:**
- MFA (Multi-Factor Authentication) status
- Conditional Access policies
- Legacy authentication settings
- Email security (SPF, DKIM, DMARC)
- Mailbox auditing
- License usage
- Privileged account security

## Getting Started

**What you'll need:**
- Windows PowerShell 5.1 or newer (PowerShell 7 works too)
- Admin access to your Microsoft 365 tenant
- Permissions: Global Reader role minimum (see Permissions section below)

**Steps:**

1. Download or clone this repository
   ```powershell
   git clone https://github.com/mobieus10036/m365-security-guardian.git
   cd m365-security-guardian
   ```

2. Install the required PowerShell modules
   ```powershell
   .\Install-Prerequisites.ps1
   ```
   This will install the Microsoft Graph and Exchange Online modules needed.

3. Run the assessment
   ```powershell
   .\Start-M365Assessment.ps1
   ```
   You'll be prompted to sign in to your M365 tenant.

Reports will be saved to the `reports/` folder.

## Permissions Needed

Your account needs one of these roles:
- **Global Reader** - can run most checks
- **Security Reader** - needed for security assessments  
- **Compliance Administrator** - needed for compliance checks

Or just use **Global Administrator** if you have it (gives access to everything).

## What Gets Checked

**Security:**
- Multi-Factor Authentication (MFA) enforcement
- Conditional Access policies
- Privileged accounts configuration
- Legacy authentication status

**Compliance:**
- Data Loss Prevention (DLP) policies
- Retention policies
- Sensitivity labels

**Exchange Online:**
- Anti-spam/anti-malware settings
- Safe Attachments and Safe Links
- SPF, DKIM, and DMARC records (checks actual DNS records)
- Mailbox auditing

**Licensing:**
- License assignments
- Inactive users with licenses
- Optimization opportunities

> **Known Issue**: SharePoint and Teams modules are currently disabled due to PowerShell 7 compatibility issues with some Microsoft modules. Working on fixing this.

## Understanding the Reports

After running the assessment, you'll find several files in the `reports/` folder:

- **HTML file** - Easy to read in a browser, color-coded results
- **JSON file** - All the raw data if you need it
- **CSV file** - Open in Excel for further analysis
- **DomainEmailAuth CSV** - Shows SPF/DKIM/DMARC status for each domain
- **NonCompliantMailboxes CSV** - Lists mailboxes without auditing enabled
- **InactiveMailboxes CSV** - Shows licensed users who haven't signed in recently

## Configuration

You can customize the thresholds and settings by editing `config/assessment-config.json`. For example:

```json
{
  "Security": {
    "MFAEnforcementThreshold": 95,
    "PrivilegedAccountMFARequired": true
  },
  "Licensing": {
    "InactiveDaysThreshold": 90
  }
}
```

## Other Useful Commands

Run only specific checks:
```powershell
.\Start-M365Assessment.ps1 -Modules Security,Exchange
```

Generate only HTML output:
```powershell
.\Start-M365Assessment.ps1 -OutputFormat HTML
```

Use a custom config file:
```powershell
.\Start-M365Assessment.ps1 -ConfigPath .\my-config.json
```

## Fixing Issues

### Enabling Mailbox Auditing

If the assessment finds mailboxes without auditing enabled, you can fix them using:

```powershell
# See what would change (doesn't actually change anything)
.\Enable-MailboxAuditing.ps1 -WhatIf

# Enable auditing on all non-compliant mailboxes
.\Enable-MailboxAuditing.ps1

# Skip confirmations
.\Enable-MailboxAuditing.ps1 -Force
```

The script reads the latest CSV report and enables auditing where needed.

## Documentation

More detailed info is in the `docs/` folder:
- [Best Practices Reference](docs/best-practices-reference.md)
- [DNS Validation Guide](docs/QUICK-REFERENCE-DNS-VALIDATION.md)
- [Remediation Guides](docs/remediation-guides/)

## Contributing

I'm learning, so if you see ways to improve the code, please feel free to:
1. Open an issue
2. Fork the repo
3. Make your changes
4. Submit a pull request

Check [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

MIT License - see [LICENSE](LICENSE) file.

## Important Notes

**This tool only reads data** - it doesn't make changes to your Microsoft 365 tenant. You'll need to manually implement any fixes based on the reports.

Always review findings with your IT or security team before making changes to production environments.

## Help & Support

- **Found a bug?** [Open an issue](https://github.com/mobieus10036/m365-security-guardian/issues)
- **Have a question?** [Start a discussion](https://github.com/mobieus10036/m365-security-guardian/discussions)
- **Security concern?** See [SECURITY.md](SECURITY.md)

## Acknowledgments

This project was built with significant help from:
- **GitHub Copilot** - for code generation and problem-solving
- Microsoft documentation and security guides
- The PowerShell community
- Stack Overflow and various online resources

Thanks to everyone who shares knowledge online - it makes learning to code much more accessible!
