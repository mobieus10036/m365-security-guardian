# M365 Security Guardian

PowerShell toolkit that assesses Microsoft 365 security posture and exports results as HTML/CSV/JSON.

## Quick Start

Prerequisites

- Windows PowerShell 5.1+ or PowerShell 7
- Microsoft 365 account with at least Global Reader

Setup and run

```powershell
git clone https://github.com/mobieus10036/m365-security-guardian.git
cd m365-security-guardian
./Install-Prerequisites.ps1
./Start-M365Assessment.ps1
```
 
Reports are written to `reports/`.

## What It Checks

- Security: MFA, Conditional Access, legacy auth, privileged accounts
- Exchange: anti-spam/malware, Safe Links/Attachments, SPF/DKIM/DMARC, mailbox auditing
- Licensing: assignments, inactive users, optimization signals

## Run Specific Modules

```powershell
# Security only
./Start-M365Assessment.ps1 -Modules Security

# Security + Exchange
./Start-M365Assessment.ps1 -Modules Security,Exchange

# All (default)
./Start-M365Assessment.ps1
```

Available: `Security`, `Exchange`, `Licensing`, `All`.

## Output Formats

```powershell
./Start-M365Assessment.ps1 -OutputFormat HTML   # just HTML
./Start-M365Assessment.ps1 -OutputFormat CSV    # just CSVs
./Start-M365Assessment.ps1 -OutputFormat All    # default
```

## Configuration (optional)

Edit `config/assessment-config.json` or pass a custom file:

```powershell
./Start-M365Assessment.ps1 -ConfigPath ./my-config.json
```

## Permissions

- Global Reader: most checks
- Security Reader / Compliance Administrator: some checks
- Global Administrator: full access (not required)

## Notes

- Read-only: scripts do not modify tenant settings.
- Reports may contain sensitive details; store and share carefully.

## Support

- Issues: [GitHub Issues](https://github.com/mobieus10036/m365-security-guardian/issues)
- Security: see `SECURITY.md`

## License

MIT — see `LICENSE`.
