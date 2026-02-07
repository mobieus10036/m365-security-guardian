# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in M365 Security Guardian:

- **DO NOT** open public GitHub issues for security problems
- Use GitHub's [Security Advisories](https://github.com/mobieus10036/m365-security-guardian/security/advisories) feature to report privately
- Alternatively, contact the maintainer privately via GitHub

**Please include:**

- Description of the vulnerability
- Potential impact and severity
- Steps to reproduce
- Affected version(s)
- Suggested remediation (optional)

You will receive an acknowledgement within 3-5 business days. We will work with you to coordinate a fix and responsible disclosure timeline.

---

## Security Scope

**What This Tool Does:**

- **Read-only assessment** - The tool does not modify any tenant settings
- Calls Microsoft Graph and Exchange Online APIs only
- No data is sent to third parties beyond Microsoft services
- All processing is performed locally on your machine

**Important Security Notes:**

- Generated reports may contain sensitive configuration details
- Store and share reports securely (consider them confidential)
- Review reports before sharing externally
- Use certificate authentication for production environments

---

## Supported Versions

| Version | Supported | Status |
| ------- | --------- | ------ |
| 3.x     | ✅ Yes    | Current release |
| < 3.0   | ❌ No     | Legacy versions |

Only the current major version (3.x) receives security updates.
