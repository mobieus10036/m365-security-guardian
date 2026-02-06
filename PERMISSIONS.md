# Required Permissions for M365 Security Guardian

This document provides a comprehensive list of all permissions required to run the M365 Security Guardian tool.

## Table of Contents

- [Overview](#overview)
- [Microsoft Graph API Permissions](#microsoft-graph-api-permissions)
- [Exchange Online Roles](#exchange-online-roles)
- [Permission to Check Mapping](#permission-to-check-mapping)
- [Setup Instructions](#setup-instructions)
- [Troubleshooting](#troubleshooting)

---

## Overview

The M365 Security Guardian tool requires:

1. **Microsoft Graph API permissions** (Application type) - For reading Entra ID, Conditional Access, and SharePoint configurations
2. **Exchange Online RBAC role** - For reading mailbox, email security, and compliance settings

**Important:** You do NOT need Global Administrator rights. The specific permissions listed below are sufficient for a complete assessment.

---

## Microsoft Graph API Permissions

These are **Application permissions** (not Delegated) that must be assigned to an App Registration in Entra ID.

### Required Permissions

| Permission | Permission ID (GUID) | Type | Description |
| ---------- | -------------------- | ---- | ----------- |
| `User.Read.All` | `df021288-bdef-4463-88db-98f22de89214` | Application | Read all users' full profiles |
| `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | Application | Read directory data |
| `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | Application | Read your organization's policies |
| `Organization.Read.All` | `498476ce-e0fe-48b0-b801-37ba7e2685c6` | Application | Read organization information |
| `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | Application | Read all audit log data |
| `Application.Read.All` | `9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30` | Application | Read all applications |
| `RoleManagement.Read.All` | `d5fe8ce8-684c-4c83-a52c-46e882ce4be1` | Application | Read role management data for all RBAC providers |
| `RoleManagement.Read.Directory` | `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` | Application | Read all directory RBAC settings |
| `SharePointTenantSettings.Read.All` | `83d4163d-a2d8-4d3b-9695-4ae3ca98f888` | Application | Read SharePoint and OneDrive tenant settings |

### Optional Permissions (License-Dependent)

| Permission | Permission ID (GUID) | Type | Requires |
| ---------- | -------------------- | ---- | -------- |
| `SecurityEvents.Read.All` | `38d9df27-64da-44fd-b7c5-a6fbac20248f` | Application | Microsoft 365 E5 or E5 Security for Secure Score |

### Admin Consent Required

All the above permissions require **admin consent**. A Global Administrator, Application Administrator, or Cloud Application Administrator must grant consent.

---

## Exchange Online Roles

Exchange Online uses Role-Based Access Control (RBAC). The user running the assessment needs to be assigned to one of these roles:

### Recommended Role

| Role | Description |
| ---- | ----------- |
| **View-Only Organization Management** | Full read-only access to all Exchange settings. This is the recommended minimum role. |

### Alternative Roles

| Role | Capabilities | Limitations |
| ---- | ------------ | ----------- |
| **Security Reader** | Email security policies, threat protection | Cannot read compliance settings |
| **Compliance Management** | DLP, Retention, Sensitivity Labels | Cannot read security policies |
| **Global Reader** | All M365 settings (read-only) | Broader than necessary |
| **Organization Management** | Full Exchange access | More permissions than needed |

### Exchange Cmdlets Used by This Tool

| Cmdlet | Purpose | Minimum Role |
| ------ | ------- | ------------ |
| `Get-EXOMailbox` | Check mailbox auditing status | View-Only Organization Management |
| `Get-AcceptedDomain` | List domains for email auth checks | View-Only Organization Management |
| `Get-DkimSigningConfig` | DKIM configuration status | View-Only Organization Management |
| `Get-MalwareFilterPolicy` | Anti-malware settings | Security Reader |
| `Get-SafeAttachmentPolicy` | Defender for O365 Safe Attachments | Security Reader |
| `Get-SafeLinksPolicy` | Defender for O365 Safe Links | Security Reader |
| `Get-RetentionCompliancePolicy` | Retention policies | Compliance Management |
| `Get-DlpCompliancePolicy` | Data Loss Prevention policies | Compliance Management |
| `Get-Label` | Sensitivity labels | Compliance Management |
| `Get-LabelPolicy` | Sensitivity label policies | Compliance Management |

---

## Permission to Check Mapping

### Security Module Checks

| Check | Graph Permissions Required | Exchange Role Required |
| ----- | ------------------------- | ---------------------- |
| MFA Configuration | `User.Read.All`, `Directory.Read.All` | None |
| Conditional Access | `Policy.Read.All` | None |
| Privileged Accounts | `Directory.Read.All`, `RoleManagement.Read.Directory` | None |
| PIM Configuration | `RoleManagement.Read.All`, `Directory.Read.All` | None |
| Legacy Authentication | `Policy.Read.All`, `AuditLog.Read.All` | None |
| Application Permissions | `Application.Read.All`, `Directory.Read.All` | None |
| External Sharing | `SharePointTenantSettings.Read.All` | None |
| Secure Score | `SecurityEvents.Read.All` | None |

### Exchange Module Checks

| Check | Graph Permissions Required | Exchange Role Required |
| ----- | ------------------------- | ---------------------- |
| Email Security (ATP) | None | Security Reader |
| SPF/DKIM/DMARC | None | View-Only Organization Management |
| Mailbox Auditing | None | View-Only Organization Management |

### Compliance Module Checks

| Check | Graph Permissions Required | Exchange Role Required |
| ----- | ------------------------- | ---------------------- |
| DLP Policies | None | Compliance Management |
| Retention Policies | None | Compliance Management |
| Sensitivity Labels | None | Compliance Management |

### Licensing Module Checks

| Check | Graph Permissions Required | Exchange Role Required |
| ----- | ------------------------- | ---------------------- |
| License Optimization | `User.Read.All`, `AuditLog.Read.All` | None |

---

## Setup Instructions

### Option 1: Automated Setup (Recommended)

Run the setup script to create an App Registration with all required permissions:

```powershell
.\Setup-AppRegistration-CLI.ps1
```

This script:

1. Creates a self-signed certificate
2. Creates an Entra ID App Registration
3. Adds all required Graph API permissions
4. Requests admin consent
5. Saves configuration for future runs

### Option 2: Manual Setup

#### Step 1: Create App Registration

1. Go to [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations**
2. Click **New registration**
3. Name: `M365 Security Guardian`
4. Supported account types: **Single tenant**
5. Click **Register**

#### Step 2: Add API Permissions

1. Go to **API permissions** → **Add a permission**
2. Select **Microsoft Graph** → **Application permissions**
3. Add each permission from the [Required Permissions](#required-permissions) table
4. Click **Grant admin consent for [Tenant]**

#### Step 3: Create Certificate or Secret

**Certificate (Recommended):**

```powershell
# Create self-signed certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=M365 Security Guardian" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddYears(2)

# Export public key for upload to Azure
$certPath = ".\m365-assessment-cert.cer"
Export-Certificate -Cert $cert -FilePath $certPath
```

Upload the `.cer` file to your App Registration under **Certificates & secrets**.

**Client Secret (Alternative):**

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Note: Secrets expire and are less secure than certificates

#### Step 4: Assign Exchange Online Role

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com

# Add user to View-Only Organization Management
Add-RoleGroupMember -Identity "View-Only Organization Management" -Member "assessmentuser@yourdomain.com"
```

---

## Troubleshooting

### Common Permission Errors

| Error Message | Cause | Solution |
| ------------- | ----- | -------- |
| `Insufficient privileges to complete the operation` | Missing Graph permission | Verify all permissions are granted with admin consent |
| `Access denied` on Conditional Access | Missing `Policy.Read.All` | Add permission and grant admin consent |
| `The term 'Get-EXOMailbox' is not recognized` | Not connected to Exchange Online | Run `Connect-ExchangeOnline` first |
| `The operation couldn't be performed because object couldn't be found` | Missing Exchange role | Assign View-Only Organization Management role |
| `Access to OData is disabled` | Secure Score API not available | Requires E5 license; check shows as Info |

### Verifying Permissions

**Check Graph API Permissions:**

```powershell
# After connecting with Connect-MgGraph
(Get-MgContext).Scopes
```

**Check Exchange Online Role:**

```powershell
# After connecting with Connect-ExchangeOnline
Get-RoleGroupMember -Identity "View-Only Organization Management" | Where-Object { $_.Name -eq "yourusername" }
```

### What If a Permission Is Missing?

The tool handles missing permissions gracefully:

- **Missing optional permissions:** Check displays as "Info" status with guidance
- **Missing required permissions:** Check displays as "Warning" with error details
- **Exchange not connected:** Exchange checks skipped with informational message

### Security Considerations

- Use **Application permissions** (app-only) rather than Delegated permissions for automated/scheduled runs
- Use **certificate authentication** instead of client secrets
- Store certificates securely and rotate before expiry
- Use a dedicated service account or managed identity for production deployments
- Review and audit the App Registration permissions periodically

---

## Quick Reference Card

### Minimum Permissions for Core Checks

```text
Microsoft Graph (Application):
├── User.Read.All
├── Directory.Read.All
├── Policy.Read.All
└── AuditLog.Read.All

Exchange Online:
└── View-Only Organization Management role
```

### Full Permissions for All Checks

```text
Microsoft Graph (Application):
├── User.Read.All
├── Directory.Read.All
├── Policy.Read.All
├── Organization.Read.All
├── AuditLog.Read.All
├── Application.Read.All
├── RoleManagement.Read.All
├── RoleManagement.Read.Directory
├── SharePointTenantSettings.Read.All
└── SecurityEvents.Read.All (E5 only)

Exchange Online:
└── View-Only Organization Management role
```

---

## Version History

| Version | Date | Changes |
| ------- | ---- | ------- |
| 1.0 | 2026-02-03 | Initial permissions documentation |
