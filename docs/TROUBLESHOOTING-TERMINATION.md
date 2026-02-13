# Troubleshooting: PowerShell Process Termination During Assessment

## Symptoms

- PowerShell window closes unexpectedly during assessment
- VSCode Extension Terminal displays: "Connection to PowerShell Editor Services was closed"
- Assessment runs for 10-15 minutes then suddenly terminates
- No clear error message before termination

## Root Cause (Fixed in v3.1.1)

**Graph API operations with `-All` parameter were blocking indefinitely during large dataset enumeration**, causing:

1. **Memory exhaustion** in tenants with 10,000+ users or 5,000+ applications
2. **Graph API throttling (429 errors)** during pagination with no retry logic
3. **Timeout failures** with no recovery mechanism
4. **Silent process termination** when PowerShell hits OS resource limits

### Critical Failure Points (Fixed)

| Module | Operation | Issue |
|--------|-----------|-------|
| **Test-AppPermissions.ps1** | `Get-MgServicePrincipal -All` | Blocks 5-15 min in large tenants |
| **Test-MFAConfiguration.ps1** | `Get-MgUser -All` | Loads all users into memory |
| **Test-LicenseOptimization.ps1** | `Get-MgUser -All -Property SignInActivity` | Slowest operation (sign-in data) |
| **Test-PIMConfiguration.ps1** | Multiple `-All` PIM queries | Compounds blocking time |

## Fix Implemented (v3.1.1)

### 1. Resilient Graph API Wrapper

Created `Invoke-MgGraphWithRetry` module with:
- **5-minute timeout** per operation (configurable)
- **3 retry attempts** with exponential backoff (10s → 20s → 40s)
- **Progress indication** so users know assessment is running
- **Graceful failure** — returns empty array instead of crashing
- **Throttling detection** — specifically handles 429 errors

### 2. Enhanced Error Handling

- **Global trap handler** for unhandled exceptions
- **Per-module error recovery** — failed modules don't abort entire assessment
- **Diagnostic logging** — captures exact failure location and context
- **Result validation** — ensures malformed module outputs don't crash scoring

### 3. Resource Protection

- **ErrorActionPreference = Continue** — prevents silent termination
- **Finally block** — guarantees Graph disconnection even on failure
- **Heartbeat tracking** — detects hung operations

## Verification

After upgrading to v3.1.1, you should see:

```powershell
PS> .\Start-M365Assessment.ps1

[info] Loaded Graph API retry wrapper

# During long operations:
Write-Progress: [Retrieving service principals] Retrieving data from Microsoft Graph...
Write-Progress: [Retrieving users for MFA analysis] Retrieving data from Microsoft Graph...

# On throttling (now handled automatically):
[WARNING] [Retrieving OAuth2 grants] Graph API throttling detected (attempt 1/3)
[info] Waiting 10 seconds before retry...
```

## Large Tenant Optimization Tips

For tenants with 10,000+ users or 5,000+ applications:

### 1. Run During Off-Peak Hours
Graph API performance is better outside business hours (evenings/weekends).

### 2. Increase Timeout (If Needed)
Edit `modules\Core\Invoke-MgGraphWithRetry.ps1`:

```powershell
# Default is 300 seconds (5 minutes)
# For very large tenants, increase to 10 minutes:
[int]$TimeoutSeconds = 600
```

### 3. Monitor Progress
Use `-Verbose` to see detailed progress:

```powershell
.\Start-M365Assessment.ps1 -Verbose
```

### 4. Run Modules Separately
If timeouts persist, run assessment modules individually:

```powershell
# Run only Security module (fastest)
.\Start-M365Assessment.ps1 -Modules Security

# Then run Exchange and Licensing separately
.\Start-M365Assessment.ps1 -Modules Exchange
.\Start-M365Assessment.ps1 -Modules Licensing
```

## Diagnostic Commands

If issues persist, run diagnostics:

```powershell
# Check Graph SDK version (should be 2.0+)
Get-Module Microsoft.Graph.* -ListAvailable | Select Name, Version

# Test Graph connection manually
Connect-MgGraph -Scopes "User.Read.All"
Measure-Command { Get-MgUser -Top 100 }  # Should complete in < 5 seconds

# Check tenant size
(Get-MgUser -ConsistencyLevel eventual -Count userCount).Count
(Get-MgServicePrincipal -ConsistencyLevel eventual -Count spCount).Count
```

## Expected Performance

| Tenant Size | Expected Duration | Notes |
|-------------|-------------------|-------|
| **Small** (< 500 users, < 200 apps) | 2-4 minutes | Fast |
| **Medium** (500-5K users, 200-1K apps) | 4-8 minutes | Typical |
| **Large** (5K-20K users, 1K-5K apps) | 8-15 minutes | Use retry wrapper |
| **Enterprise** (20K+ users, 5K+ apps) | 15-25 minutes | Run off-peak, increase timeout |

## Still Having Issues?

1. **Check PERMISSIONS.md** — Ensure you have required Graph API permissions
2. **Review Visual Studio Code logs** — Check Output → PowerShell Extension
3. **Enable verbose logging**:
   ```powershell
   $VerbosePreference = 'Continue'
   .\Start-M365Assessment.ps1
   ```
4. **Report with diagnostics**:
   ```powershell
   .\tools\Get-EnvDiagnostics.ps1 | Out-File diagnostics.txt
   ```
   Then create an issue at: https://github.com/mobieus10036/m365-security-guardian/issues

## Technical Details

### Why `-All` Was Problematic

The Microsoft Graph PowerShell SDK `-All` parameter:
- Uses **synchronous pagination** (blocks PowerShell runspace)
- Has **no built-in timeout** (can hang indefinitely)
- **Does not surface throttling** to calling code
- **Accumulates all results in memory** (can exhaust RAM with large datasets)

### How `Invoke-MgGraphWithRetry` Fixes This

```powershell
# OLD (blocks indefinitely):
$users = Get-MgUser -All

# NEW (timeout + retry + progress):
$users = Invoke-MgGraphWithRetry -ScriptBlock {
    Get-MgUser -All -ErrorAction Stop
} -OperationName "Retrieving users" -TimeoutSeconds 300
```

The wrapper:
1. Runs the operation in a **background job** with timeout
2. **Polls for completion** every second
3. **Kills the job** if timeout exceeded
4. **Retries** on transient errors (429, 502, 503)
5. **Returns empty array** on fatal failure (tool continues)

## Version History

- **v3.1.0 and earlier** — Used direct `-All` calls (could hang/crash)
- **v3.1.1+** — Resilient wrapper with timeout/retry (fixed)
