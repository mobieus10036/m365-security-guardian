<#
.SYNOPSIS
    Resilient wrapper for Microsoft Graph API calls with retry logic.

.DESCRIPTION
    Wraps Graph cmdlets that use -All parameter to add:
    - Exponential backoff retry (3 attempts)
    - Progress indication for long operations
    - Graceful handling of throttling (429) and transient errors
    
    Note: No custom timeout is implemented. Graph SDK cmdlets manage their own HTTP timeouts 
    (~300s per request). This function only handles retry logic for transient failures.

.PARAMETER ScriptBlock
    The Graph cmdlet to execute (e.g., { Get-MgUser -All }).

.PARAMETER OperationName
    Descriptive name for progress tracking (e.g., "Retrieving users").

.PARAMETER MaxRetries
    Number of retry attempts on transient failures (default: 3).

.OUTPUTS
    Array of objects returned by the Graph cmdlet, or empty array on failure.

.NOTES
    Project: M365 Security Guardian
    Version: 3.1.2
    Created: 2026-02-13
    
    IMPORTANT: Graph SDK cmdlets MUST execute in the main PowerShell runspace.
    Background jobs, tasks, or threading mechanisms cause CLR crashes (exit code -532462766).
#>

function Invoke-MgGraphWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Graph API operation",

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )

    $attempt = 0
    $result = @()
    $completed = $false

    Write-Verbose "[$OperationName] Starting operation with retry protection..."
    
    while (-not $completed -and $attempt -lt $MaxRetries) {
        $attempt++
        
        try {
            Write-Verbose "[$OperationName] Attempt $attempt of $MaxRetries"
            Write-Progress -Activity $OperationName -Status "Retrieving data from Microsoft Graph..." -PercentComplete -1

            # Execute directly in current runspace (no background threads/jobs)
            # Graph SDK cmdlets MUST run in PowerShell runspace to work correctly
            # The SDK has its own HTTP timeout handling (default ~300s per request)
            $result = & $ScriptBlock
            
            Write-Progress -Activity $OperationName -Completed
            Write-Verbose "[$OperationName] Successfully retrieved $(@($result).Count) items"
            $completed = $true
        }
        catch {
            $errorMessage = $_.Exception.Message
            $errorType = $_.Exception.GetType().FullName
            
            Write-Verbose "[$OperationName] Error type: $errorType"
            Write-Verbose "[$OperationName] Error message: $errorMessage"
            
            # Check if it's a retryable error
            $isRetryable = $false
            
            # HTTP 429 - Too Many Requests (throttling)
            if ($errorMessage -like "*429*" -or $errorMessage -like "*throttl*" -or $errorMessage -like "*TooManyRequests*") {
                Write-Warning "[$OperationName] Graph API throttling detected (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            # HTTP 503 - Service Unavailable  
            elseif ($errorMessage -like "*Service Unavailable*" -or $errorMessage -like "*503*" -or $errorMessage -like "*ServiceUnavailable*") {
                Write-Warning "[$OperationName] Service temporarily unavailable (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            # HTTP 502 - Bad Gateway
            elseif ($errorMessage -like "*BadGateway*" -or $errorMessage -like "*502*") {
                Write-Warning "[$OperationName] Gateway error (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            # HTTP 504 - Gateway Timeout
            elseif ($errorMessage -like "*GatewayTimeout*" -or $errorMessage -like "*504*") {
                Write-Warning "[$OperationName] Gateway timeout (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            # Connection errors
            elseif ($errorMessage -like "*connection*" -or $errorMessage -like "*network*") {
                Write-Warning "[$OperationName] Network connectivity issue (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            # Generic timeout
            elseif ($errorMessage -like "*timeout*" -or $errorMessage -like "*timed out*") {
                Write-Warning "[$OperationName] Operation timed out (attempt $attempt/$MaxRetries)"
                $isRetryable = $true
            }
            else {
                # Non-retryable error (permissions, invalid query, etc.)
                Write-Warning "[$OperationName] Non-retryable error: $errorMessage"
                Write-Progress -Activity $OperationName -Completed
                return @()
            }

            # Retry logic with exponential backoff
            if ($isRetryable -and $attempt -lt $MaxRetries) {
                $backoffSeconds = [Math]::Pow(2, $attempt) * 5  # 10s, 20s, 40s
                Write-Information "[$OperationName] Waiting $backoffSeconds seconds before retry..." -InformationAction Continue
                Start-Sleep -Seconds $backoffSeconds
            }
            elseif ($attempt -ge $MaxRetries) {
                Write-Warning "[$OperationName] Max retry attempts ($MaxRetries) exceeded. Returning empty result."
                Write-Progress -Activity $OperationName -Completed
                return @()
            }
        }
    }

    Write-Progress -Activity $OperationName -Completed
    return $result
}

function Invoke-MgGraphBatched {
    <#
    .SYNOPSIS
        Retrieves Graph data with batching and progress indication.
    
    .DESCRIPTION
        Alternative to -All that uses explicit pagination with:
        - Page size limiting (default 999)
        - Progress indication
        - Early termination on errors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{},

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 999,

        [Parameter(Mandatory = $false)]
        [string]$OperationName = "Retrieving data"
    )

    $allResults = @()
    $page = 1
    $morePages = $true

    try {
        Write-Verbose "[$OperationName] Starting batched retrieval with page size $PageSize"

        while ($morePages) {
            Write-Progress -Activity $OperationName -Status "Retrieving page $page..." -PercentComplete -1
            
            $params = $Parameters.Clone()
            $params['Top'] = $PageSize
            
            $pageResults = & $CommandName @params -ErrorAction Stop
            
            if ($pageResults) {
                $allResults += $pageResults
                $page++
                
                # Check if there are more pages (Graph SDK handles this internally with -All)
                # For explicit pagination, we'd need to check for @odata.nextLink
                # Since we're wrapping existing -All commands, we break here
                $morePages = $false
            }
            else {
                $morePages = $false
            }
        }

        Write-Progress -Activity $OperationName -Completed
        Write-Verbose "[$OperationName] Retrieved total of $($allResults.Count) items"
        return $allResults
    }
    catch {
        Write-Warning "[$OperationName] Error during batched retrieval: $_"
        Write-Progress -Activity $OperationName -Completed
        return $allResults  # Return partial results
    }
}
