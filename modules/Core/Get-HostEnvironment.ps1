<#
.SYNOPSIS
    Detects the PowerShell host environment and configures display characters.

.DESCRIPTION
    Determines whether the script is running in PowerShell ISE, VS Code,
    Windows Terminal, or a standard console, and sets script-scoped variables
    for Unicode characters that may not render correctly in all environments.

    ISE uses the Consolas font which cannot render certain Unicode glyphs.
    This module provides ASCII fallbacks for those environments.

.NOTES
    Project: M365 Security Guardian
    This module should be dot-sourced before any console output is generated.
#>

function Initialize-HostEnvironment {
    <#
    .SYNOPSIS
        Detects the host environment and sets display character variables.

    .DESCRIPTION
        Sets script-scoped variables for Unicode/ASCII characters based on
        the detected PowerShell host. ISE and hosts with limited Unicode
        support get ASCII fallbacks.

    .OUTPUTS
        Sets the following script-scoped variables:
        - $script:HostType          : 'ISE', 'VSCode', 'WindowsTerminal', 'Console'
        - $script:SupportsUnicode   : $true/$false
        - $script:CheckMark         : '✓' or '+'
        - $script:CrossMark         : '✗' or 'x'
        - $script:InfoMark          : 'i' or 'i'
        - $script:WarningMark       : '!' or '!'
        - $script:ArrowUp           : '^' or '^'
        - $script:ArrowDown         : 'v' or 'v'
        - $script:ArrowRight        : '->' or '->'
        - $script:BlockFull         : '#' or '#'
        - $script:BlockLight        : '-' or '-'
        - $script:Bullet            : '*' or '*'
    #>
    [CmdletBinding()]
    param()

    # Detect host type
    $script:HostType = switch ($Host.Name) {
        'Windows PowerShell ISE Host' { 'ISE' }
        'Visual Studio Code Host'     { 'VSCode' }
        default                       { 'Console' }
    }

    # Check for Windows Terminal (supports full Unicode)
    if ($script:HostType -eq 'Console' -and $env:WT_SESSION) {
        $script:HostType = 'WindowsTerminal'
    }

    # Determine Unicode support
    # ISE has limited Unicode rendering with Consolas font
    # All other modern hosts support Unicode well
    $script:SupportsUnicode = $script:HostType -ne 'ISE'

    # Set display characters based on Unicode support
    if ($script:SupportsUnicode) {
        $script:CheckMark   = [char]0x2713  # ✓
        $script:CrossMark   = [char]0x2717  # ✗
        $script:InfoMark    = 'i'           # ℹ renders poorly even in some Unicode hosts
        $script:WarningMark = '!'
        $script:ArrowUp     = [char]0x2191  # ↑
        $script:ArrowDown   = [char]0x2193  # ↓
        $script:ArrowRight  = [char]0x2192  # →
        $script:BlockFull   = [char]0x2588  # █
        $script:BlockLight  = [char]0x2591  # ░
        $script:Bullet      = [char]0x2022  # •
    }
    else {
        $script:CheckMark   = '+'
        $script:CrossMark   = 'x'
        $script:InfoMark    = 'i'
        $script:WarningMark = '!'
        $script:ArrowUp     = '^'
        $script:ArrowDown   = 'v'
        $script:ArrowRight  = '->'
        $script:BlockFull   = '#'
        $script:BlockLight  = '-'
        $script:Bullet      = '*'
    }

    Write-Verbose "Host environment: $($script:HostType) (Unicode: $($script:SupportsUnicode))"
}

function Get-HostEnvironmentInfo {
    <#
    .SYNOPSIS
        Returns the current host environment detection results.
    #>
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        HostType        = $script:HostType
        HostName        = $Host.Name
        SupportsUnicode = $script:SupportsUnicode
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        PSEdition       = $PSVersionTable.PSEdition
    }
}

# Auto-initialize when dot-sourced
Initialize-HostEnvironment
