function Import-M365SecurityConfiguration {
    <#
    .SYNOPSIS
    Loads and validates a per-tenant assessment configuration file.
    .DESCRIPTION
    The configuration lists emergency-access accounts, optional threshold overrides, and accepted
    risks with an owner, reason, and expiry date. Validation errors list every problem at once.
    .EXAMPLE
    $configuration = Import-M365SecurityConfiguration -Path ./config/contoso.json
    $snapshot | Get-M365SecurityFinding -Configuration $configuration
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $raw = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 32
    ConvertTo-SecurityConfiguration -InputObject $raw
}
