function Import-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Loads a saved snapshot for offline assessment or comparison.
    .EXAMPLE
    Import-M365SecuritySnapshot -Path ./examples/sample-tenant-snapshot.json | Get-M365SecurityFinding
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $snapshot = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 64
    Assert-SnapshotSchema -Snapshot $snapshot
    $snapshot
}
