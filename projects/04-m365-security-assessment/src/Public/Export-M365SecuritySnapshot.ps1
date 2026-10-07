function Export-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Saves a snapshot as JSON so it can be re-assessed offline or compared later.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $directory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $Snapshot | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $fullPath -Encoding utf8 -ErrorAction Stop
    Get-Item -LiteralPath $fullPath
}
