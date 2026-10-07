function Export-M365SecurityReport {
    <#
    .SYNOPSIS
    Writes findings (and optional drift) to timestamped CSV, JSON, and HTML reports and returns the files.
    .EXAMPLE
    Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -OutputDirectory ./output
    .EXAMPLE
    $drift = Compare-M365SecuritySnapshot -ReferenceSnapshot $previous -DifferenceSnapshot $snapshot
    Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -Drift $drift -ReferenceSnapshot $previous -OutputDirectory ./output
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $OutputDirectory,
        [AllowEmptyCollection()] [object[]] $Drift = @(),
        [AllowNull()] [object] $ReferenceSnapshot,
        [ValidatePattern('^[\w.-]+$')] [string] $BaseName = 'M365-Security-Assessment',
        [ValidateSet('Csv', 'Html', 'Json')] [string[]] $Format = @('Csv', 'Html', 'Json')
    )

    $directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $stamp = Format-SnapshotDate -Snapshot $Snapshot -Format 'yyyyMMdd-HHmmss'
    $tenantId = [string] (Get-PropertyValue $Snapshot 'TenantId')
    $collectedAt = Format-SnapshotDate -Snapshot $Snapshot -Format 'o'
    $referenceAt = if ($ReferenceSnapshot) { Format-SnapshotDate -Snapshot $ReferenceSnapshot -Format 'o' } else { $null }

    foreach ($kind in ($Format | Select-Object -Unique)) {
        $path = Join-Path $directory "$BaseName-$stamp.$($kind.ToLowerInvariant())"
        switch ($kind) {
            'Csv' {
                $columns = 'TenantId,CollectedAtUtc,CheckId,Category,Title,Severity,Status,OriginalStatus,Observed,Recommendation,AffectedCount,AffectedObjects,AcceptanceNote,BaselineControls,Reference'
                if (@($Finding).Count -eq 0) {
                    $columns | Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
                }
                else {
                    $Finding | ForEach-Object {
                        [pscustomobject]@{
                            TenantId         = $tenantId
                            CollectedAtUtc   = $collectedAt
                            CheckId          = $_.CheckId
                            Category         = $_.Category
                            Title            = $_.Title
                            Severity         = $_.Severity
                            Status           = $_.Status
                            OriginalStatus   = $_.OriginalStatus
                            Observed         = $_.Observed
                            Recommendation   = $_.Recommendation
                            AffectedCount    = $_.AffectedCount
                            AffectedObjects  = @($_.AffectedObjects) -join '; '
                            AcceptanceNote   = $_.AcceptanceNote
                            BaselineControls = @($_.BaselineControls) -join '; '
                            Reference        = $_.Reference
                        }
                    } | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8 -ErrorAction Stop
                }
                if ($ReferenceSnapshot) {
                    $driftPath = Join-Path $directory "$BaseName-Drift-$stamp.csv"
                    if (@($Drift).Count -eq 0) {
                        'ReferenceCollectedAtUtc,CollectedAtUtc,Category,Item,ChangeType,Before,After,Detail' |
                            Set-Content -LiteralPath $driftPath -Encoding utf8 -ErrorAction Stop
                    }
                    else {
                        $Drift | Select-Object @{ n = 'ReferenceCollectedAtUtc'; e = { $referenceAt } }, @{ n = 'CollectedAtUtc'; e = { $collectedAt } },
                            Category, Item, ChangeType, Before, After, Detail |
                            Export-Csv -LiteralPath $driftPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop
                    }
                    Get-Item -LiteralPath $driftPath
                }
            }
            'Json' {
                $report = [ordered]@{
                    Tool           = 'M365SecurityAssessment'
                    ToolVersion    = $script:ToolVersion
                    TenantId       = $tenantId
                    CollectedBy    = [string] (Get-PropertyValue $Snapshot 'CollectedBy')
                    CollectedAtUtc = $collectedAt
                    Summary        = Get-FindingSummary -Finding $Finding
                    Findings       = @($Finding)
                }
                if ($ReferenceSnapshot) {
                    $report.ReferenceCollectedAtUtc = $referenceAt
                    $report.Drift = @($Drift)
                }
                [pscustomobject] $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
            }
            'Html' {
                ConvertTo-SecurityReportHtml -Finding @($Finding) -Snapshot $Snapshot -Drift @($Drift) -ReferenceSnapshot $ReferenceSnapshot |
                    Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
            }
        }
        Get-Item -LiteralPath $path
    }
}
