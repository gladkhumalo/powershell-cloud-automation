function Compare-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Reports what changed between two snapshots of the same tenant.
    .DESCRIPTION
    Returns one change per difference: findings that regressed or improved, accounts that became
    newly affected, and raw configuration changes (Conditional Access policies, Global
    Administrator assignments, authorization policy settings, and authentication methods).
    Both snapshots are evaluated with the same configuration so only tenant changes are reported.
    .EXAMPLE
    Compare-M365SecuritySnapshot -ReferenceSnapshot $lastMonth -DifferenceSnapshot $today |
        Where-Object ChangeType -in 'Regressed', 'NewlyAffected'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object] $ReferenceSnapshot,
        [Parameter(Mandatory)] [object] $DifferenceSnapshot,
        [AllowNull()] [object] $Configuration
    )

    Assert-SnapshotSchema -Snapshot $ReferenceSnapshot
    Assert-SnapshotSchema -Snapshot $DifferenceSnapshot
    $referenceTenant = [string] (Get-PropertyValue $ReferenceSnapshot 'TenantId')
    $differenceTenant = [string] (Get-PropertyValue $DifferenceSnapshot 'TenantId')
    if ($referenceTenant -and $differenceTenant -and $referenceTenant -ne $differenceTenant) {
        throw "Cannot compare snapshots from different tenants ('$referenceTenant' and '$differenceTenant')."
    }

    $before = @(Get-M365SecurityFinding -Snapshot $ReferenceSnapshot -Configuration $Configuration)
    $after = @(Get-M365SecurityFinding -Snapshot $DifferenceSnapshot -Configuration $Configuration)
    $categoryRank = @{ Finding = 0; Collection = 2 }

    @(Compare-FindingSet -Before $before -After $after) + @(Compare-ConfigurationSource -Reference $ReferenceSnapshot -Difference $DifferenceSnapshot) |
        Sort-Object `
            @{ Expression = { if ($categoryRank.ContainsKey($_.Category)) { $categoryRank[$_.Category] } else { 1 } } },
            @{ Expression = { $script:ChangeTypeRank[$_.ChangeType] } },
            Category, Item
}
