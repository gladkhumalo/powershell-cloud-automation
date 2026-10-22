<#
.SYNOPSIS
Exports Azure Resource Manager resources to CSV and JSON, or processes an offline snapshot.
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param (
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string[]] $SubscriptionId,

    [Parameter(Mandatory, ParameterSetName = 'Offline')]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath,

    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '../output')
)

$ErrorActionPreference = 'Stop'
$resources = @()
if ($PSCmdlet.ParameterSetName -eq 'Offline') {
    $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw | ConvertFrom-Json
    if ($null -eq $snapshot -or $snapshot.Resources -isnot [array]) {
        throw 'Snapshot must contain a Resources array (which may be empty).'
    }
    $resources = @($snapshot.Resources)
}
else {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    $originalContext = Get-AzContext -ErrorAction Stop
    if (-not $originalContext) { throw 'Sign in with Connect-AzAccount before running this script.' }
    try {
        foreach ($id in ($SubscriptionId | Select-Object -Unique)) {
            $subscription = Get-AzSubscription -SubscriptionId $id -ErrorAction Stop
            if (@($subscription).Count -ne 1) { throw "Subscription '$id' did not resolve uniquely." }
            $context = Set-AzContext -Subscription $subscription.Id -Tenant $subscription.TenantId -Scope Process -ErrorAction Stop
            foreach ($resource in @(Get-AzResource -DefaultProfile $context -ErrorAction Stop)) {
                $resources += [pscustomobject]@{
                    SubscriptionId = $subscription.Id
                    SubscriptionName = $subscription.Name
                    ResourceGroupName = $resource.ResourceGroupName
                    Name = $resource.Name
                    ResourceType = $resource.ResourceType
                    Location = $resource.Location
                    ResourceId = $resource.ResourceId
                }
            }
        }
    }
    finally {
        $null = Set-AzContext -Context $originalContext -Scope Process -ErrorAction Stop
    }
}

$fields = @('SubscriptionId', 'SubscriptionName', 'ResourceGroupName', 'Name', 'ResourceType', 'Location', 'ResourceId')
foreach ($resource in $resources) {
    foreach ($field in $fields) {
        if ($null -eq $resource -or [string]::IsNullOrWhiteSpace([string]$resource.$field)) {
            throw "Resource is missing required field '$field'."
        }
    }
}
$report = @($resources | Sort-Object SubscriptionId, ResourceGroupName, ResourceType, Name, ResourceId | Select-Object -Property $fields)
$directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$null = New-Item -ItemType Directory -Path $directory -Force
$csvPath = Join-Path $directory 'azure-resource-inventory.csv'
$jsonPath = Join-Path $directory 'azure-resource-inventory.json'
if ($report.Count -eq 0) {
    ($fields -join ',') | Set-Content -LiteralPath $csvPath -Encoding utf8
}
else {
    $report | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
}
ConvertTo-Json -InputObject @($report) -Depth 5 | Set-Content -LiteralPath $jsonPath -Encoding utf8
[pscustomobject]@{ ResourceCount = $report.Count; CsvPath = $csvPath; JsonPath = $jsonPath }
