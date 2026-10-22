# 05 — Azure Resource Inventory

**Status:** v0.1; offline and mocked validation complete, live Azure validation pending.

Lists Azure Resource Manager resources across selected subscriptions for an administrator to review resource ownership and regional distribution. CSV and JSON contain SubscriptionId, SubscriptionName, ResourceGroupName, Name, ResourceType, Location, and ResourceId. Rows sort by subscription, group, type, name, and ID.

## Offline usage

Run from the repository root using Windows PowerShell 5.1 or PowerShell 7:

```powershell
./projects/05-azure-resource-inventory/src/Export-AzureResourceInventory.ps1 -SnapshotPath ./projects/05-azure-resource-inventory/examples/sample-resources.json
```

The sample contains two fictional resources in different subscriptions and locations. No Azure modules or sign-in are needed. A snapshot is an object with a Resources array. Each resource requires the seven nonempty fields listed above; an empty array is valid.

## Live usage

Install Az.Accounts and Az.Resources and sign in before running:

```powershell
Install-Module Az.Accounts, Az.Resources -Scope CurrentUser
Connect-AzAccount
Get-AzSubscription | Select-Object Name, Id, TenantId
./projects/05-azure-resource-inventory/src/Export-AzureResourceInventory.ps1 -SubscriptionId '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'
```

Use an identity with Reader access at each selected subscription for full coverage. Narrower permissions may return only accessible resources. Subscription IDs are explicit; duplicate IDs are collected once. The script uses process-scoped Azure contexts, passes the selected context to resource queries, and restores the original context in a finally block. Azure operations are read-only.

## Output and limitations

The script returns ResourceCount, CsvPath, and JsonPath. The default destination is this project's ignored output folder. Use -OutputDirectory to choose another folder. Files are named azure-resource-inventory.csv and azure-resource-inventory.json and are overwritten on subsequent successful runs. Use separate directories to retain history. Empty results produce a header-only CSV and an empty JSON array. Single-resource JSON remains an array.

Collection and validation finish before writing reports. Collection failures terminate the run without writing a partial inventory; existing reports from previous runs remain, so check command success before using them. Filesystem writes are sequential and a write failure can leave one report written. The inventory covers ARM resources returned by Get-AzResource, not data-plane objects, empty resource groups, costs, or VM health. No live Azure validation has been performed.

## Tests

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester ./projects/05-azure-resource-inventory/tests/AzureResourceInventory.Tests.ps1
```

Seven offline/mocked tests cover sorting and export parity, empty results, CSV punctuation and Unicode, single-resource JSON, invalid snapshots, subscription selection, context restoration, collection failure, and missing sign-in. Az modules and credentials are not needed for tests.

References: [Get-AzResource](https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azresource), [Azure contexts](https://learn.microsoft.com/en-us/powershell/azure/context-persistence), and [Set-AzContext](https://learn.microsoft.com/en-us/powershell/module/az.accounts/set-azcontext).
