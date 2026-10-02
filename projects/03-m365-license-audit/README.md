# 03 — M365 License Audit

**Status:** v0.1 — subscribed SKU capacity CSV

This report helps an administrator see how many licenses of each subscribed SKU are enabled, consumed, and available. It reads tenant subscription data and does not change license assignments.

## Requirements

- PowerShell 7.2 or newer
- A Microsoft 365 work or school account with permission to read subscribed SKUs. Microsoft Graph requires the delegated `LicenseAssignment.Read.All` scope and a supported Microsoft Entra role or equivalent custom role.
- Microsoft Graph modules:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
```

## Run

From the repository root:

```powershell
./projects/03-m365-license-audit/src/Get-M365LicenseAudit.ps1
```

Complete the device-code sign-in for the tenant you intend to audit. The default CSV is `projects/03-m365-license-audit/output/M365-License-Audit.csv`. Use `-OutputPath` to choose another location.

```powershell
./projects/03-m365-license-audit/src/Get-M365LicenseAudit.ps1 -OutputPath './projects/03-m365-license-audit/output/My-Tenant-Licenses.csv'
```

The CSV columns are `SkuPartNumber`, `SkuId`, `CapabilityStatus`, `EnabledUnits`, `ConsumedUnits`, and `AvailableUnits`. Available units are calculated as enabled minus consumed; a negative value is preserved if Graph reports more consumed units than enabled units. An empty tenant produces a header-only CSV. The output folder is excluded from Git because reports contain tenant information.

Example with fictional data:

```csv
SkuPartNumber,SkuId,CapabilityStatus,EnabledUnits,ConsumedUnits,AvailableUnits
EXAMPLE_SKU,11111111-1111-1111-1111-111111111111,Enabled,100,75,25
```

This first milestone reports subscription capacity only. It does not list users or identify who holds a license. A later milestone can add per-user assignments and map SKU part numbers to friendly product names.

## Validation

The CSV conversion is in `src/Export-M365LicenseReport.ps1`, so it can be tested without Graph modules or a tenant. From the repository root, run:

```powershell
Invoke-Pester ./projects/03-m365-license-audit/tests/Export-M365LicenseReport.Tests.ps1
```

The three tests use fictional SKUs to check normal counts, an empty report, and over-consumption. They pass with Pester 3.4 and PowerShell 7.6. Live Graph retrieval has not been validated yet; it needs a tenant sign-in and the Graph modules. Review the resulting CSV locally before sharing it.

## References

- [Microsoft Graph subscribed SKUs API](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
- [Get-MgSubscribedSku](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgsubscribedsku?view=graph-powershell-1.0)
