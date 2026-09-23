# 01 — M365 User Audit

**Status:** v0.1 — basic CSV export

This first milestone retrieves users from Microsoft Graph and writes a focused CSV report. It is intentionally small so each later feature can be learned and added separately.

## What v0.1 does

1. Checks for `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users`.
2. Opens a device-code Graph session with delegated `User.Read.All` permission.
3. Retrieves all users and selects six properties: display name, user principal name, account enabled, user type, department, and job title.
4. Exports those properties to UTF-8 CSV and disconnects from Graph.

`User.Read.All` may require administrator consent in your tenant. The script reads user data; it does not modify accounts.

## Requirements

- PowerShell 7.2 or newer
- A Microsoft 365 account allowed to read users in the target tenant
- The two Graph modules, installed if needed with:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser
```

## Run

From the repository root:

```powershell
./projects/01-m365-user-audit/src/Get-M365UserAudit.ps1
```

Graph will display a sign-in URL and one-time code. Complete that sign-in with an account in the tenant you intend to audit.

The default CSV is `projects/01-m365-user-audit/output/M365-User-Audit.csv`, regardless of the current working directory. To choose another path:

```powershell
./projects/01-m365-user-audit/src/Get-M365UserAudit.ps1 -OutputPath './projects/01-m365-user-audit/output/Test-Tenant-Users.csv'
```

Review the CSV locally. It may contain personal and tenant information; `output/` is excluded from Git.

## Validation

v0.1 was run against a Microsoft 365 tenant with device-code sign-in. It produced a CSV with the six columns listed above. The live report is kept local and is not part of this repository.

## Why the report uses `Select-Object`

Graph returns user objects with many properties. `Select-Object` creates a narrow report with predictable columns before `Export-Csv` writes the file. In v0.2, this transformation can become explicit `[pscustomobject]` construction as calculated fields are added.

## Next milestone

v0.2 will make the account status and profile fields easier to interpret, and begin moving the transformation into a reusable function.
