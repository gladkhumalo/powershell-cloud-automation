# Microsoft Graph notes

Add authentication, permission, and API notes as you build M365 projects.

## Calling Graph directly with Invoke-MgGraphRequest

[Project 04](../projects/04-m365-security-assessment/README.md) uses `Invoke-MgGraphRequest` instead of the per-resource cmdlets, so it only needs `Microsoft.Graph.Authentication`.

- Relative URIs such as `v1.0/policies/authorizationPolicy` resolve against the connected cloud's Graph endpoint.
- `-OutputType PSObject` returns `PSCustomObject` values, which behave like objects loaded with `ConvertFrom-Json`. The same code can therefore evaluate live data and saved JSON snapshots.
- Collection responses are paged. Keep requesting `@odata.nextLink` until it is absent; reading only `value` from the first response silently drops data in larger tenants.
- Property names such as `@odata.type` contain a dot, so access them with `$item.'@odata.type'` or `PSObject.Properties['@odata.type']`, not a split-on-dot helper.

## Read-only security assessment permissions

| Data | Endpoint | Delegated scope | Notes |
| --- | --- | --- | --- |
| Security defaults | `policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | `isEnabled` |
| Conditional Access | `identity/conditionalAccess/policies` | `Policy.Read.All` | `state` is `enabled`, `disabled`, or `enabledForReportingButNotEnforced` (report-only) |
| Authorization policy | `policies/authorizationPolicy` | `Policy.Read.All` | Guest invitations, guest role, user consent, app registration |
| Global Administrators | `directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members` | `RoleManagement.Read.Directory` | Active assignments only; PIM eligibility is a separate API |
| MFA and SSPR registration | `reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | Needs Entra ID P1/P2 and a reader role such as Global Reader; excludes disabled users |
| Authentication methods | `policies/authenticationMethodsPolicy` | `Policy.Read.All` | Method configurations (`Sms`, `Voice`, `Email`, ...) are returned inline; `policyMigrationState` shows legacy policy migration |
| PIM active assignments | `roleManagement/directory/roleAssignmentScheduleInstances?$filter=roleDefinitionId eq '<id>'&$expand=principal` | `RoleManagement.Read.Directory` | `assignmentType` is `Assigned` (standing) or `Activated` (just-in-time) |
| PIM eligible assignments | `roleManagement/directory/roleEligibilityScheduleInstances?...` | `RoleManagement.Read.Directory` | Eligible users and groups that are not currently active |
| Role-assignable group members | `groups/{id}/transitiveMembers` | `GroupMember.Read.All` | Expands groups that hold a role directly or through PIM |

`RoleManagement.Read.Directory` is listed as a higher-privileged alternative to `RoleAssignmentSchedule.Read.Directory` and `RoleEligibilitySchedule.Read.Directory`, so one read-only scope covers the directory role and PIM reads. For built-in directory roles, the role definition ID equals the role template ID (Global Administrator: `62e90394-69f5-4237-9190-012177145e10`).

With delegated permissions, the signed-in user also needs a directory role that allows the read. Global Reader covers everything above without write access.
