# 04 — M365 Security Assessment

**Status:** v0.1 — ten read-only identity, privileged access, application, and guest checks

This tool reviews a Microsoft 365 tenant's Microsoft Entra ID configuration and reports what an attacker would look for first: accounts that can sign in with only a password, too many or poorly protected Global Administrators, users who can grant apps access to company data, and open guest access. It reads configuration through Microsoft Graph, **never changes anything**, and writes CSV, JSON, and HTML reports with a recommendation and Microsoft Learn reference for every finding.

![Sample HTML report generated from the fictional tenant snapshot](screenshots/sample-report.png)

## Who it is for

An administrator, consultant, or managed service provider who needs a fast, repeatable baseline before a deeper review, after onboarding a new tenant, or on a schedule to catch configuration drift. The HTML report is written for an IT manager; the CSV and JSON are for tracking, comparison, and import into other tools.

## Try it without a tenant

A fictional tenant snapshot is included, so you can see the full workflow offline. From the repository root:

```powershell
./projects/04-m365-security-assessment/src/Invoke-M365SecurityAssessment.ps1 `
    -SnapshotPath ./projects/04-m365-security-assessment/examples/sample-tenant-snapshot.json
```

The run prints a summary and writes timestamped CSV, JSON, and HTML reports to `projects/04-m365-security-assessment/output/`. Ready-made results are in [`examples/sample-report.html`](examples/sample-report.html) and [`examples/sample-report.csv`](examples/sample-report.csv).

## Checks

| ID | Check | Severity | Pass | Warn | Fail |
| --- | --- | --- | --- | --- | --- |
| ID-001 | MFA is enforced for all users | High | Security defaults on, or an enabled Conditional Access policy requires MFA or an authentication strength for all users and all resources | A qualifying policy is report-only, or MFA covers only selected admin roles | Neither |
| ID-002 | Legacy authentication is blocked | High | Security defaults on, or an enabled policy blocks Exchange ActiveSync **and** other clients for all users | A qualifying policy is report-only | Neither |
| ID-003 | Members are registered for MFA | Medium | ≥ 95% of member accounts registered | ≥ 80% | < 80% |
| PRIV-001 | Global Administrator count is within range | High | 2–4 users | Fewer than 2, or a group/service principal holds the role | More than 4 |
| PRIV-002 | Administrators are registered for MFA | High | Every admin registered | — | Any admin unregistered |
| PRIV-003 | Administrators have phishing-resistant methods | Medium | Every admin has FIDO2, a passkey, or Windows Hello for Business | Any admin without one | — |
| APP-001 | User consent to applications is restricted | High | User consent disabled | Consent limited by a policy such as `microsoft-user-default-low` | Legacy policy: users can consent to any app |
| APP-002 | Users cannot register applications | Medium | Disabled | Enabled | — |
| COLLAB-001 | Guest invitations are restricted | Medium | Admins and Guest Inviters only, or disabled | All members can invite | Everyone, including guests, can invite |
| COLLAB-002 | Guest directory access is restricted | Low | Restricted to own objects | Limited (Microsoft default) | Same access as members |

Every finding has one of four statuses. **NotAssessed** means the data needed for that check could not be collected, for example because of a missing permission or license. The tool reports this instead of guessing a result. One failed data source never stops the rest of the assessment.

The Global Administrator range and MFA registration percentages are defaults, not fixed rules. Adjust them with `-MinimumGlobalAdmins`, `-MaximumGlobalAdmins`, `-MfaRegistrationTargetPercent`, and `-MfaRegistrationMinimumPercent`.

## Requirements

- PowerShell 7.2 or newer.
- For live runs, the Microsoft Graph authentication module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

- An account with the **Global Reader** role (recommended), or Security Reader. The script requests these delegated, read-only scopes, which may need admin consent the first time:

| Scope | Used for |
| --- | --- |
| `Policy.Read.All` | Security defaults, Conditional Access policies, authorization policy |
| `RoleManagement.Read.Directory` | Global Administrator role members |
| `AuditLog.Read.All` | User registration details (MFA and method registration) |

Registration details come from the authentication methods activity report, which [requires Microsoft Entra ID P1 or P2](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity#permissions-and-licenses). Without it, ID-003, PRIV-002, and PRIV-003 report NotAssessed and the other checks still run.

## Run against a tenant

```powershell
./projects/04-m365-security-assessment/src/Invoke-M365SecurityAssessment.ps1 -SaveSnapshot
```

Complete the device-code sign-in for the tenant you are authorized to assess. Use `-TenantId` to target a specific tenant, `-OutputDirectory` to choose where reports go, `-Format Html` to write only some formats, and `-PassThru` to return the finding objects to the pipeline. The script warns if any requested scope was not granted, and it disconnects from Graph when it finishes.

`-SaveSnapshot` also saves the raw configuration as JSON. You can re-run the assessment on it later with `-SnapshotPath`, with no sign-in needed, so a review is reproducible and two points in time can be compared.

The functions are also available as a module for scripting:

```powershell
Import-Module ./projects/04-m365-security-assessment/src/M365SecurityAssessment.psd1
Connect-MgGraph -Scopes Policy.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All
$snapshot = Get-M365SecuritySnapshot
$findings = $snapshot | Get-M365SecurityFinding
$findings | Where-Object Status -in 'Fail', 'Warn' | Format-Table Status, Severity, CheckId, Title
Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -OutputDirectory ./output
```

## Design

```text
Graph (read-only) --> Get-M365SecuritySnapshot --> snapshot (JSON-serializable)
                                                        |
                       Import-M365SecuritySnapshot -----+
                                                        v
                                             Get-M365SecurityFinding   (pure evaluation, no Graph calls)
                                                        v
                                             Export-M365SecurityReport (CSV, JSON, HTML)
```

Collection and evaluation are separate on purpose. All the security logic runs on plain data, so it can be tested offline. A saved snapshot always produces the same findings, and new checks can be added without new Graph calls when the data is already collected. Graph requests go through `Invoke-MgGraphRequest` with paging, so only `Microsoft.Graph.Authentication` is needed.

## Output

| File | Contents |
| --- | --- |
| `M365-Security-Assessment-<yyyyMMdd-HHmmss>.html` | Summary counts and findings sorted by status and severity, with affected accounts and guidance links. Light and dark themes. |
| `M365-Security-Assessment-<timestamp>.csv` | One row per check. Includes `TenantId` and `CollectedAtUtc`, so reports from several tenants or dates can be combined. |
| `M365-Security-Assessment-<timestamp>.json` | Summary and full findings, including every affected account. |
| `M365-Security-Snapshot-<timestamp>.json` | Raw collected configuration (with `-SaveSnapshot`). |

The timestamp is the collection time in UTC. Reports contain tenant IDs, policy names, and user principal names; the `output/` folder is excluded from Git. Store and share reports as confidential.

## Limitations

- **Active assignments only.** PRIV-001 counts active Global Administrator assignments. Eligible Privileged Identity Management (PIM) assignments are not included, and members of role-assignable groups are not expanded.
- **Policy intent, not sign-in outcome.** The Conditional Access checks look for a tenant-wide policy. They do not simulate every sign-in, network location, or exclusion, so review excluded accounts (normally only emergency-access accounts) separately.
- **Registration data excludes disabled users.** Microsoft's registration report omits disabled accounts. Unlicensed shared mailboxes and service accounts may still appear as unregistered members.
- **Phishing-resistant methods** are identified by registered method names (`fido2`, `windowsHelloForBusiness`, `passKey*`). Certificate-based authentication is not counted yet.
- This is a configuration baseline, not a full security assessment. It does not cover Exchange Online, SharePoint, Teams, Defender, Intune, or audit log settings.

## Validation

The offline Pester suite covers every check's Pass, Warn, Fail, and NotAssessed branches, threshold boundaries (including a value that rounds to 95.0% but is below target), Graph paging and partial collection failure (with mocked Graph calls), snapshot round-trips, report file names and contents, and HTML encoding of tenant-supplied names:

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester ./projects/04-m365-security-assessment/tests/M365SecurityAssessment.Tests.ps1
```

All 30 tests pass with PowerShell 7.6.6 and Pester 3.4.0, and GitHub Actions runs them on pull requests and pushes to `main`. PSScriptAnalyzer reports no errors; the remaining warnings are deliberate `Write-Host` console progress and in-memory `New-*` helpers. Live Graph collection has not been validated against a tenant yet. Before relying on results, run it once in a test tenant, compare each finding with the Entra admin center, and record the outcome here.

## Next improvements

- Count eligible PIM assignments and expand role-assignable groups for PRIV-001.
- Add checks for self-service password reset, authentication method policy (SMS and voice), and risky sign-in policies.
- Compare two snapshots to report configuration drift.
- Map checks to CIS Microsoft 365 Foundations Benchmark control numbers.

## References

- [Security defaults in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults)
- [Conditional Access: require MFA for all users](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength)
- [Conditional Access: block legacy authentication](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication)
- [Best practices for Microsoft Entra roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices)
- [List userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- [Configure external collaboration settings](https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure)
