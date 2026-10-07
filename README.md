# PowerShell Cloud Automation Portfolio

Hands-on PowerShell projects for Windows administration, Microsoft 365 reporting, and network diagnostics. Each project has a focused script, run instructions, and a place for tests and examples. Projects 01–03 have v0.1 implementations, Projects 04 and 07 have v0.2, and the remaining projects are planned.

## Try a project

The workstation health check runs locally on Windows:

```powershell
./projects/02-workstation-health-check/src/Get-WorkstationHealth.ps1 | Format-List
```

The network diagnostics project checks a local target without tenant access:

```powershell
./projects/07-network-diagnostics-toolkit/src/Invoke-NetworkDiagnostic.ps1 -Target localhost -TcpPort 443 | Format-List
```

The security assessment evaluates a fictional tenant offline, shows what changed since the previous month, and writes CSV, JSON, and HTML reports:

```powershell
./projects/04-m365-security-assessment/src/Invoke-M365SecurityAssessment.ps1 -SnapshotPath ./projects/04-m365-security-assessment/examples/sample-tenant-snapshot.json -CompareToSnapshotPath ./projects/04-m365-security-assessment/examples/sample-tenant-snapshot-previous.json -ConfigurationPath ./config/m365-security-assessment.example.json
```

Live Microsoft 365 runs require Graph modules and a tenant sign-in. Start with their project READMEs for prerequisites. To run all offline tests with Pester 3.4:

```powershell
Invoke-Pester ./projects/01-m365-user-audit/tests/Export-M365UserReport.Tests.ps1, ./projects/02-workstation-health-check/tests/Get-WorkstationHealth.Tests.ps1, ./projects/03-m365-license-audit/tests/Export-M365LicenseReport.Tests.ps1, ./projects/04-m365-security-assessment/tests/M365SecurityAssessment.Tests.ps1, ./projects/07-network-diagnostics-toolkit/tests/NetworkDiagnostics.Tests.ps1
```

GitHub Actions runs those tests on pushes and pull requests to `main`. The Graph connection still needs a manual tenant check.

## Projects

| Project | Focus | Status |
| --- | --- | --- |
| [01 — M365 User Audit](projects/01-m365-user-audit/README.md) | Microsoft Graph and user reporting | v0.1 |
| [02 — Workstation Health Check](projects/02-workstation-health-check/README.md) | Windows administration | v0.1 |
| [03 — M365 License Audit](projects/03-m365-license-audit/README.md) | License reporting | v0.1 |
| [04 — M365 Security Assessment](projects/04-m365-security-assessment/README.md) | Entra ID security checks, accepted risks, and drift comparison | v0.2 |
| [05 — Azure Resource Inventory](projects/05-azure-resource-inventory/README.md) | Azure reporting | Planned |
| [06 — Azure VM Health Check](projects/06-azure-vm-health-check/README.md) | Azure operations | Planned |
| [07 — Network Diagnostics Toolkit](projects/07-network-diagnostics-toolkit/README.md) | Network troubleshooting | v0.2 |
| [08 — Automation Runbook Project](projects/08-automation-runbook-project/README.md) | Scheduled cloud automation | Planned |

## Layout

- `docs/` — learning roadmap and topic notes
- `projects/` — one folder per portfolio project
- `modules/` — future reusable module structure
- `scripts/` — future standalone scripts by topic
- `sample-data/` — safe, fictional test data when needed
- `.github/` — future workflows and contribution templates
- `config/` — example settings; per-tenant assessment files are excluded from Git

Each project has `src/`, `tests/`, `examples/`, `output/`, and `screenshots/` folders. Empty folders contain `.gitkeep` files. Generated reports in `output/` are ignored by Git.

## Learning path

Windows and M365 administration → Microsoft Graph → Azure automation → reusable modules and testing → CI/CD and runbooks. See [learning roadmap](docs/learning-roadmap.md).
