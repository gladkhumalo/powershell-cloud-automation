# Changelog

## Unreleased

- Added Project 04 v0.2: four new checks (weak authentication methods, SSPR, standing Global Administrator access, and emergency-access lockout protection), PIM-eligible and group-based Global Administrator counting, a per-tenant configuration file with accepted risks that expire, snapshot drift comparison in the HTML/CSV/JSON reports, CISA SCuBA baseline IDs on findings, `-FailOnSeverity` exit codes, and a Public/Private module layout with 59 offline tests.
- Added Project 04 v0.1: a read-only Microsoft 365 security assessment with ten Entra ID checks (MFA enforcement, legacy authentication, MFA registration, Global Administrator count, admin MFA and phishing-resistant methods, user consent, app registration, and guest access), offline snapshot mode with a fictional sample tenant, CSV/JSON/HTML reports, and 30 offline Pester tests in CI.
- Added optional local route, source-interface, gateway, and DNS context to Project 07, plus a three-case troubleshooting lab walkthrough.
- Added Project 07 v0.1: read-only name resolution, ICMP, and TCP checks with structured results, offline Pester tests, and CI coverage.
- Extracted Project 01 CSV generation and added offline Pester tests for user status, CSV text, and empty results.
- Added GitHub Actions to run the offline Pester tests on pushes and pull requests to `main`.
- Added Pester tests for Project 02 calculations and missing measurements.
- Added Project 03 v0.1: a Microsoft Graph subscribed SKU capacity CSV.
- Separated Project 03 CSV generation from Graph retrieval and added offline Pester tests.
- Added Project 02 v0.1: a structured local workstation health report with uptime, CPU, memory, and fixed-disk details.
- Started Project 02 with four raw CIM discovery queries and property notes.
- Added Project 01 v0.1: Graph user retrieval and basic CSV export.
- Created the repository structure and documentation placeholders.
