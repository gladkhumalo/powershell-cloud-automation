# 07 — Network Diagnostics Toolkit

**Status:** v0.2 — local diagnostic report with optional path context

This read-only PowerShell tool checks one or more targets from a Windows workstation. It records name resolution, one ICMP echo, and a TCP connection attempt to a chosen port as **separate results**. An optional local snapshot shows the source address, interface, selected route, gateway, and DNS servers. It returns objects for investigation or export; it does not change network settings or write a file by default.

## Why this exists

A support engineer needs a repeatable first check when someone says “the service is down.” A successful ping does not prove the application port is open, and a failed ping does not prove TCP is down. The report keeps those observations separate and avoids declaring a root cause from one test.

## Requirements

- Windows with PowerShell 7.2 or newer and the built-in `DnsClient` module.
- Access to the target appropriate for your lab or operational role. ICMP may be filtered, and TCP results depend on the selected port and the network path.
- No cloud account is required. The basic checks work without administrator rights; Windows may deny the optional route or interface queries in some environments. The report records that status and keeps the other results.

## Run

From the repository root, start with your own workstation:

```powershell
./projects/07-network-diagnostics-toolkit/src/Invoke-NetworkDiagnostic.ps1 -Target localhost -TcpPort 443 | Format-List
```

Use multiple targets or pipeline input when investigating a known lab or approved network:

```powershell
$results = @('localhost', '127.0.0.1') |
    ./projects/07-network-diagnostics-toolkit/src/Invoke-NetworkDiagnostic.ps1 -TcpPort 443 -TimeoutSeconds 2
$results | Format-Table Target, NameResolutionStatus, IcmpStatus, TcpPort, TcpStatus
```

Add local path context when you need to check which interface and route Windows selected:

```powershell
$result = ./projects/07-network-diagnostics-toolkit/src/Invoke-NetworkDiagnostic.ps1 `
    -Target 10.10.10.20 -TcpPort 8443 -IncludeLocalContext
$result | Format-List Target, TestedAddress, IcmpStatus, TcpStatus
$result.LocalContext | Format-List
```

The [three-case troubleshooting walkthrough](examples/three-case-troubleshooting-walkthrough.md) uses a fictional two-VM office service to practice DNS failure, blocked ICMP with working TCP, and an unavailable TCP service. Its expected patterns are prompts until you run and document them.

The same function is exported by [`src/NetworkDiagnostics.psm1`](src/NetworkDiagnostics.psm1) for reuse:

```powershell
Import-Module ./projects/07-network-diagnostics-toolkit/src/NetworkDiagnostics.psm1 -Force
Invoke-NetworkDiagnostic -Target localhost -TcpPort 443
```

To save a report, choose an appropriate path and sanitize it before sharing. The project's `output/` folder is ignored by Git:

```powershell
$results | Select-Object TimestampUtc, Target, TestedAddress, NameResolutionStatus,
    IcmpStatus, IcmpLatencyMs, TcpPort, TcpStatus, NameResolutionError, IcmpError, TcpError |
    Export-Csv ./projects/07-network-diagnostics-toolkit/output/diagnostics.csv -NoTypeInformation
```

## Read the result

| Field | Meaning |
| --- | --- |
| `NameResolutionStatus` | `Succeeded` for a hostname, `NotNeeded` for an IP literal, or `Failed`. |
| `ResolvedAddresses` / `TestedAddress` | All returned addresses, and the single address used for ICMP and TCP. IPv4 is preferred when present. |
| `IcmpStatus` / `IcmpLatencyMs` | One ICMP echo result and latency if successful. A failure may mean filtering rather than host unavailability. |
| `TcpPort` / `TcpStatus` | TCP connection to the tested address and chosen port: `Succeeded`, `Failed`, `TimedOut`, or `NotRun`. |
| `*Error` | Error text for a failed check; useful evidence, not an automatic diagnosis. |
| `LocalContext` | `$null` by default. With `-IncludeLocalContext`, contains `Status`, `SourceAddress`, `InterfaceAlias`, `InterfaceIndex`, `RoutePrefix`, `NextHop`, `DefaultGateway`, `DnsServers`, and `Error`. |

If name resolution fails, the script marks ICMP, TCP, and local route selection `NotRun`; use `Get-DnsClientServerAddress` separately to inspect resolver settings. When a hostname resolves to multiple addresses, it tests **one** address; supply a specific IP for the others. A TCP connect proves only that a connection was accepted, not that TLS, HTTP, authentication, or the application works. The `TimeoutSeconds` setting bounds the ICMP and TCP attempts, not the operating system's name lookup or the optional Windows route/configuration cmdlets. [Microsoft Test-Connection](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection?view=powershell-7.6), [Microsoft Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname)

The local snapshot uses [Find-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/find-netroute?view=windowsserver2025-ps) to obtain Windows' selected source address and route, then [Get-NetIPConfiguration](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration?view=windowsserver2025-ps) for that interface's gateway and DNS servers. `Succeeded` means both queries returned data, `Partial` means route selection succeeded but interface details did not, `Unavailable` means route selection failed, and `NotRun` means no target address was available. This is a snapshot of Windows' route decision; it does not prove packets traversed that path. Local interface and DNS details can be sensitive; sanitize exports before sharing.

## Verification

Run the offline Pester suite:

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester ./projects/07-network-diagnostics-toolkit/tests/NetworkDiagnostics.Tests.ps1
```

The tests cover a literal IP, a mixed IPv4/IPv6 lookup, failed resolution, an ICMP failure with a successful TCP check, pipeline targets, local route/interface context, denied route access, input validation, and a TCP connection to a local listener. All 18 repository tests passed locally with PowerShell 7.6.6 and Pester 3.4.0. A restricted local smoke check returned `Unavailable` for route context while keeping the probe results. A read-only host-access check against a private example destination returned `Succeeded` with source address, route, gateway, and DNS fields present; no local values were committed. GitHub Actions runs the offline tests on pull requests and pushes to `main`.

## Next improvements

Add a compact human-readable summary after the structured results prove useful. Keep actual target names, internal addresses, screenshots, and exported reports out of public examples unless sanitized.
