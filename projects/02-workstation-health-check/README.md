# 02 — Workstation Health Check

**Status:** Discovery step for v0.1

This project will turn Windows troubleshooting data into a clear workstation health report. The current script intentionally runs only four raw CIM queries. It does not build a health object or export a file yet.

## Run the discovery script

On Windows, from the repository root:

```powershell
./projects/02-workstation-health-check/src/Get-WorkstationHealth.ps1
```

To learn what each class returns, run a query on its own and inspect its properties:

```powershell
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$os | Get-Member -MemberType Property
$os | Select-Object Caption, Version, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory
```

Repeat that pattern with `Win32_ComputerSystem`, `Win32_Processor`, and `Win32_LogicalDisk -Filter 'DriveType=3'`. The script itself leaves the objects raw so you can see what Windows supplies before deciding how to shape the report.

## Properties identified

| CIM class | Properties useful for the planned report | Detail to remember |
| --- | --- | --- |
| [`Win32_OperatingSystem`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) | `Caption`, `Version`, `LastBootUpTime`, `TotalVisibleMemorySize`, `FreePhysicalMemory` | The two memory values are in kilobytes. |
| [`Win32_ComputerSystem`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem) | `Name`, `UserName`, `TotalPhysicalMemory` | Total physical memory is in bytes; `UserName` refers to the console user in a terminal-services scenario. |
| [`Win32_Processor`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor) | `Name`, `LoadPercentage` | Load percentage is a recent sample for each processor. |
| [`Win32_LogicalDisk`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk) | `DeviceID`, `DriveType`, `Size`, `FreeSpace` | `DriveType=3` selects fixed disks; size and free space are in bytes. |

The four classes were inspected on a Windows workstation. No machine-specific values or output files are committed.

## Next step

Use the raw objects to build one `[pscustomobject]` with computer name, logged-in user, Windows version, uptime, CPU, memory, and disk fields. Later milestones will add networking, pending reboot, Defender, event logs, remote computers, and tests.
