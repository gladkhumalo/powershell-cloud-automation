# 02 — Workstation Health Check

**Status:** v0.1 — local workstation report

This script reads four Windows CIM classes and returns one PowerShell object describing the local workstation. It does not write a file or change system settings.

## Run

Requirements: Windows and PowerShell 7.2 or newer. From the repository root:

```powershell
$health = ./projects/02-workstation-health-check/src/Get-WorkstationHealth.ps1
$health | Format-List
$health.FixedDisks | Format-Table
```

The report includes computer name, logged-on user, Windows name and version, last boot time, uptime in days, processor name, average CPU load, total and free memory in GiB, memory used percentage, and fixed-disk details. Each disk has its drive letter, size and free space in GiB, and free percentage. Property names use `GB` for readability; calculations divide by powers of 1024.

CPU load is a recent CIM sample, not continuous monitoring. Windows can return no sample; `CpuLoadPercent` is then `$null`. Percentages are also `$null` if their total size is zero. `LoggedOnUser` can be empty when Windows does not report a console user.

To inspect the source data, run a query on its own:

```powershell
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$os | Get-Member -MemberType Property
$os | Select-Object Caption, Version, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory
```

Repeat that pattern with `Win32_ComputerSystem`, `Win32_Processor`, and `Win32_LogicalDisk -Filter 'DriveType=3'`.

## Properties identified

| CIM class | Properties used | Detail to remember |
| --- | --- | --- |
| [`Win32_OperatingSystem`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) | `Caption`, `Version`, `LastBootUpTime`, `TotalVisibleMemorySize`, `FreePhysicalMemory` | The two memory values are in kilobytes. |
| [`Win32_ComputerSystem`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem) | `Name`, `UserName`, `TotalPhysicalMemory` | Total physical memory is in bytes; `UserName` refers to the console user in a terminal-services scenario. |
| [`Win32_Processor`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor) | `Name`, `LoadPercentage` | Load percentage is a recent sample for each processor. |
| [`Win32_LogicalDisk`](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk) | `DeviceID`, `DriveType`, `Size`, `FreeSpace` | `DriveType=3` selects fixed disks; size and free space are in bytes. |

The script was run on a Windows workstation and returned one report object with fixed-disk data. No machine-specific values or output files are committed.

## Later milestones

Add networking, pending reboot, Defender, event logs, remote computers, and automated tests.

