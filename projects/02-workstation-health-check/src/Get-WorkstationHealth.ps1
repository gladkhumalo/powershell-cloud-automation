#Requires -Version 7.2
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$processors = @(Get-CimInstance -ClassName Win32_Processor)
$fixedDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')

$memoryTotalKB = [double] $os.TotalVisibleMemorySize
$memoryFreeKB = [double] $os.FreePhysicalMemory
$cpuSamples = @($processors | Where-Object { $null -ne $_.LoadPercentage })

$disks = @($fixedDisks | ForEach-Object {
    $sizeBytes = [double] $_.Size
    $freeBytes = [double] $_.FreeSpace

    [pscustomobject]@{
        Drive       = $_.DeviceID
        SizeGB      = [math]::Round($sizeBytes / 1GB, 2)
        FreeGB      = [math]::Round($freeBytes / 1GB, 2)
        FreePercent = if ($sizeBytes -gt 0) { [math]::Round(100 * $freeBytes / $sizeBytes, 1) } else { $null }
    }
})

[pscustomobject]@{
    ComputerName      = $computer.Name
    LoggedOnUser      = $computer.UserName
    OperatingSystem   = $os.Caption
    WindowsVersion    = $os.Version
    LastBootTime      = $os.LastBootUpTime
    UptimeDays        = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
    ProcessorName     = ($processors.Name -join '; ')
    CpuLoadPercent    = if ($cpuSamples.Count -gt 0) { [math]::Round(($cpuSamples | Measure-Object -Property LoadPercentage -Average).Average, 1) } else { $null }
    MemoryTotalGB     = [math]::Round($memoryTotalKB / 1MB, 2)
    MemoryFreeGB      = [math]::Round($memoryFreeKB / 1MB, 2)
    MemoryUsedPercent = if ($memoryTotalKB -gt 0) { [math]::Round(100 * ($memoryTotalKB - $memoryFreeKB) / $memoryTotalKB, 1) } else { $null }
    FixedDisks        = $disks
}

