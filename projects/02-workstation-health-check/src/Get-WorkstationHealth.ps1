# Project 02 discovery step: inspect the raw CIM objects before shaping a report.
# Run these queries individually in PowerShell while exploring their properties.

Get-CimInstance -ClassName Win32_OperatingSystem
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName Win32_Processor
Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3'
