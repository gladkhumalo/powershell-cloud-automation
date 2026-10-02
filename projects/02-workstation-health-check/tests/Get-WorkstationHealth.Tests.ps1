$scriptPath = Join-Path $PSScriptRoot '../src/Get-WorkstationHealth.ps1'

Describe 'Get-WorkstationHealth' {
    Mock Get-CimInstance {
        switch ($ClassName) {
            'Win32_OperatingSystem' {
                [pscustomobject]@{
                    Caption = 'Windows Test'
                    Version = '10.0'
                    LastBootUpTime = (Get-Date).AddDays(-2)
                    TotalVisibleMemorySize = 8388608
                    FreePhysicalMemory = 4194304
                }
            }
            'Win32_ComputerSystem' {
                [pscustomobject]@{ Name = 'TEST-PC'; UserName = 'TEST\User' }
            }
            'Win32_Processor' {
                [pscustomobject]@{ Name = 'CPU A'; LoadPercentage = 20 }
                [pscustomobject]@{ Name = 'CPU B'; LoadPercentage = 40 }
            }
            'Win32_LogicalDisk' {
                [pscustomobject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 25GB }
            }
        }
    }

    It 'calculates memory, CPU, disk, and uptime from CIM data' {
        $report = & $scriptPath

        $report.ComputerName | Should Be 'TEST-PC'
        $report.CpuLoadPercent | Should Be 30
        $report.MemoryTotalGB | Should Be 8
        $report.MemoryFreeGB | Should Be 4
        $report.MemoryUsedPercent | Should Be 50
        $report.FixedDisks.Count | Should Be 1
        $report.FixedDisks[0].FreePercent | Should Be 25
        $report.UptimeDays | Should BeGreaterThan 1.9
    }

    Context 'when measurements are unavailable or totals are zero' {
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [pscustomobject]@{
                        Caption = 'Windows Test'
                        Version = '10.0'
                        LastBootUpTime = (Get-Date).AddDays(-1)
                        TotalVisibleMemorySize = 0
                        FreePhysicalMemory = 0
                    }
                }
                'Win32_ComputerSystem' {
                    [pscustomobject]@{ Name = 'TEST-PC'; UserName = $null }
                }
                'Win32_Processor' {
                    [pscustomobject]@{ Name = 'CPU A'; LoadPercentage = $null }
                }
                'Win32_LogicalDisk' {
                    [pscustomobject]@{ DeviceID = 'C:'; Size = 0; FreeSpace = 0 }
                }
            }
        }

        It 'leaves percentages without valid samples or denominators empty' {
            $report = & $scriptPath

            $report.CpuLoadPercent | Should BeNullOrEmpty
            $report.MemoryUsedPercent | Should BeNullOrEmpty
            $report.FixedDisks[0].FreePercent | Should BeNullOrEmpty
        }
    }
}
