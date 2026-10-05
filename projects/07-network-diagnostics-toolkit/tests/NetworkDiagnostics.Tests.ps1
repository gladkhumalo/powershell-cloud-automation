$modulePath = Join-Path $PSScriptRoot '../src/NetworkDiagnostics.psm1'
$scriptPath = Join-Path $PSScriptRoot '../src/Invoke-NetworkDiagnostic.ps1'
Import-Module $modulePath -Force

Describe 'Invoke-NetworkDiagnostic' {
    InModuleScope NetworkDiagnostics {
        It 'checks a literal IP without a name lookup and keeps ICMP and TCP results separate' {
            Mock Resolve-DnsName { throw 'A literal address should not be resolved' }
            Mock Test-Connection { throw 'ICMP blocked' }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Succeeded'; Error = $null } }

            $result = Invoke-NetworkDiagnostic -Target '10.10.10.10' -TcpPort 443

            $result.NameResolutionStatus | Should Be 'NotNeeded'
            $result.TestedAddress | Should Be '10.10.10.10'
            $result.IcmpStatus | Should Be 'Failed'
            $result.TcpStatus | Should Be 'Succeeded'
            $result.LocalContext | Should BeNullOrEmpty
            Assert-MockCalled Resolve-DnsName -Times 0 -Exactly
            Assert-MockCalled Test-DiagnosticTcp -Times 1 -Exactly
        }

        It 'selects an IPv4 answer and returns all resolved addresses' {
            Mock Resolve-DnsName {
                [pscustomobject]@{ IPAddress = 'fd00::10' }
                [pscustomobject]@{ IPAddress = '10.10.10.10' }
            }
            Mock Test-Connection { [pscustomobject]@{ Status = 'Success'; Latency = 7 } }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Failed'; Error = 'Connection refused' } }

            $result = Invoke-NetworkDiagnostic -Target 'lab.example' -TcpPort 8443

            $result.NameResolutionStatus | Should Be 'Succeeded'
            $result.ResolvedAddresses.Count | Should Be 2
            $result.TestedAddress | Should Be '10.10.10.10'
            $result.IcmpStatus | Should Be 'Succeeded'
            $result.IcmpLatencyMs | Should Be 7
            $result.TcpPort | Should Be 8443
            $result.TcpStatus | Should Be 'Failed'
        }

        It 'does not probe when name resolution returns no address' {
            Mock Resolve-DnsName { [pscustomobject]@{ Name = 'missing.example'; IPAddress = $null } }
            Mock Test-Connection { throw 'Should not ping' }
            Mock Test-DiagnosticTcp { throw 'Should not connect' }

            $result = Invoke-NetworkDiagnostic -Target 'missing.example'

            $result.NameResolutionStatus | Should Be 'Failed'
            $result.IcmpStatus | Should Be 'NotRun'
            $result.TcpStatus | Should Be 'NotRun'
        }

        It 'returns one report per pipeline target' {
            Mock Test-Connection { [pscustomobject]@{ Status = 'Success'; Latency = 1 } }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Succeeded'; Error = $null } }

            $reports = @('10.10.10.10', '10.10.10.11') | Invoke-NetworkDiagnostic -TcpPort 443

            $reports.Count | Should Be 2
            $reports[0].Target | Should Be '10.10.10.10'
            $reports[1].Target | Should Be '10.10.10.11'
        }

        It 'adds the selected source, route, gateway, and DNS servers when requested' {
            Mock Test-Connection { [pscustomobject]@{ Status = 'Success'; Latency = 1 } }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Succeeded'; Error = $null } }
            Mock Find-NetRoute {
                [pscustomobject]@{ IPAddress = '10.10.10.5'; InterfaceAlias = 'LabEthernet'; InterfaceIndex = 7 }
                [pscustomobject]@{ DestinationPrefix = '10.10.20.0/24'; NextHop = '10.10.10.1'; InterfaceIndex = 7 }
            }
            Mock Get-NetIPConfiguration {
                [pscustomobject]@{
                    IPv4DefaultGateway = [pscustomobject]@{ NextHop = '10.10.10.1' }
                    IPv6DefaultGateway = $null
                    DNSServer = [pscustomobject]@{ ServerAddresses = @('10.10.10.53', '10.10.10.54') }
                }
            }

            $result = Invoke-NetworkDiagnostic -Target '10.10.20.10' -IncludeLocalContext

            $result.LocalContext.Status | Should Be 'Succeeded'
            $result.LocalContext.SourceAddress | Should Be '10.10.10.5'
            $result.LocalContext.InterfaceAlias | Should Be 'LabEthernet'
            $result.LocalContext.InterfaceIndex | Should Be 7
            $result.LocalContext.RoutePrefix | Should Be '10.10.20.0/24'
            $result.LocalContext.NextHop | Should Be '10.10.10.1'
            $result.LocalContext.DefaultGateway | Should Be '10.10.10.1'
            $result.LocalContext.DnsServers.Count | Should Be 2
        }

        It 'keeps probe results when local route access is denied' {
            Mock Test-Connection { [pscustomobject]@{ Status = 'Success'; Latency = 1 } }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Succeeded'; Error = $null } }
            Mock Find-NetRoute { throw 'Access denied' }

            $result = Invoke-NetworkDiagnostic -Target '10.10.20.10' -IncludeLocalContext

            $result.IcmpStatus | Should Be 'Succeeded'
            $result.TcpStatus | Should Be 'Succeeded'
            $result.LocalContext.Status | Should Be 'Unavailable'
            $result.LocalContext.Error | Should Match 'Access denied'
        }

        It 'keeps selected route details when interface configuration is unavailable' {
            Mock Test-Connection { [pscustomobject]@{ Status = 'Success'; Latency = 1 } }
            Mock Test-DiagnosticTcp { [pscustomobject]@{ Status = 'Succeeded'; Error = $null } }
            Mock Find-NetRoute {
                [pscustomobject]@{ IPAddress = '10.10.10.5'; InterfaceAlias = 'LabEthernet'; InterfaceIndex = 7 }
                [pscustomobject]@{ DestinationPrefix = '10.10.20.0/24'; NextHop = '10.10.10.1'; InterfaceIndex = 7 }
            }
            Mock Get-NetIPConfiguration { throw 'Access denied' }

            $result = Invoke-NetworkDiagnostic -Target '10.10.20.10' -IncludeLocalContext

            $result.LocalContext.Status | Should Be 'Partial'
            $result.LocalContext.SourceAddress | Should Be '10.10.10.5'
            $result.LocalContext.RoutePrefix | Should Be '10.10.20.0/24'
            $result.LocalContext.DefaultGateway | Should BeNullOrEmpty
        }

        It 'skips route selection when a hostname cannot resolve' {
            Mock Resolve-DnsName { throw 'Name does not exist' }

            $result = Invoke-NetworkDiagnostic -Target 'missing.lab.invalid' -IncludeLocalContext

            $result.NameResolutionStatus | Should Be 'Failed'
            $result.LocalContext.Status | Should Be 'NotRun'
            $result.LocalContext.SourceAddress | Should BeNullOrEmpty
        }
    }

    It 'accepts a TCP connection to a local listener through the public script' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
            $result = & $scriptPath -Target '127.0.0.1' -TcpPort $port -TimeoutSeconds 2

            $result.NameResolutionStatus | Should Be 'NotNeeded'
            $result.TcpStatus | Should Be 'Succeeded'
        }
        finally {
            $listener.Stop()
        }
    }

    It 'rejects an invalid TCP port' {
        $errorCaught = $null
        try {
            & $scriptPath -Target '127.0.0.1' -TcpPort 0 -ErrorAction Stop | Out-Null
        }
        catch {
            $errorCaught = $_
        }

        $errorCaught | Should Not BeNullOrEmpty
        $errorCaught.Exception.GetType().Name | Should Be 'ParameterBindingValidationException'
    }
}
