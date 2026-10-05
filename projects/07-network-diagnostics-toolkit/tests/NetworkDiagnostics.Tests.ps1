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
