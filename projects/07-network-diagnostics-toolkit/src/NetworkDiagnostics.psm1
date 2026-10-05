#Requires -Version 7.2
Set-StrictMode -Version Latest

function Resolve-DiagnosticAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Target
    )

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($Target, [ref] $parsedAddress)) {
        return [pscustomobject]@{
            Status    = 'NotNeeded'
            Addresses = @($parsedAddress.ToString())
            Selected  = $parsedAddress.ToString()
            Error     = $null
        }
    }

    try {
        $answers = @(Resolve-DnsName -Name $Target -DnsOnly -ErrorAction Stop)
        $addresses = @($answers | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
        if ($addresses.Count -eq 0) {
            throw 'The lookup returned no IP addresses.'
        }

        # Choose one address deterministically. The caller can test another address explicitly.
        $ipv4 = @($addresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
        $selected = if ($ipv4.Count -gt 0) { $ipv4[0] } else { $addresses[0] }

        return [pscustomobject]@{
            Status    = 'Succeeded'
            Addresses = $addresses
            Selected  = $selected
            Error     = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Status    = 'Failed'
            Addresses = @()
            Selected  = $null
            Error     = $_.Exception.Message
        }
    }
}

function Test-DiagnosticIcmp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Address,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    try {
        $reply = Test-Connection -TargetName $Address -Count 1 -TimeoutSeconds $TimeoutSeconds -ErrorAction Stop
        if ($reply.Status -eq 'Success') {
            return [pscustomobject]@{ Status = 'Succeeded'; LatencyMs = [int] $reply.Latency; Error = $null }
        }

        return [pscustomobject]@{ Status = 'Failed'; LatencyMs = $null; Error = [string] $reply.Status }
    }
    catch {
        return [pscustomobject]@{ Status = 'Failed'; LatencyMs = $null; Error = $_.Exception.Message }
    }
}

function Test-DiagnosticTcp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutSeconds
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $attempt = $client.ConnectAsync($ip, $Port)
        if (-not $attempt.Wait($TimeoutSeconds * 1000)) {
            return [pscustomobject]@{ Status = 'TimedOut'; Error = "TCP connection exceeded $TimeoutSeconds second(s)." }
        }

        return [pscustomobject]@{ Status = 'Succeeded'; Error = $null }
    }
    catch {
        $cause = $_.Exception
        if ($cause -is [System.AggregateException] -and $cause.InnerException) {
            $cause = $cause.InnerException
        }
        return [pscustomobject]@{ Status = 'Failed'; Error = $cause.Message }
    }
    finally {
        $client.Dispose()
    }
}

function Get-DiagnosticLocalContext {
    [CmdletBinding()]
    param (
        [string] $Address
    )

    $context = [pscustomobject]@{
        Status         = 'NotRun'
        SourceAddress  = $null
        InterfaceAlias = $null
        InterfaceIndex = $null
        RoutePrefix    = $null
        NextHop        = $null
        DefaultGateway = $null
        DnsServers     = @()
        Error          = $null
    }

    if (-not $Address) {
        $context.Error = 'Name resolution did not provide an address for route selection.'
        return $context
    }

    try {
        $path = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
        $source = $path | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1
        $route = $path | Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
        if (-not $source -or -not $route) {
            throw 'Windows did not return both a source address and a route.'
        }

        $context.SourceAddress = [string] $source.IPAddress
        $context.InterfaceAlias = [string] $source.InterfaceAlias
        $context.InterfaceIndex = [int] $source.InterfaceIndex
        $context.RoutePrefix = [string] $route.DestinationPrefix
        $context.NextHop = [string] $route.NextHop
        $context.Status = 'Succeeded'
    }
    catch {
        $context.Status = 'Unavailable'
        $context.Error = $_.Exception.Message
        return $context
    }

    try {
        $configuration = Get-NetIPConfiguration -InterfaceIndex $context.InterfaceIndex -ErrorAction Stop |
            Select-Object -First 1
        if (-not $configuration) {
            throw 'Windows did not return configuration for the selected interface.'
        }

        $ip = [System.Net.IPAddress]::Parse($Address)
        $gateway = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $configuration.IPv6DefaultGateway
        }
        else {
            $configuration.IPv4DefaultGateway
        }
        if ($gateway) {
            $context.DefaultGateway = [string] (@($gateway)[0].NextHop)
        }
        if ($configuration.DNSServer) {
            $context.DnsServers = @($configuration.DNSServer.ServerAddresses)
        }
    }
    catch {
        $context.Status = 'Partial'
        $context.Error = $_.Exception.Message
    }

    return $context
}

function Invoke-NetworkDiagnostic {
    <#
    .SYNOPSIS
    Checks name resolution, ICMP, and a TCP port for one or more targets.
    .DESCRIPTION
    Returns one object per target. A failed name lookup skips ICMP and TCP checks.
    ICMP failure does not override the separate TCP result. Local route context is optional.
    .EXAMPLE
    Invoke-NetworkDiagnostic -Target localhost -TcpPort 443
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $Target,

        [ValidateRange(1, 65535)]
        [int] $TcpPort = 443,

        [ValidateRange(1, 30)]
        [int] $TimeoutSeconds = 2,

        [switch] $IncludeLocalContext
    )

    process {
        foreach ($item in $Target) {
            $resolution = Resolve-DiagnosticAddress -Target $item
            $icmp = [pscustomobject]@{ Status = 'NotRun'; LatencyMs = $null; Error = $null }
            $tcp = [pscustomobject]@{ Status = 'NotRun'; Error = $null }
            $localContext = $null

            if ($resolution.Status -ne 'Failed') {
                $icmp = Test-DiagnosticIcmp -Address $resolution.Selected -TimeoutSeconds $TimeoutSeconds
                $tcp = Test-DiagnosticTcp -Address $resolution.Selected -Port $TcpPort -TimeoutSeconds $TimeoutSeconds
            }
            if ($IncludeLocalContext) {
                $localContext = Get-DiagnosticLocalContext -Address $resolution.Selected
            }

            $result = [pscustomobject]@{
                TimestampUtc         = (Get-Date).ToUniversalTime()
                Target               = $item
                NameResolutionStatus = $resolution.Status
                ResolvedAddresses    = @($resolution.Addresses)
                TestedAddress        = $resolution.Selected
                NameResolutionError  = $resolution.Error
                IcmpStatus           = $icmp.Status
                IcmpLatencyMs        = $icmp.LatencyMs
                IcmpError            = $icmp.Error
                TcpPort              = $TcpPort
                TcpStatus            = $tcp.Status
                TcpError             = $tcp.Error
                LocalContext         = $localContext
            }
            $result.PSObject.TypeNames.Insert(0, 'NetworkDiagnostic.Result')
            $result
        }
    }
}

Export-ModuleMember -Function Invoke-NetworkDiagnostic
