#Requires -Version 7.2
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

begin {
    Import-Module (Join-Path $PSScriptRoot 'NetworkDiagnostics.psm1') -Force
}

process {
    $Target | Invoke-NetworkDiagnostic -TcpPort $TcpPort -TimeoutSeconds $TimeoutSeconds -IncludeLocalContext:$IncludeLocalContext
}
