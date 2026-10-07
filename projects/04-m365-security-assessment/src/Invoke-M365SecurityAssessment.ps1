#Requires -Version 7.2
<#
.SYNOPSIS
Runs a read-only Microsoft 365 security assessment and writes CSV, JSON, and HTML reports.
.DESCRIPTION
Live mode signs in to Microsoft Graph with read-only delegated scopes, collects a configuration
snapshot, evaluates it, and disconnects. Offline mode evaluates a saved snapshot without Graph.
.EXAMPLE
./Invoke-M365SecurityAssessment.ps1 -SaveSnapshot
.EXAMPLE
./Invoke-M365SecurityAssessment.ps1 -SnapshotPath ../examples/sample-tenant-snapshot.json
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param (
    [Parameter(ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [Parameter(ParameterSetName = 'Live')]
    [switch] $SaveSnapshot,

    [Parameter(Mandatory, ParameterSetName = 'Offline')]
    [ValidateNotNullOrEmpty()]
    [string] $SnapshotPath,

    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '../output'),

    [ValidateSet('Csv', 'Html', 'Json')]
    [string[]] $Format = @('Csv', 'Html', 'Json'),

    [ValidateRange(0, 100)] [int] $MinimumGlobalAdmins = 2,
    [ValidateRange(1, 100)] [int] $MaximumGlobalAdmins = 4,
    [ValidateRange(0, 100)] [double] $MfaRegistrationTargetPercent = 95,
    [ValidateRange(0, 100)] [double] $MfaRegistrationMinimumPercent = 80,

    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'
$requiredScopes = @('Policy.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All')
$connected = $false

Import-Module (Join-Path $PSScriptRoot 'M365SecurityAssessment.psd1') -Force

try {
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        Write-Host "Loading snapshot from $SnapshotPath..."
        $snapshot = Import-M365SecuritySnapshot -Path $SnapshotPath
    }
    else {
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
            throw "Required module 'Microsoft.Graph.Authentication' is not installed. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
        }

        $connectParameters = @{
            Scopes        = $requiredScopes
            UseDeviceCode = $true
            ContextScope  = 'Process'
            NoWelcome     = $true
            ErrorAction   = 'Stop'
        }
        if ($TenantId) {
            $connectParameters.TenantId = $TenantId
        }

        Write-Host "Connecting to Microsoft Graph with read-only scopes: $($requiredScopes -join ', ')..."
        Connect-MgGraph @connectParameters
        $connected = $true

        $granted = @((Get-MgContext).Scopes)
        $missing = @($requiredScopes | Where-Object { $_ -notin $granted })
        if ($missing.Count -gt 0) {
            Write-Warning "The session was not granted: $($missing -join ', '). Checks that need them will report NotAssessed."
        }

        Write-Host 'Collecting tenant configuration...'
        $snapshot = Get-M365SecuritySnapshot
    }

    $findingParameters = @{
        MinimumGlobalAdmins           = $MinimumGlobalAdmins
        MaximumGlobalAdmins           = $MaximumGlobalAdmins
        MfaRegistrationTargetPercent  = $MfaRegistrationTargetPercent
        MfaRegistrationMinimumPercent = $MfaRegistrationMinimumPercent
    }
    $findings = @($snapshot | Get-M365SecurityFinding @findingParameters)
    $files = @(Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -OutputDirectory $OutputDirectory -Format $Format)

    if ($SaveSnapshot) {
        $snapshotFile = Join-Path $OutputDirectory ([IO.Path]::GetFileNameWithoutExtension($files[0].Name) -replace '^M365-Security-Assessment', 'M365-Security-Snapshot')
        $files += Export-M365SecuritySnapshot -Snapshot $snapshot -Path "$snapshotFile.json"
    }

    $counts = $findings | Group-Object Status -AsHashTable -AsString
    $count = { param ($status) if ($counts -and $counts.ContainsKey($status)) { $counts[$status].Count } else { 0 } }
    Write-Host ''
    Write-Host "Tenant $($snapshot.TenantId): Fail $(& $count 'Fail') | Warn $(& $count 'Warn') | Not assessed $(& $count 'NotAssessed') | Pass $(& $count 'Pass')"
    $findings | Format-Table Status, Severity, CheckId, Title -AutoSize | Out-Host
    Write-Host 'Reports (confidential, contain tenant data):'
    $files | ForEach-Object { Write-Host "  $($_.FullName)" }

    if ($PassThru) {
        $findings
    }
}
catch {
    throw "The M365 security assessment failed: $($_.Exception.Message)"
}
finally {
    if ($connected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
