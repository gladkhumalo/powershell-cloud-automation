#Requires -Version 7.2
<#
.SYNOPSIS
Runs a read-only Microsoft 365 security assessment and writes CSV, JSON, and HTML reports.
.DESCRIPTION
Live mode signs in to Microsoft Graph with read-only delegated scopes, collects a configuration
snapshot, evaluates it, and disconnects. Offline mode evaluates a saved snapshot without Graph.
A configuration file adds emergency-access accounts, thresholds, and accepted risks. A previous
snapshot adds a "changes since" drift section.
.EXAMPLE
./Invoke-M365SecurityAssessment.ps1 -SaveSnapshot -ConfigurationPath ../../../config/contoso.json
.EXAMPLE
./Invoke-M365SecurityAssessment.ps1 -SnapshotPath ../examples/sample-tenant-snapshot.json `
    -CompareToSnapshotPath ../examples/sample-tenant-snapshot-previous.json `
    -ConfigurationPath ../../../config/m365-security-assessment.example.json
.EXAMPLE
./Invoke-M365SecurityAssessment.ps1 -SnapshotPath ./snapshot.json -FailOnSeverity High
# Exits with code 1 when any High-severity check fails, for scheduled runs and pipelines.
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
    [string] $ConfigurationPath,

    [ValidateNotNullOrEmpty()]
    [string] $CompareToSnapshotPath,

    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '../output'),

    [ValidateSet('Csv', 'Html', 'Json')]
    [string[]] $Format = @('Csv', 'Html', 'Json'),

    [ValidateRange(0, 100)] [int] $MinimumGlobalAdmins,
    [ValidateRange(1, 100)] [int] $MaximumGlobalAdmins,
    [ValidateRange(0, 100)] [double] $MfaRegistrationTargetPercent,
    [ValidateRange(0, 100)] [double] $MfaRegistrationMinimumPercent,

    [ValidateSet('High', 'Medium', 'Low')]
    [string] $FailOnSeverity,

    [switch] $PassThru
)

$ErrorActionPreference = 'Stop'
$requiredScopes = @('Policy.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All', 'GroupMember.Read.All')
$connected = $false
$exitCode = 0

Import-Module (Join-Path $PSScriptRoot 'M365SecurityAssessment.psd1') -Force

try {
    $configuration = $null
    if ($ConfigurationPath) {
        Write-Host "Loading configuration from $ConfigurationPath..."
        $configuration = Import-M365SecurityConfiguration -Path $ConfigurationPath
    }
    $reference = $null
    if ($CompareToSnapshotPath) {
        $reference = Import-M365SecuritySnapshot -Path $CompareToSnapshotPath
    }

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

    $findingParameters = @{ Configuration = $configuration }
    foreach ($name in @('MinimumGlobalAdmins', 'MaximumGlobalAdmins', 'MfaRegistrationTargetPercent', 'MfaRegistrationMinimumPercent')) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $findingParameters[$name] = $PSBoundParameters[$name]
        }
    }
    $findings = @($snapshot | Get-M365SecurityFinding @findingParameters)

    $reportParameters = @{ Finding = $findings; Snapshot = $snapshot; OutputDirectory = $OutputDirectory; Format = $Format }
    $drift = @()
    if ($reference) {
        $drift = @(Compare-M365SecuritySnapshot -ReferenceSnapshot $reference -DifferenceSnapshot $snapshot -Configuration $configuration)
        $reportParameters.Drift = $drift
        $reportParameters.ReferenceSnapshot = $reference
    }
    $files = @(Export-M365SecurityReport @reportParameters)

    if ($SaveSnapshot) {
        $stamp = (Get-Date $snapshot.CollectedAtUtc).ToUniversalTime().ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
        $files += Export-M365SecuritySnapshot -Snapshot $snapshot -Path (Join-Path $OutputDirectory "M365-Security-Snapshot-$stamp.json")
    }

    $counts = @{}
    $findings | Group-Object Status | ForEach-Object { $counts[$_.Name] = $_.Count }
    $count = { param ($status) if ($counts.ContainsKey($status)) { $counts[$status] } else { 0 } }
    Write-Host ''
    Write-Host "Tenant $($snapshot.TenantId): Fail $(& $count 'Fail') | Warn $(& $count 'Warn') | Not assessed $(& $count 'NotAssessed') | Accepted $(& $count 'Accepted') | Pass $(& $count 'Pass')"
    $findings | Format-Table Status, Severity, CheckId, Title -AutoSize | Out-Host

    if ($reference) {
        $regressions = @($drift | Where-Object { $_.ChangeType -in @('Regressed', 'NewlyAffected') })
        Write-Host "Changes since $((Get-Date $reference.CollectedAtUtc).ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)): $($drift.Count) total, $($regressions.Count) regression(s)."
        if ($regressions.Count -gt 0) {
            $regressions | Format-Table ChangeType, Item, Before, After -AutoSize | Out-Host
        }
    }

    Write-Host 'Reports (confidential, contain tenant data):'
    $files | ForEach-Object { Write-Host "  $($_.FullName)" }

    if ($FailOnSeverity) {
        $limit = @{ High = 0; Medium = 1; Low = 2 }[$FailOnSeverity]
        $blocking = @($findings | Where-Object { $_.Status -eq 'Fail' -and @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] -le $limit })
        if ($blocking.Count -gt 0) {
            Write-Warning "$($blocking.Count) failed check(s) at or above $FailOnSeverity severity: $($blocking.CheckId -join ', ')."
            $exitCode = 1
        }
    }

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

exit $exitCode
