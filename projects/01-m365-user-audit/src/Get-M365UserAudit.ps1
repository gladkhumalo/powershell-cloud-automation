#Requires -Version 7.2
[CmdletBinding()]
param (
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = (Join-Path $PSScriptRoot '../output/M365-User-Audit.csv')
)

$ErrorActionPreference = 'Stop'
$connected = $false

try {
    foreach ($moduleName in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Required module '$moduleName' is not installed. Install it with: Install-Module $moduleName -Scope CurrentUser"
        }
    }

    $reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $reportDirectory = Split-Path -Parent $reportPath
    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $reportDirectory -Force
    }

    Write-Host 'Connecting to Microsoft Graph with User.Read.All...'
    Connect-MgGraph -Scopes 'User.Read.All' -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop
    $connected = $true

    Write-Host 'Retrieving Microsoft 365 users...'
    $users = @(Get-MgUser -All -Property @(
        'displayName'
        'userPrincipalName'
        'accountEnabled'
        'userType'
        'department'
        'jobTitle'
    ) -ErrorAction Stop)

    $report = @($users | Select-Object DisplayName, UserPrincipalName, AccountEnabled, UserType, Department, JobTitle)
    $report | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop

    Write-Host "Exported $($report.Count) users to $reportPath"
}
catch {
    throw "The M365 user audit failed: $($_.Exception.Message)"
}
finally {
    if ($connected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
