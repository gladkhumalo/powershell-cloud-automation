#Requires -Version 7.2
[CmdletBinding()]
param (
    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = (Join-Path $PSScriptRoot '../output/M365-License-Audit.csv')
)

$ErrorActionPreference = 'Stop'
$connected = $false
. (Join-Path $PSScriptRoot 'Export-M365LicenseReport.ps1')

try {
    foreach ($moduleName in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement')) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Required module '$moduleName' is not installed. Install it with: Install-Module $moduleName -Scope CurrentUser"
        }
    }

    Write-Host 'Connecting to Microsoft Graph with LicenseAssignment.Read.All...'
    Connect-MgGraph -Scopes 'LicenseAssignment.Read.All' -UseDeviceCode -ContextScope Process -NoWelcome -ErrorAction Stop
    $connected = $true

    Write-Host 'Retrieving subscribed license SKUs...'
    $skus = @(Get-MgSubscribedSku -All -Property @(
        'skuId'
        'skuPartNumber'
        'capabilityStatus'
        'prepaidUnits'
        'consumedUnits'
    ) -ErrorAction Stop)

    $reportCount = Export-M365LicenseReport -Skus $skus -OutputPath $OutputPath
    Write-Host "Exported $reportCount license SKUs to $OutputPath"
}
catch {
    throw "The M365 license audit failed: $($_.Exception.Message)"
}
finally {
    if ($connected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
