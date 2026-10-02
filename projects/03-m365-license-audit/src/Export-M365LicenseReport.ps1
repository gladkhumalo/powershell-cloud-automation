function Export-M365LicenseReport {
    [CmdletBinding()]
    param (
        [AllowEmptyCollection()]
        [object[]] $Skus,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath
    )

    $reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $reportDirectory = Split-Path -Parent $reportPath

    $report = @($Skus | Sort-Object SkuPartNumber | ForEach-Object {
        $enabled = [long] $_.PrepaidUnits.Enabled
        $consumed = [long] $_.ConsumedUnits

        [pscustomobject]@{
            SkuPartNumber = $_.SkuPartNumber
            SkuId = $_.SkuId
            CapabilityStatus = $_.CapabilityStatus
            EnabledUnits = $enabled
            ConsumedUnits = $consumed
            AvailableUnits = $enabled - $consumed
        }
    })

    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $reportDirectory -Force
    }

    if ($report.Count -eq 0) {
        'SkuPartNumber,SkuId,CapabilityStatus,EnabledUnits,ConsumedUnits,AvailableUnits' |
            Set-Content -LiteralPath $reportPath -Encoding utf8 -ErrorAction Stop
    }
    else {
        $report | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop
    }

    return $report.Count
}
