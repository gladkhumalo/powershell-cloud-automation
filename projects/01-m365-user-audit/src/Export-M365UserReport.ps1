function Export-M365UserReport {
    [CmdletBinding()]
    param (
        [AllowEmptyCollection()]
        [object[]] $Users,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath
    )

    $reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $reportDirectory = Split-Path -Parent $reportPath

    $report = @($Users | ForEach-Object {
        [pscustomobject]@{
            DisplayName = $_.DisplayName
            UserPrincipalName = $_.UserPrincipalName
            AccountEnabled = $_.AccountEnabled
            UserType = $_.UserType
            Department = $_.Department
            JobTitle = $_.JobTitle
        }
    })

    if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $reportDirectory -Force
    }

    if ($report.Count -eq 0) {
        'DisplayName,UserPrincipalName,AccountEnabled,UserType,Department,JobTitle' |
            Set-Content -LiteralPath $reportPath -Encoding utf8 -ErrorAction Stop
    }
    else {
        $report | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding utf8 -ErrorAction Stop
    }

    return $report.Count
}
