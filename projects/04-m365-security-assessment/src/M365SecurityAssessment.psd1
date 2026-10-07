@{
    RootModule           = 'M365SecurityAssessment.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f3c2b1e-8d4a-4c7e-9b5f-2a1d0e9c8b74'
    Author               = 'Glad Khumalo'
    Description          = 'Read-only Microsoft 365 and Entra ID security configuration assessment with offline evaluation and CSV, JSON, and HTML reports.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Get-M365SecuritySnapshot'
        'Export-M365SecuritySnapshot'
        'Import-M365SecuritySnapshot'
        'Get-M365SecurityFinding'
        'Export-M365SecurityReport'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Microsoft365', 'EntraID', 'Security', 'MicrosoftGraph', 'Assessment')
        }
    }
}
