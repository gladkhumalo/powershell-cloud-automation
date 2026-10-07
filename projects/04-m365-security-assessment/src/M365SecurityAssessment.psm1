#Requires -Version 7.2
Set-StrictMode -Version Latest

$script:ToolVersion = '0.2.0'
$script:SnapshotSchemaVersion = 1
$script:ConfigurationSchemaVersion = 1
$script:GlobalAdministratorRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

# Private files define helpers and the check catalog; public files define the exported commands.
foreach ($folder in @('Private', 'Public')) {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @(
    'Get-M365SecuritySnapshot'
    'Export-M365SecuritySnapshot'
    'Import-M365SecuritySnapshot'
    'Import-M365SecurityConfiguration'
    'Get-M365SecurityFinding'
    'Compare-M365SecuritySnapshot'
    'Export-M365SecurityReport'
)
