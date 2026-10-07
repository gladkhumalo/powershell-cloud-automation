function Get-PropertyValue {
    # Reads a nested property without tripping strict mode. Each name is one level, so
    # names that contain dots (such as '@odata.type') are safe.
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)] [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory, Position = 1)] [string[]] $Name
    )

    $current = $InputObject
    foreach ($segment in $Name) {
        if ($null -eq $current) {
            return $null
        }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) {
                return $null
            }
            $current = $current[$segment]
        }
        else {
            $property = $current.PSObject.Properties[$segment]
            if (-not $property) {
                return $null
            }
            $current = $property.Value
        }
    }
    return $current
}

function Test-PropertyPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $InputObject) {
        return $false
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    return [bool] $InputObject.PSObject.Properties[$Name]
}

function Format-Invariant {
    param (
        [Parameter(Mandatory)] [string] $Format,
        [object[]] $Arguments
    )

    [string]::Format([cultureinfo]::InvariantCulture, $Format, $Arguments)
}

function Get-SnapshotSource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [string] $Name
    )

    $source = Get-PropertyValue $Snapshot 'Sources', $Name
    if ($null -eq $source) {
        return [pscustomobject]@{
            Name   = $Name
            Status = 'Missing'
            Error  = 'The snapshot does not contain this source.'
            Data   = $null
        }
    }

    [pscustomobject]@{
        Name   = $Name
        Status = [string] (Get-PropertyValue $source 'Status')
        Error  = [string] (Get-PropertyValue $source 'Error')
        Data   = (Get-PropertyValue $source 'Data')
    }
}

function Test-SourceCollected {
    param ([Parameter(Mandatory)] [object] $Source)

    $Source.Status -eq 'Collected'
}

function Get-SourceItem {
    param ([Parameter(Mandatory)] [object] $Source)

    @($Source.Data) | Where-Object { $null -ne $_ }
}

function Format-SourceError {
    param ([Parameter(Mandatory)] [object[]] $Source)

    ($Source | ForEach-Object { "Source '$($_.Name)' was not collected: $($_.Error)" }) -join ' '
}

function Get-ObjectTypeName {
    param ([AllowNull()] [object] $DirectoryObject)

    [string] (Get-PropertyValue $DirectoryObject '@odata.type') -replace '^#microsoft\.graph\.', ''
}

function Format-DirectoryObject {
    param ([Parameter(Mandatory)] [object] $DirectoryObject)

    $type = Get-ObjectTypeName $DirectoryObject
    $name = Get-PropertyValue $DirectoryObject 'userPrincipalName'
    if (-not $name) { $name = Get-PropertyValue $DirectoryObject 'displayName' }
    if (-not $name) { $name = Get-PropertyValue $DirectoryObject 'id' }

    if ($type -in @('', 'user')) {
        return [string] $name
    }
    return "${type}: $name"
}

function Format-UserRecord {
    param ([Parameter(Mandatory)] [object] $Record)

    $name = Get-PropertyValue $Record 'userPrincipalName'
    if (-not $name) { $name = Get-PropertyValue $Record 'id' }
    [string] $name
}

function Get-DirectoryIdentityMap {
    # Builds an id-to-UPN lookup from every source that carries user identities.
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $byId = @{}
    $add = {
        param ($Id, $Upn)
        if ($Id -and $Upn -and -not $byId.ContainsKey([string] $Id)) {
            $byId[[string] $Id] = [string] $Upn
        }
    }

    foreach ($name in @('GlobalAdministrators', 'UserRegistrationDetails')) {
        foreach ($item in @(Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name $name))) {
            & $add (Get-PropertyValue $item 'id') (Get-PropertyValue $item 'userPrincipalName')
        }
    }
    foreach ($name in @('GlobalAdminAssignments', 'GlobalAdminEligibility')) {
        foreach ($item in @(Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name $name))) {
            & $add (Get-PropertyValue $item 'principalId') (Get-PropertyValue $item 'principal', 'userPrincipalName')
        }
    }
    foreach ($group in @(Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminGroupMembers'))) {
        foreach ($member in @(Get-PropertyValue $group 'members' | Where-Object { $_ })) {
            & $add (Get-PropertyValue $member 'id') (Get-PropertyValue $member 'userPrincipalName')
        }
    }

    $byUpn = @{}
    foreach ($key in $byId.Keys) {
        $byUpn[$byId[$key]] = $key
    }
    [pscustomobject]@{ ById = $byId; ByUpn = $byUpn }
}

function Resolve-PrincipalLabel {
    param (
        [AllowNull()] [string] $Id,
        [AllowNull()] [string] $Upn,
        [Parameter(Mandatory)] [object] $IdentityMap,
        [AllowNull()] [string] $DisplayName
    )

    if ($Upn) { return $Upn }
    if ($Id -and $IdentityMap.ById.ContainsKey($Id)) { return $IdentityMap.ById[$Id] }
    if ($DisplayName) { return $DisplayName }
    return $Id
}

function New-SecurityFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warn', 'Fail', 'NotAssessed')] [string] $Status,
        [Parameter(Mandatory)] [string] $Observed,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $AffectedObjects
    )

    $definition = $script:CheckCatalog[$CheckId]
    $affected = @($AffectedObjects | Where-Object { $_ } | Select-Object -Unique)

    $finding = [pscustomobject]@{
        CheckId          = $CheckId
        Category         = $definition.Category
        Title            = $definition.Title
        Severity         = $definition.Severity
        Status           = $Status
        OriginalStatus   = $Status
        Observed         = $Observed
        Recommendation   = $definition.Recommendation
        AffectedCount    = $affected.Count
        AffectedObjects  = [string[]] $affected
        AcceptanceNote   = $null
        BaselineControls = [string[]] @($definition.Baseline)
        Reference        = $definition.Reference
    }
    $finding.PSObject.TypeNames.Insert(0, 'M365Security.Finding')
    $finding
}

function New-NotAssessedFinding {
    param (
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [object[]] $Source
    )

    New-SecurityFinding -CheckId $CheckId -Status NotAssessed -Observed (Format-SourceError -Source $Source)
}

function Assert-SnapshotSchema {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $version = Get-PropertyValue $Snapshot 'SchemaVersion'
    if ($version -ne $script:SnapshotSchemaVersion) {
        throw "Unsupported snapshot schema version '$version'. This tool reads version $($script:SnapshotSchemaVersion)."
    }
    if ($null -eq (Get-PropertyValue $Snapshot 'Sources')) {
        throw 'The snapshot has no Sources section.'
    }
}

function Get-SnapshotTimestamp {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $value = Get-PropertyValue $Snapshot 'CollectedAtUtc'
    if ($value -is [datetime]) {
        if ($value.Kind -eq [System.DateTimeKind]::Unspecified) {
            return [datetime]::SpecifyKind($value, [System.DateTimeKind]::Utc)
        }
        return $value.ToUniversalTime()
    }
    if ($value) {
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        return [datetime]::Parse([string] $value, [cultureinfo]::InvariantCulture, $styles)
    }
    return (Get-Date).ToUniversalTime()
}

function Format-SnapshotDate {
    param ([Parameter(Mandatory)] [object] $Snapshot, [string] $Format = 'yyyy-MM-dd HH:mm')

    (Get-SnapshotTimestamp -Snapshot $Snapshot).ToString($Format, [cultureinfo]::InvariantCulture)
}

function Get-FindingSummary {
    param ([AllowEmptyCollection()] [object[]] $Finding)

    $summary = [ordered]@{ Fail = 0; Warn = 0; NotAssessed = 0; Accepted = 0; Pass = 0 }
    foreach ($item in @($Finding)) {
        $summary[$item.Status]++
    }
    [pscustomobject] $summary
}

function ConvertTo-HtmlText {
    param ([AllowNull()] [object] $Value)

    [System.Net.WebUtility]::HtmlEncode([string] $Value)
}
