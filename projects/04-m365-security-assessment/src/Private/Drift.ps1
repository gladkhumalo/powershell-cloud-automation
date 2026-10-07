$script:ChangeTypeRank = @{
    Regressed        = 0
    NewlyAffected    = 1
    Added            = 2
    Removed          = 3
    Modified         = 4
    Changed          = 5
    NoLongerAffected = 6
    Improved         = 7
}

function New-SecurityChange {
    param (
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Item,
        [Parameter(Mandatory)] [ValidateSet('Regressed', 'Improved', 'Changed', 'NewlyAffected', 'NoLongerAffected', 'Added', 'Removed', 'Modified')] [string] $ChangeType,
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After,
        [AllowNull()] [string] $Detail
    )

    $change = [pscustomobject]@{
        Category   = $Category
        Item       = $Item
        ChangeType = $ChangeType
        Before     = [string] $Before
        After      = [string] $After
        Detail     = $Detail
    }
    $change.PSObject.TypeNames.Insert(0, 'M365Security.Change')
    $change
}

function Get-StatusChangeType {
    param ([Parameter(Mandatory)] [string] $Before, [Parameter(Mandatory)] [string] $After)

    $quality = @{ Fail = 0; Warn = 1; Pass = 2 }
    if (-not $quality.ContainsKey($Before) -or -not $quality.ContainsKey($After)) {
        return 'Changed'
    }
    if ($quality[$After] -gt $quality[$Before]) { 'Improved' } else { 'Regressed' }
}

function Compare-FindingSet {
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Before,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $After
    )

    $beforeById = @{}
    $Before | ForEach-Object { $beforeById[$_.CheckId] = $_ }
    foreach ($current in $After) {
        $previous = $beforeById[$current.CheckId]
        if (-not $previous) {
            continue
        }
        $item = "$($current.CheckId) $($current.Title)"
        if ($previous.Status -ne $current.Status) {
            $type = Get-StatusChangeType -Before $previous.Status -After $current.Status
            New-SecurityChange -Category 'Finding' -Item $item -ChangeType $type -Before $previous.Status -After $current.Status -Detail $current.Observed
        }
        $added = @($current.AffectedObjects | Where-Object { $_ -notin @($previous.AffectedObjects) })
        $removed = @($previous.AffectedObjects | Where-Object { $_ -notin @($current.AffectedObjects) })
        if ($added.Count -gt 0) {
            New-SecurityChange -Category 'Finding' -Item $item -ChangeType NewlyAffected -Before $previous.AffectedCount -After $current.AffectedCount -Detail ($added -join ', ')
        }
        if ($removed.Count -gt 0) {
            New-SecurityChange -Category 'Finding' -Item $item -ChangeType NoLongerAffected -Before $previous.AffectedCount -After $current.AffectedCount -Detail ($removed -join ', ')
        }
    }
}

function ConvertTo-ComparableJson {
    param ([AllowNull()] [object] $Value)

    if ($null -eq $Value) {
        return ''
    }
    $Value | ConvertTo-Json -Depth 20 -Compress
}

function Compare-PolicySet {
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Before,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $After,
        [Parameter(Mandatory)] [object] $IdentityMap
    )

    $category = 'Conditional Access'
    $beforeById = [ordered]@{}
    $Before | ForEach-Object { $beforeById[[string] (Get-PropertyValue $_ 'id')] = $_ }
    $afterById = [ordered]@{}
    $After | ForEach-Object { $afterById[[string] (Get-PropertyValue $_ 'id')] = $_ }

    foreach ($id in $afterById.Keys) {
        $current = $afterById[$id]
        $name = [string] (Get-PropertyValue $current 'displayName')
        if (-not $beforeById.Contains($id)) {
            New-SecurityChange -Category $category -Item $name -ChangeType Added -After (Get-PropertyValue $current 'state') -Detail 'New policy.'
            continue
        }

        $previous = $beforeById[$id]
        $previousState = [string] (Get-PropertyValue $previous 'state')
        $currentState = [string] (Get-PropertyValue $current 'state')
        if ($previousState -ne $currentState) {
            New-SecurityChange -Category $category -Item $name -ChangeType Modified -Before $previousState -After $currentState -Detail 'Policy state changed.'
        }

        $details = [System.Collections.Generic.List[string]]::new()
        $previousName = [string] (Get-PropertyValue $previous 'displayName')
        if ($previousName -ne $name) {
            $details.Add("Renamed from '$previousName'.")
        }
        foreach ($condition in @('includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles')) {
            $old = @(Get-PolicyUserCondition -Policy $previous -Name $condition)
            $new = @(Get-PolicyUserCondition -Policy $current -Name $condition)
            $added = @($new | Where-Object { $_ -notin $old } | ForEach-Object { Resolve-PrincipalLabel -Id $_ -Upn $null -IdentityMap $IdentityMap })
            $removed = @($old | Where-Object { $_ -notin $new } | ForEach-Object { Resolve-PrincipalLabel -Id $_ -Upn $null -IdentityMap $IdentityMap })
            if ($added.Count -gt 0) { $details.Add("${condition}: added $($added -join ', ').") }
            if ($removed.Count -gt 0) { $details.Add("${condition}: removed $($removed -join ', ').") }
        }

        # Anything else in the definition (apps, platforms, locations, controls) is reported generically.
        $strip = {
            param ($Policy)
            $copy = (ConvertTo-ComparableJson $Policy) | ConvertFrom-Json -Depth 20
            foreach ($property in @('id', 'displayName', 'state', 'createdDateTime', 'modifiedDateTime', 'templateId')) {
                $copy.PSObject.Properties.Remove($property)
            }
            $users = Get-PropertyValue $copy 'conditions', 'users'
            if ($users) {
                foreach ($property in @('includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles')) {
                    $users.PSObject.Properties.Remove($property)
                }
            }
            ConvertTo-ComparableJson $copy
        }
        if ((& $strip $previous) -ne (& $strip $current)) {
            $details.Add('Other conditions or controls changed.')
        }
        if ($details.Count -gt 0) {
            New-SecurityChange -Category $category -Item $name -ChangeType Modified -Detail ($details -join ' ')
        }
    }

    foreach ($id in $beforeById.Keys) {
        if (-not $afterById.Contains($id)) {
            $previous = $beforeById[$id]
            New-SecurityChange -Category $category -Item ([string] (Get-PropertyValue $previous 'displayName')) -ChangeType Removed -Before (Get-PropertyValue $previous 'state') -Detail 'Policy deleted.'
        }
    }
}

function Compare-PrincipalSet {
    param (
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Detail,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Before,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $After
    )

    $old = @{}
    $Before | ForEach-Object { $old[$_.Id] = $_.Label }
    $new = @{}
    $After | ForEach-Object { $new[$_.Id] = $_.Label }
    foreach ($id in $new.Keys | Sort-Object { $new[$_] }) {
        if (-not $old.ContainsKey($id)) {
            New-SecurityChange -Category $Category -Item $new[$id] -ChangeType Added -Detail $Detail
        }
    }
    foreach ($id in $old.Keys | Sort-Object { $old[$_] }) {
        if (-not $new.ContainsKey($id)) {
            New-SecurityChange -Category $Category -Item $old[$id] -ChangeType Removed -Detail $Detail
        }
    }
}

function Get-ActiveGlobalAdminPrincipal {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdministrators') | ForEach-Object {
        [pscustomobject]@{ Id = [string] (Get-PropertyValue $_ 'id'); Label = Format-DirectoryObject $_ }
    }
}

function Get-EligibleGlobalAdminPrincipal {
    param ([Parameter(Mandatory)] [object] $Snapshot, [Parameter(Mandatory)] [object] $IdentityMap)

    Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminEligibility') | ForEach-Object {
        $principal = Get-PropertyValue $_ 'principal'
        $id = [string] (Get-PropertyValue $_ 'principalId')
        $label = if ($principal) { Format-DirectoryObject $principal } else { Resolve-PrincipalLabel -Id $id -Upn $null -IdentityMap $IdentityMap }
        [pscustomobject]@{ Id = $id; Label = $label }
    }
}

function Compare-SettingValue {
    param (
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Item,
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After
    )

    $old = (@($Before) | Where-Object { $null -ne $_ } | ForEach-Object { [string] $_ } | Sort-Object) -join '; '
    $new = (@($After) | Where-Object { $null -ne $_ } | ForEach-Object { [string] $_ } | Sort-Object) -join '; '
    if ($old -ne $new) {
        New-SecurityChange -Category $Category -Item $Item -ChangeType Modified -Before $old -After $new
    }
}

function Compare-ConfigurationSource {
    # Raw configuration differences, compared only where both snapshots collected the source.
    param (
        [Parameter(Mandatory)] [object] $Reference,
        [Parameter(Mandatory)] [object] $Difference
    )

    $sourceNames = @(@(Get-ObjectProperty (Get-PropertyValue $Reference 'Sources')).Name + @(Get-ObjectProperty (Get-PropertyValue $Difference 'Sources')).Name | Select-Object -Unique)
    $collected = @{}
    foreach ($name in $sourceNames) {
        $before = Get-SnapshotSource -Snapshot $Reference -Name $name
        $after = Get-SnapshotSource -Snapshot $Difference -Name $name
        $collected[$name] = (Test-SourceCollected $before) -and (Test-SourceCollected $after)
        if ($before.Status -ne $after.Status) {
            $detail = if (-not (Test-SourceCollected $after)) { $after.Error } else { $null }
            New-SecurityChange -Category 'Collection' -Item $name -ChangeType Changed -Before $before.Status -After $after.Status -Detail $detail
        }
    }

    $map = Get-DirectoryIdentityMap -Snapshot $Difference
    foreach ($id in (Get-DirectoryIdentityMap -Snapshot $Reference).ById.GetEnumerator()) {
        if (-not $map.ById.ContainsKey($id.Key)) { $map.ById[$id.Key] = $id.Value }
    }

    if ($collected['SecurityDefaults']) {
        Compare-SettingValue -Category 'Security defaults' -Item 'isEnabled' `
            -Before (Get-PropertyValue (Get-SnapshotSource $Reference 'SecurityDefaults').Data 'isEnabled') `
            -After (Get-PropertyValue (Get-SnapshotSource $Difference 'SecurityDefaults').Data 'isEnabled')
    }
    if ($collected['ConditionalAccessPolicies']) {
        Compare-PolicySet -IdentityMap $map `
            -Before @(Get-SourceItem -Source (Get-SnapshotSource $Reference 'ConditionalAccessPolicies')) `
            -After @(Get-SourceItem -Source (Get-SnapshotSource $Difference 'ConditionalAccessPolicies'))
    }
    if ($collected['GlobalAdministrators']) {
        Compare-PrincipalSet -Category 'Global Administrators' -Detail 'Active assignment' `
            -Before @(Get-ActiveGlobalAdminPrincipal -Snapshot $Reference) -After @(Get-ActiveGlobalAdminPrincipal -Snapshot $Difference)
    }
    if ($collected['GlobalAdminEligibility']) {
        Compare-PrincipalSet -Category 'Global Administrators' -Detail 'Eligible assignment (PIM)' `
            -Before @(Get-EligibleGlobalAdminPrincipal -Snapshot $Reference -IdentityMap $map) `
            -After @(Get-EligibleGlobalAdminPrincipal -Snapshot $Difference -IdentityMap $map)
    }
    if ($collected['AuthorizationPolicy']) {
        $old = (Get-SnapshotSource $Reference 'AuthorizationPolicy').Data
        $new = (Get-SnapshotSource $Difference 'AuthorizationPolicy').Data
        foreach ($setting in @(
                @('allowInvitesFrom'),
                @('guestUserRoleId'),
                @('defaultUserRolePermissions', 'allowedToCreateApps'),
                @('defaultUserRolePermissions', 'permissionGrantPoliciesAssigned')
            )) {
            Compare-SettingValue -Category 'Authorization policy' -Item ($setting -join '.') -Before (Get-PropertyValue $old $setting) -After (Get-PropertyValue $new $setting)
        }
    }
    if ($collected['AuthenticationMethodsPolicy']) {
        $old = (Get-SnapshotSource $Reference 'AuthenticationMethodsPolicy').Data
        $new = (Get-SnapshotSource $Difference 'AuthenticationMethodsPolicy').Data
        Compare-SettingValue -Category 'Authentication methods' -Item 'policyMigrationState' -Before (Get-PropertyValue $old 'policyMigrationState') -After (Get-PropertyValue $new 'policyMigrationState')
        $states = {
            param ($Policy)
            $result = @{}
            foreach ($method in @(Get-PropertyValue $Policy 'authenticationMethodConfigurations' | Where-Object { $_ })) {
                $result[[string] (Get-PropertyValue $method 'id')] = [string] (Get-PropertyValue $method 'state')
            }
            $result
        }
        $oldStates = & $states $old
        $newStates = & $states $new
        foreach ($method in @($oldStates.Keys + $newStates.Keys | Select-Object -Unique | Sort-Object)) {
            Compare-SettingValue -Category 'Authentication methods' -Item $method -Before $oldStates[$method] -After $newStates[$method]
        }
    }
}
