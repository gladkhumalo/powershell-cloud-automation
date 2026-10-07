function Invoke-SnapshotCollector {
    param (
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Collector
    )

    Write-Verbose "Collecting $Name..."
    try {
        $data = & $Collector
        [pscustomobject]@{ Status = 'Collected'; Error = $null; Data = $data }
    }
    catch {
        Write-Warning "Could not collect ${Name}: $($_.Exception.Message)"
        [pscustomobject]@{ Status = 'Failed'; Error = $_.Exception.Message; Data = $null }
    }
}

function Invoke-GraphCollection {
    # Follows @odata.nextLink until every page is read.
    param ([Parameter(Mandatory)] [string] $Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        foreach ($item in @(Get-PropertyValue $response 'value')) {
            if ($null -ne $item) {
                $items.Add($item)
            }
        }
        $next = Get-PropertyValue $response '@odata.nextLink'
    }
    , $items.ToArray()
}

function Invoke-RoleScheduleCollection {
    # Reads PIM schedule instances for Global Administrator. Expanding the principal gives names and
    # object types; if a tenant rejects the expansion, the plain instances are still useful.
    param ([Parameter(Mandatory)] [ValidateSet('roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances')] [string] $Resource)

    $filter = "`$filter=roleDefinitionId%20eq%20'$($script:GlobalAdministratorRoleTemplateId)'"
    $uri = "v1.0/roleManagement/directory/${Resource}?$filter"
    try {
        Invoke-GraphCollection -Uri "$uri&`$expand=principal"
    }
    catch {
        Write-Verbose "Retrying $Resource without principal expansion: $($_.Exception.Message)"
        Invoke-GraphCollection -Uri $uri
    }
}

function Get-CollectedItem {
    param ([Parameter(Mandatory)] [object] $Source)

    if ($Source.Status -eq 'Collected') {
        @($Source.Data) | Where-Object { $null -ne $_ }
    }
}

function Get-GlobalAdminGroupId {
    # Finds groups that hold Global Administrator directly or through PIM so their members can be expanded.
    param ([Parameter(Mandatory)] [System.Collections.IDictionary] $Sources)

    $groups = [ordered]@{}
    foreach ($member in @(Get-CollectedItem -Source $Sources.GlobalAdministrators)) {
        if ((Get-ObjectTypeName $member) -eq 'group') {
            $groups[[string] (Get-PropertyValue $member 'id')] = [string] (Get-PropertyValue $member 'displayName')
        }
    }
    foreach ($name in @('GlobalAdminAssignments', 'GlobalAdminEligibility')) {
        foreach ($instance in @(Get-CollectedItem -Source $Sources[$name])) {
            $principal = Get-PropertyValue $instance 'principal'
            if ((Get-ObjectTypeName $principal) -eq 'group') {
                $groups[[string] (Get-PropertyValue $instance 'principalId')] = [string] (Get-PropertyValue $principal 'displayName')
            }
        }
    }
    $groups
}
