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
        $message = Get-GraphErrorMessage -ErrorRecord $_
        Write-Warning "Could not collect ${Name}: $message"
        [pscustomobject]@{ Status = 'Failed'; Error = $message; Data = $null }
    }
}

function Get-GraphErrorMessage {
    # Graph puts the useful reason (for example a missing license) in the response body, not the status line.
    param ([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord] $ErrorRecord)

    $message = $ErrorRecord.Exception.Message
    $body = if ($ErrorRecord.ErrorDetails) { $ErrorRecord.ErrorDetails.Message } else { $null }
    if ($body) {
        try {
            $graphError = Get-PropertyValue ($body | ConvertFrom-Json -ErrorAction Stop) 'error'
            $code = Get-PropertyValue $graphError 'code'
            $detail = Get-PropertyValue $graphError 'message'
            if ($code -or $detail) {
                return "$message Graph error $($code): $detail".Trim()
            }
        }
        catch {
            Write-Verbose "Error body was not Graph JSON: $body"
        }
        if ($body -ne $message) {
            return "$message $body".Trim()
        }
    }
    $message
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
    # Reads PIM schedule instances for Global Administrator. The role is filtered locally because a
    # server-side $filter was rejected with 400 Bad Request in a live tenant; the full list is small.
    # Expanding the principal gives names and object types; if a tenant rejects the expansion, the
    # plain instances are still useful.
    param ([Parameter(Mandatory)] [ValidateSet('roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances')] [string] $Resource)

    $uri = "v1.0/roleManagement/directory/$Resource"
    try {
        $instances = Invoke-GraphCollection -Uri "${uri}?`$expand=principal"
    }
    catch {
        $expandError = Get-GraphErrorMessage -ErrorRecord $_
        Write-Verbose "Retrying $Resource without principal expansion: $expandError"
        try {
            $instances = Invoke-GraphCollection -Uri $uri
        }
        catch {
            throw "With principal expansion: $expandError Without: $(Get-GraphErrorMessage -ErrorRecord $_)"
        }
    }
    , @($instances | Where-Object { (Get-PropertyValue $_ 'roleDefinitionId') -eq $script:GlobalAdministratorRoleTemplateId })
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
