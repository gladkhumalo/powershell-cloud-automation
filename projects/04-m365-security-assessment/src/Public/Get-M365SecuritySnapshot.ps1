function Get-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Collects the read-only tenant configuration that the security checks evaluate.
    .DESCRIPTION
    Requires an existing Microsoft Graph connection (Connect-MgGraph). Each data source is
    collected independently: a permission or licensing error on one source is recorded in the
    snapshot and the affected checks report NotAssessed instead of stopping the assessment.
    .EXAMPLE
    Connect-MgGraph -Scopes Policy.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All, GroupMember.Read.All
    $snapshot = Get-M365SecuritySnapshot
    #>
    [CmdletBinding()]
    param ()

    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with the scopes listed in the project README first.'
    }

    $sources = [ordered]@{}
    $sources.SecurityDefaults = Invoke-SnapshotCollector -Name 'security defaults' -Collector {
        Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -OutputType PSObject -ErrorAction Stop
    }
    $sources.ConditionalAccessPolicies = Invoke-SnapshotCollector -Name 'Conditional Access policies' -Collector {
        Invoke-GraphCollection -Uri 'v1.0/identity/conditionalAccess/policies'
    }
    $sources.AuthorizationPolicy = Invoke-SnapshotCollector -Name 'authorization policy' -Collector {
        $response = Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/authorizationPolicy' -OutputType PSObject -ErrorAction Stop
        # Older responses wrap the singleton in a collection.
        $wrapped = Get-PropertyValue $response 'value'
        if ($null -ne $wrapped) { @($wrapped)[0] } else { $response }
    }
    $sources.AuthenticationMethodsPolicy = Invoke-SnapshotCollector -Name 'authentication methods policy' -Collector {
        Invoke-MgGraphRequest -Method GET -Uri 'v1.0/policies/authenticationMethodsPolicy' -OutputType PSObject -ErrorAction Stop
    }
    $sources.GlobalAdministrators = Invoke-SnapshotCollector -Name 'Global Administrator members' -Collector {
        Invoke-GraphCollection -Uri "v1.0/directoryRoles(roleTemplateId='$($script:GlobalAdministratorRoleTemplateId)')/members?`$select=id,displayName,userPrincipalName"
    }
    $sources.GlobalAdminAssignments = Invoke-SnapshotCollector -Name 'Global Administrator active assignments (PIM)' -Collector {
        Invoke-RoleScheduleCollection -Resource roleAssignmentScheduleInstances
    }
    $sources.GlobalAdminEligibility = Invoke-SnapshotCollector -Name 'Global Administrator eligible assignments (PIM)' -Collector {
        Invoke-RoleScheduleCollection -Resource roleEligibilityScheduleInstances
    }

    $groups = Get-GlobalAdminGroupId -Sources $sources
    $sources.GlobalAdminGroupMembers = Invoke-SnapshotCollector -Name 'Global Administrator group members' -Collector {
        , @(foreach ($groupId in $groups.Keys) {
                [pscustomobject]@{
                    id          = $groupId
                    displayName = $groups[$groupId]
                    members     = (Invoke-GraphCollection -Uri "v1.0/groups/$groupId/transitiveMembers?`$select=id,displayName,userPrincipalName")
                }
            })
    }
    $sources.UserRegistrationDetails = Invoke-SnapshotCollector -Name 'user registration details' -Collector {
        Invoke-GraphCollection -Uri 'v1.0/reports/authenticationMethods/userRegistrationDetails'
    }

    [pscustomobject]@{
        SchemaVersion  = $script:SnapshotSchemaVersion
        Tool           = 'M365SecurityAssessment'
        ToolVersion    = $script:ToolVersion
        TenantId       = [string] $context.TenantId
        CollectedBy    = [string] $context.Account
        CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
        Sources        = [pscustomobject] $sources
    }
}
