function Get-ExpandedGroupMember {
    # Returns member labels for a group, or $null when the group's members were not collected.
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [object] $IdentityMap
    )

    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminGroupMembers'
    if (-not (Test-SourceCollected $source)) {
        return $null
    }
    $group = Get-SourceItem -Source $source | Where-Object { (Get-PropertyValue $_ 'id') -eq $GroupId } | Select-Object -First 1
    if (-not $group) {
        return $null
    }
    , @(Get-PropertyValue $group 'members' | Where-Object { $_ -and (Get-ObjectTypeName $_) -in @('', 'user') } | ForEach-Object {
            [pscustomobject]@{
                Id    = [string] (Get-PropertyValue $_ 'id')
                Label = Resolve-PrincipalLabel -Id (Get-PropertyValue $_ 'id') -Upn (Get-PropertyValue $_ 'userPrincipalName') -IdentityMap $IdentityMap
            }
        })
}

function Get-GlobalAdminPrincipal {
    # Resolves everyone who can hold Global Administrator: active, PIM-eligible, and through groups.
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [object] $IdentityMap
    )

    $users = [ordered]@{}
    $groups = [ordered]@{}
    $servicePrincipals = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()

    $addUser = {
        param ($Id, $Upn, $Path, $DisplayName)
        $label = Resolve-PrincipalLabel -Id $Id -Upn $Upn -IdentityMap $IdentityMap -DisplayName $DisplayName
        $key = if ($Id) { [string] $Id } else { [string] $label }
        if (-not $users.Contains($key)) {
            $users[$key] = [pscustomobject]@{
                Id    = $Id
                Label = $label
                Paths = [System.Collections.Generic.List[string]]::new()
            }
        }
        if (-not $users[$key].Paths.Contains($Path)) {
            $users[$key].Paths.Add($Path)
        }
    }

    foreach ($member in @(Get-SourceItem -Source (Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdministrators'))) {
        $type = Get-ObjectTypeName $member
        $id = [string] (Get-PropertyValue $member 'id')
        if ($type -in @('', 'user')) {
            & $addUser $id (Get-PropertyValue $member 'userPrincipalName') 'active' (Get-PropertyValue $member 'displayName')
        }
        elseif ($type -eq 'group') {
            $groups[$id] = [string] (Get-PropertyValue $member 'displayName')
        }
        else {
            $servicePrincipals.Add((Format-DirectoryObject $member))
        }
    }

    $eligibility = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminEligibility'
    if (Test-SourceCollected $eligibility) {
        foreach ($instance in @(Get-SourceItem -Source $eligibility)) {
            $principal = Get-PropertyValue $instance 'principal'
            $id = [string] (Get-PropertyValue $instance 'principalId')
            $type = Get-ObjectTypeName $principal
            if ($type -eq 'group') {
                $groups[$id] = [string] (Get-PropertyValue $principal 'displayName')
            }
            elseif ($type -in @('', 'user')) {
                & $addUser $id (Get-PropertyValue $principal 'userPrincipalName') 'eligible' (Get-PropertyValue $principal 'displayName')
            }
            else {
                $servicePrincipals.Add((Format-DirectoryObject $principal))
            }
        }
    }
    else {
        $notes.Add("Eligible (PIM) assignments are not included because source 'GlobalAdminEligibility' was not collected: $($eligibility.Error)")
    }

    $unexpanded = [System.Collections.Generic.List[string]]::new()
    foreach ($groupId in @($groups.Keys)) {
        $groupName = if ($groups[$groupId]) { $groups[$groupId] } else { $groupId }
        $members = Get-ExpandedGroupMember -Snapshot $Snapshot -GroupId $groupId -IdentityMap $IdentityMap
        if ($null -eq $members) {
            $unexpanded.Add($groupName)
            continue
        }
        foreach ($member in $members) {
            & $addUser $member.Id $member.Label "group: $groupName"
        }
    }

    [pscustomobject]@{
        Users             = @($users.Values)
        UnexpandedGroups  = @($unexpanded)
        ServicePrincipals = @($servicePrincipals)
        Notes             = @($notes)
    }
}

function Test-GlobalAdministratorCount {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [object] $Context
    )

    $checkId = 'PRIV-001'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdministrators'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $minimum = $Context.Thresholds.MinimumGlobalAdmins
    $maximum = $Context.Thresholds.MaximumGlobalAdmins
    $admins = Get-GlobalAdminPrincipal -Snapshot $Snapshot -IdentityMap $Context.IdentityMap
    $users = @($admins.Users)
    $activeCount = @($users | Where-Object { $_.Paths -contains 'active' }).Count
    $eligibleOnlyCount = @($users | Where-Object { $_.Paths -notcontains 'active' -and $_.Paths -contains 'eligible' }).Count
    $groupCount = @($users | Where-Object { @($_.Paths | Where-Object { $_ -like 'group: *' }).Count -gt 0 }).Count

    $status = if ($users.Count -gt $maximum) { 'Fail' } elseif ($users.Count -lt $minimum) { 'Warn' } else { 'Pass' }
    $observed = "$($users.Count) user(s) can hold Global Administrator: $activeCount with an active assignment, $eligibleOnlyCount eligible only through PIM, and $groupCount through role-assignable groups. The target range is $minimum to $maximum."
    $extra = [System.Collections.Generic.List[string]]::new()

    if ($admins.UnexpandedGroups.Count -gt 0) {
        $observed += " Members of $($admins.UnexpandedGroups.Count) group(s) could not be expanded, so more people may hold the role."
        $admins.UnexpandedGroups | ForEach-Object { $extra.Add("group: $_") }
        if ($status -eq 'Pass') { $status = 'Warn' }
    }
    if ($admins.ServicePrincipals.Count -gt 0) {
        $observed += " $($admins.ServicePrincipals.Count) application or service principal assignment(s) also hold the role."
        $admins.ServicePrincipals | ForEach-Object { $extra.Add($_) }
        if ($status -eq 'Pass') { $status = 'Warn' }
    }
    foreach ($note in $admins.Notes) {
        $observed += " $note"
    }

    $affected = if ($status -eq 'Pass') { @() } else { @($users | ForEach-Object Label | Sort-Object) + @($extra) }
    New-SecurityFinding -CheckId $checkId -Status $status -Observed $observed -AffectedObjects $affected
}

function Get-AdministratorRecord {
    param ([Parameter(Mandatory)] [object] $Source)

    Get-SourceItem -Source $Source | Where-Object { (Get-PropertyValue $_ 'isAdmin') -eq $true }
}

function Test-AdministratorMfaRegistration {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'PRIV-002'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'UserRegistrationDetails'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $admins = @(Get-AdministratorRecord -Source $source)
    if ($admins.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report did not identify any administrators, so administrator MFA registration could not be confirmed.'
    }

    $unregistered = @($admins | Where-Object { (Get-PropertyValue $_ 'isMfaRegistered') -ne $true })
    if ($unregistered.Count -gt 0) {
        $observed = "$($unregistered.Count) of $($admins.Count) administrator account(s) have not registered an MFA method."
        return New-SecurityFinding -CheckId $checkId -Status Fail -Observed $observed -AffectedObjects @($unregistered | ForEach-Object { Format-UserRecord $_ })
    }
    New-SecurityFinding -CheckId $checkId -Status Pass -Observed "All $($admins.Count) administrator account(s) are registered for MFA."
}

function Test-PhishingResistantMethod {
    param ([AllowNull()] [AllowEmptyCollection()] [string[]] $Method)

    foreach ($item in @($Method)) {
        if ($item -in @('fido2', 'windowsHelloForBusiness') -or $item -like 'passKey*') {
            return $true
        }
    }
    return $false
}

function Test-AdministratorPhishingResistantMethod {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'PRIV-003'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'UserRegistrationDetails'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $admins = @(Get-AdministratorRecord -Source $source)
    if ($admins.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report did not identify any administrators.'
    }

    $missing = @($admins | Where-Object { -not (Test-PhishingResistantMethod -Method @(Get-PropertyValue $_ 'methodsRegistered')) })
    if ($missing.Count -gt 0) {
        $observed = "$($missing.Count) of $($admins.Count) administrator account(s) have no FIDO2 key, passkey, or Windows Hello for Business method registered."
        return New-SecurityFinding -CheckId $checkId -Status Warn -Observed $observed -AffectedObjects @($missing | ForEach-Object { Format-UserRecord $_ })
    }
    New-SecurityFinding -CheckId $checkId -Status Pass -Observed "All $($admins.Count) administrator account(s) have a phishing-resistant method registered."
}

function Test-StandingGlobalAdministrator {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [object] $Context
    )

    $checkId = 'PRIV-004'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminAssignments'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    # 'Assigned' instances are standing access; 'Activated' instances come from a time-limited PIM activation.
    $standing = [System.Collections.Generic.List[string]]::new()
    foreach ($instance in @(Get-SourceItem -Source $source | Where-Object { (Get-PropertyValue $_ 'assignmentType') -eq 'Assigned' })) {
        $principal = Get-PropertyValue $instance 'principal'
        $id = [string] (Get-PropertyValue $instance 'principalId')
        $type = Get-ObjectTypeName $principal
        if ($type -eq 'group') {
            $members = Get-ExpandedGroupMember -Snapshot $Snapshot -GroupId $id -IdentityMap $Context.IdentityMap
            if ($null -eq $members) {
                $standing.Add("group: $(Get-PropertyValue $principal 'displayName')")
            }
            else {
                $members | ForEach-Object { $standing.Add($_.Label) }
            }
        }
        elseif ($type -in @('', 'user')) {
            $standing.Add((Resolve-PrincipalLabel -Id $id -Upn (Get-PropertyValue $principal 'userPrincipalName') -IdentityMap $Context.IdentityMap))
        }
        else {
            $standing.Add((Format-DirectoryObject $principal))
        }
    }

    $emergency = @($Context.EmergencyAccessAccounts)
    $nonEmergency = @($standing | Select-Object -Unique | Where-Object { $_ -notin $emergency })

    $eligibility = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdminEligibility'
    $eligibilityNote = if (-not (Test-SourceCollected $eligibility)) {
        'Eligible assignments could not be read.'
    }
    elseif (@(Get-SourceItem -Source $eligibility).Count -eq 0) {
        'PIM eligibility is not used for Global Administrator.'
    }
    else {
        "$(@(Get-SourceItem -Source $eligibility).Count) eligible assignment(s) exist."
    }

    if ($nonEmergency.Count -eq 0) {
        $observed = if ($standing.Count -eq 0) {
            'No permanent Global Administrator assignments exist; access is activated just in time.'
        }
        else {
            'Only emergency-access accounts hold permanent Global Administrator assignments; other administrators activate the role just in time.'
        }
        return New-SecurityFinding -CheckId $checkId -Status Pass -Observed $observed
    }

    $observed = "$($nonEmergency.Count) account(s) hold permanent (standing) Global Administrator access outside PIM activation. $eligibilityNote"
    if ($emergency.Count -eq 0) {
        $observed += ' No emergency-access accounts are configured, so none were excluded from this count.'
    }
    New-SecurityFinding -CheckId $checkId -Status Warn -Observed $observed -AffectedObjects $nonEmergency
}

function Test-EmergencyAccess {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [object] $Context
    )

    $checkId = 'PRIV-005'
    $emergency = @($Context.EmergencyAccessAccounts)
    if ($emergency.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'No emergency-access accounts are listed in the assessment configuration (EmergencyAccessAccounts), so lockout protection could not be checked.'
    }

    $globalAdmins = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdministrators'
    $conditionalAccess = Get-SnapshotSource -Snapshot $Snapshot -Name 'ConditionalAccessPolicies'
    $failed = @($globalAdmins, $conditionalAccess | Where-Object { -not (Test-SourceCollected $_) })
    if ($failed.Count -gt 0) {
        return New-NotAssessedFinding -CheckId $checkId -Source $failed
    }

    $map = $Context.IdentityMap
    $activeUpns = @(Get-SourceItem -Source $globalAdmins |
            Where-Object { (Get-ObjectTypeName $_) -in @('', 'user') } |
            ForEach-Object { [string] (Get-PropertyValue $_ 'userPrincipalName') })
    $emergencyIds = @($emergency | ForEach-Object { $map.ByUpn[$_] } | Where-Object { $_ })

    $notes = [System.Collections.Generic.List[string]]::new()
    $affected = [System.Collections.Generic.List[string]]::new()
    $status = 'Pass'

    $missing = @($emergency | Where-Object { $_ -notin $activeUpns })
    if ($missing.Count -gt 0) {
        $notes.Add("Emergency-access account(s) without an active Global Administrator assignment: $($missing -join ', ').")
        $missing | ForEach-Object { $affected.Add($_) }
        $status = 'Fail'
    }
    if ($emergency.Count -lt 2) {
        $notes.Add('Only one emergency-access account is configured; Microsoft recommends at least two.')
        if ($status -eq 'Pass') { $status = 'Warn' }
    }

    $lockout = [System.Collections.Generic.List[string]]::new()
    $groupOnly = [System.Collections.Generic.List[string]]::new()
    $extraExclusions = [System.Collections.Generic.List[string]]::new()
    $policies = @(Get-SourceItem -Source $conditionalAccess | Where-Object { (Test-PolicyEnabled $_) -and (Test-PolicyHasGrantControl $_) })
    foreach ($policy in $policies) {
        $includeUsers = @(Get-PolicyUserCondition -Policy $policy -Name includeUsers)
        $excludeUsers = @(Get-PolicyUserCondition -Policy $policy -Name excludeUsers)
        $targetsEmergency = ($includeUsers -contains 'All') -or
            @($includeUsers | Where-Object { $_ -in $emergencyIds }).Count -gt 0 -or
            ((Get-PolicyUserCondition -Policy $policy -Name includeRoles) -contains $script:GlobalAdministratorRoleTemplateId)

        if ($targetsEmergency -and @($excludeUsers | Where-Object { $_ -in $emergencyIds }).Count -eq 0) {
            if (@(Get-PolicyUserCondition -Policy $policy -Name excludeGroups).Count -gt 0) {
                $groupOnly.Add((Format-PolicyName $policy))
            }
            else {
                $lockout.Add((Format-PolicyName $policy))
            }
        }

        $others = @($excludeUsers | Where-Object { $_ -notin $emergencyIds -and $_ -ne 'GuestsOrExternalUsers' } |
                ForEach-Object { Resolve-PrincipalLabel -Id $_ -Upn $null -IdentityMap $map })
        if ($others.Count -gt 0) {
            $extraExclusions.Add("$(Format-PolicyName $policy) ($($others -join ', '))")
            $others | ForEach-Object { $affected.Add($_) }
        }
    }

    if ($lockout.Count -gt 0) {
        $notes.Add("Enabled policies that apply to every emergency-access account: $($lockout -join ', '). A mistake in one of them could lock out all administrators.")
        if ($status -eq 'Pass') { $status = 'Warn' }
    }
    if ($extraExclusions.Count -gt 0) {
        $notes.Add("Users who are not emergency-access accounts are excluded from enabled policies: $($extraExclusions -join '; ').")
        if ($status -eq 'Pass') { $status = 'Warn' }
    }
    if ($groupOnly.Count -gt 0) {
        $notes.Add("Policies $($groupOnly -join ', ') exclude groups only; confirm an emergency-access account is in an excluded group.")
    }

    if ($status -eq 'Pass') {
        $notes.Insert(0, "$($emergency.Count) emergency-access account(s) hold active Global Administrator, at least one is excluded from every enabled Conditional Access policy that applies to them, and no other users are excluded.")
    }
    New-SecurityFinding -CheckId $checkId -Status $status -Observed ($notes -join ' ') -AffectedObjects @($affected)
}
