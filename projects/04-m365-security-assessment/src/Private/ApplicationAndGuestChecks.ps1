function Get-DefaultUserPermission {
    # Returns the requested defaultUserRolePermissions value, or a NotAssessed finding when it is unavailable.
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $Property
    )

    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'AuthorizationPolicy'
    if (-not (Test-SourceCollected $source)) {
        return [pscustomobject]@{ Finding = (New-NotAssessedFinding -CheckId $CheckId -Source $source); Value = $null }
    }

    $permissions = Get-PropertyValue $source.Data 'defaultUserRolePermissions'
    if (-not (Test-PropertyPresent -InputObject $permissions -Name $Property)) {
        $finding = New-SecurityFinding -CheckId $CheckId -Status NotAssessed -Observed "The authorization policy did not include defaultUserRolePermissions.$Property."
        return [pscustomobject]@{ Finding = $finding; Value = $null }
    }
    [pscustomobject]@{ Finding = $null; Value = (Get-PropertyValue $permissions $Property) }
}

function Get-AuthorizationPolicySetting {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $Property
    )

    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'AuthorizationPolicy'
    if (-not (Test-SourceCollected $source)) {
        return [pscustomobject]@{ Finding = (New-NotAssessedFinding -CheckId $CheckId -Source $source); Value = $null }
    }
    $value = Get-PropertyValue $source.Data $Property
    if ($null -eq $value) {
        $finding = New-SecurityFinding -CheckId $CheckId -Status NotAssessed -Observed "The authorization policy did not include $Property."
        return [pscustomobject]@{ Finding = $finding; Value = $null }
    }
    [pscustomobject]@{ Finding = $null; Value = $value }
}

function Test-UserConsentRestricted {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'APP-001'
    $setting = Get-DefaultUserPermission -Snapshot $Snapshot -CheckId $checkId -Property 'permissionGrantPoliciesAssigned'
    if ($setting.Finding) {
        return $setting.Finding
    }

    # ManagePermissionGrantsForOwnedResource.* covers group and team owner consent, not user consent to apps.
    $selfConsent = @(@($setting.Value) | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    if ($selfConsent.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status Pass -Observed 'Users cannot consent to applications; admin consent is required.'
    }

    $policyNames = @($selfConsent | ForEach-Object { $_ -replace '^ManagePermissionGrantsForSelf\.', '' })
    if ($selfConsent -like '*microsoft-user-default-legacy') {
        return New-SecurityFinding -CheckId $checkId -Status Fail -Observed "Users can consent to any application for permissions that do not require admin consent (policy: $($policyNames -join ', '))."
    }
    New-SecurityFinding -CheckId $checkId -Status Warn -Observed "Users can consent to applications within these permission grant policies: $($policyNames -join ', '). Confirm consent is limited to verified publishers and low-impact permissions."
}

function Test-UserAppRegistration {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'APP-002'
    $setting = Get-DefaultUserPermission -Snapshot $Snapshot -CheckId $checkId -Property 'allowedToCreateApps'
    if ($setting.Finding) {
        return $setting.Finding
    }
    if ($setting.Value -eq $true) {
        return New-SecurityFinding -CheckId $checkId -Status Warn -Observed 'Default user permissions allow any member to register applications.'
    }
    New-SecurityFinding -CheckId $checkId -Status Pass -Observed "'Users can register applications' is set to No."
}

function Test-GuestInvitation {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'COLLAB-001'
    $setting = Get-AuthorizationPolicySetting -Snapshot $Snapshot -CheckId $checkId -Property 'allowInvitesFrom'
    if ($setting.Finding) {
        return $setting.Finding
    }

    switch ([string] $setting.Value) {
        'everyone' { New-SecurityFinding -CheckId $checkId -Status Fail -Observed 'Anyone in the organization, including guests, can invite guest users.' }
        'adminsGuestInvitersAndAllMembers' { New-SecurityFinding -CheckId $checkId -Status Warn -Observed 'All member users can invite guests, in addition to administrators and the Guest Inviter role.' }
        'adminsAndGuestInviters' { New-SecurityFinding -CheckId $checkId -Status Pass -Observed 'Only administrators and users in the Guest Inviter role can invite guests.' }
        'none' { New-SecurityFinding -CheckId $checkId -Status Pass -Observed 'Guest invitations are disabled for everyone, including administrators.' }
        default { New-SecurityFinding -CheckId $checkId -Status Warn -Observed "Unrecognized allowInvitesFrom value '$_'; review the external collaboration settings manually." }
    }
}

function Test-GuestDirectoryAccess {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'COLLAB-002'
    $setting = Get-AuthorizationPolicySetting -Snapshot $Snapshot -CheckId $checkId -Property 'guestUserRoleId'
    if ($setting.Finding) {
        return $setting.Finding
    }

    switch ([string] $setting.Value) {
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' { New-SecurityFinding -CheckId $checkId -Status Fail -Observed 'Guest users have the same directory access as members.' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' { New-SecurityFinding -CheckId $checkId -Status Warn -Observed 'Guest users have limited access to directory objects (the Microsoft default).' }
        '2af84b1e-32c8-42b7-82bc-daa82404023b' { New-SecurityFinding -CheckId $checkId -Status Pass -Observed 'Guest access is restricted to the properties and memberships of their own directory objects.' }
        default { New-SecurityFinding -CheckId $checkId -Status Warn -Observed "Unrecognized guestUserRoleId '$_'; review guest access settings manually." }
    }
}
