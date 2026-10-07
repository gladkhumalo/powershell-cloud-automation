#Requires -Version 7.2
Set-StrictMode -Version Latest

$script:ToolVersion = '0.1.0'
$script:SnapshotSchemaVersion = 1
$script:GlobalAdministratorRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

# Static check definitions. Order here is the report order within each status and severity.
$script:CheckCatalog = [ordered]@{
    'ID-001'     = @{
        Category       = 'Identity'
        Title          = 'MFA is enforced for all users'
        Severity       = 'High'
        Recommendation = 'Enable security defaults, or create a Conditional Access policy that requires MFA (preferably an authentication strength) for all users and all resources. Exclude only documented emergency-access accounts, and switch report-only policies to On after reviewing sign-in impact.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength'
    }
    'ID-002'     = @{
        Category       = 'Identity'
        Title          = 'Legacy authentication is blocked'
        Severity       = 'High'
        Recommendation = 'Block legacy authentication for all users with Conditional Access (client apps: Exchange ActiveSync clients and Other clients), or enable security defaults. Review sign-in logs for legacy clients before enforcing.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication'
    }
    'ID-003'     = @{
        Category       = 'Identity'
        Title          = 'Members are registered for MFA'
        Severity       = 'Medium'
        Recommendation = 'Run a registration campaign or a Conditional Access registration policy for unregistered members. Review disabled, shared, and service accounts separately instead of excluding them silently.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign'
    }
    'PRIV-001'   = @{
        Category       = 'Privileged access'
        Title          = 'Global Administrator count is within range'
        Severity       = 'High'
        Recommendation = 'Keep between two and four Global Administrators, including emergency-access accounts. Move day-to-day administration to least-privileged roles and use Privileged Identity Management for just-in-time elevation.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    }
    'PRIV-002'   = @{
        Category       = 'Privileged access'
        Title          = 'Administrators are registered for MFA'
        Severity       = 'High'
        Recommendation = 'Have every administrator register MFA now and enforce MFA for directory roles with Conditional Access. Treat an unregistered administrator as a priority account-takeover risk.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    }
    'PRIV-003'   = @{
        Category       = 'Privileged access'
        Title          = 'Administrators have phishing-resistant methods'
        Severity       = 'Medium'
        Recommendation = 'Register FIDO2 security keys, passkeys, or Windows Hello for Business for administrators, then require a phishing-resistant authentication strength for admin roles.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
    }
    'APP-001'    = @{
        Category       = 'Applications'
        Title          = 'User consent to applications is restricted'
        Severity       = 'High'
        Recommendation = "Set user consent to 'Do not allow user consent', or allow consent only for verified publishers and low-impact permissions. Enable the admin consent workflow so users can request access."
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent'
    }
    'APP-002'    = @{
        Category       = 'Applications'
        Title          = 'Users cannot register applications'
        Severity       = 'Medium'
        Recommendation = "Set 'Users can register applications' to No and assign the Application Developer role to people who need it."
        Reference      = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions'
    }
    'COLLAB-001' = @{
        Category       = 'External collaboration'
        Title          = 'Guest invitations are restricted'
        Severity       = 'Medium'
        Recommendation = 'Limit guest invitations to administrators and the Guest Inviter role, and route other external access through entitlement management or an approval process.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure'
    }
    'COLLAB-002' = @{
        Category       = 'External collaboration'
        Title          = 'Guest directory access is restricted'
        Severity       = 'Low'
        Recommendation = 'Restrict guest access to the properties and memberships of their own directory objects unless a documented business need requires broader visibility.'
        Reference      = 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions'
    }
}

$script:StatusRank = @{ Fail = 0; Warn = 1; NotAssessed = 2; Pass = 3 }
$script:SeverityRank = @{ High = 0; Medium = 1; Low = 2 }
$script:CheckRank = @{}
$index = 0
foreach ($checkId in $script:CheckCatalog.Keys) {
    $script:CheckRank[$checkId] = $index++
}

#region Helpers

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

function Get-SourceItem {
    param ([Parameter(Mandatory)] [object] $Source)

    @($Source.Data) | Where-Object { $null -ne $_ }
}

function Format-SourceError {
    param ([Parameter(Mandatory)] [object[]] $Source)

    ($Source | ForEach-Object { "Source '$($_.Name)' was not collected: $($_.Error)" }) -join ' '
}

function Format-DirectoryObject {
    param ([Parameter(Mandatory)] [object] $DirectoryObject)

    $type = [string] (Get-PropertyValue $DirectoryObject '@odata.type') -replace '^#microsoft\.graph\.', ''
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

function New-SecurityFinding {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warn', 'Fail', 'NotAssessed')] [string] $Status,
        [Parameter(Mandatory)] [string] $Observed,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $AffectedObjects
    )

    $definition = $script:CheckCatalog[$CheckId]
    $affected = @($AffectedObjects | Where-Object { $_ })

    $finding = [pscustomobject]@{
        CheckId         = $CheckId
        Category        = $definition.Category
        Title           = $definition.Title
        Severity        = $definition.Severity
        Status          = $Status
        Observed        = $Observed
        Recommendation  = $definition.Recommendation
        AffectedCount   = $affected.Count
        AffectedObjects = [string[]] $affected
        Reference       = $definition.Reference
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

function Get-FindingSummary {
    param ([AllowEmptyCollection()] [object[]] $Finding)

    $summary = [ordered]@{ Fail = 0; Warn = 0; NotAssessed = 0; Pass = 0 }
    foreach ($item in @($Finding)) {
        $summary[$item.Status]++
    }
    [pscustomobject] $summary
}

#endregion

#region Conditional Access helpers

function Test-PolicyIsTenantWide {
    param ([Parameter(Mandatory)] [object] $Policy)

    (@(Get-PropertyValue $Policy 'conditions', 'users', 'includeUsers') -contains 'All') -and
    (@(Get-PropertyValue $Policy 'conditions', 'applications', 'includeApplications') -contains 'All')
}

function Test-PolicyRequiresMfa {
    param ([Parameter(Mandatory)] [object] $Policy)

    (@(Get-PropertyValue $Policy 'grantControls', 'builtInControls') -contains 'mfa') -or
    ($null -ne (Get-PropertyValue $Policy 'grantControls', 'authenticationStrength'))
}

function Test-PolicyBlocksLegacyAuthentication {
    param ([Parameter(Mandatory)] [object] $Policy)

    $clientApps = @(Get-PropertyValue $Policy 'conditions', 'clientAppTypes')
    ($clientApps -contains 'exchangeActiveSync') -and
    ($clientApps -contains 'other') -and
    (@(Get-PropertyValue $Policy 'grantControls', 'builtInControls') -contains 'block')
}

function Format-PolicyName {
    param ([Parameter(Mandatory)] [object] $Policy)

    "'$(Get-PropertyValue $Policy 'displayName')'"
}

function Format-PolicyExclusion {
    param ([Parameter(Mandatory)] [object] $Policy)

    $parts = foreach ($kind in @('User', 'Group', 'Role')) {
        $count = @(Get-PropertyValue $Policy 'conditions', 'users', "exclude${kind}s" | Where-Object { $_ }).Count
        if ($count -gt 0) {
            $noun = if ($count -eq 1) { $kind.ToLowerInvariant() } else { "$($kind.ToLowerInvariant())s" }
            "$count excluded $noun"
        }
    }
    if ($parts) {
        return " ($(@($parts) -join ', '))"
    }
    return ''
}

function Resolve-PolicyBaselineCheck {
    # Shared logic for checks satisfied by security defaults or an equivalent Conditional Access policy.
    param (
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [scriptblock] $Predicate,
        [Parameter(Mandatory)] [string] $DefaultsObservation,
        [Parameter(Mandatory)] [string] $PolicyObservation,
        [Parameter(Mandatory)] [string] $FailObservation,
        [scriptblock] $PartialCoverage
    )

    $defaults = Get-SnapshotSource -Snapshot $Snapshot -Name 'SecurityDefaults'
    $conditionalAccess = Get-SnapshotSource -Snapshot $Snapshot -Name 'ConditionalAccessPolicies'

    if ($defaults.Status -eq 'Collected' -and (Get-PropertyValue $defaults.Data 'isEnabled') -eq $true) {
        return New-SecurityFinding -CheckId $CheckId -Status Pass -Observed $DefaultsObservation
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    if ($conditionalAccess.Status -eq 'Collected') {
        $policies = @(Get-SourceItem -Source $conditionalAccess)
        $matching = @($policies | Where-Object { & $Predicate $_ })
        $enabled = @($matching | Where-Object { (Get-PropertyValue $_ 'state') -eq 'enabled' })
        $reportOnly = @($matching | Where-Object { (Get-PropertyValue $_ 'state') -eq 'enabledForReportingButNotEnforced' })

        if ($enabled.Count -gt 0) {
            $policy = $enabled[0]
            $observed = Format-Invariant $PolicyObservation @((Format-PolicyName $policy), (Format-PolicyExclusion $policy))
            return New-SecurityFinding -CheckId $CheckId -Status Pass -Observed $observed
        }
        foreach ($policy in $reportOnly) {
            $notes.Add("Policy $(Format-PolicyName $policy) would meet this check but is in report-only mode.")
        }
        if ($PartialCoverage) {
            foreach ($note in @(& $PartialCoverage $policies)) {
                $notes.Add($note)
            }
        }
    }

    $failed = @($defaults, $conditionalAccess | Where-Object { $_.Status -ne 'Collected' })
    if ($failed.Count -gt 0) {
        $observed = (@(Format-SourceError -Source $failed) + $notes) -join ' '
        return New-SecurityFinding -CheckId $CheckId -Status NotAssessed -Observed $observed
    }
    if ($notes.Count -gt 0) {
        return New-SecurityFinding -CheckId $CheckId -Status Warn -Observed ($notes -join ' ')
    }
    New-SecurityFinding -CheckId $CheckId -Status Fail -Observed $FailObservation
}

#endregion

#region Checks

function Test-BaselineMfa {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    Resolve-PolicyBaselineCheck -CheckId 'ID-001' -Snapshot $Snapshot `
        -Predicate { param ($p) (Test-PolicyIsTenantWide $p) -and (Test-PolicyRequiresMfa $p) } `
        -DefaultsObservation 'Security defaults are enabled, so all users must register for and use MFA.' `
        -PolicyObservation 'Enabled Conditional Access policy {0} requires MFA for all users and all resources{1}.' `
        -FailObservation 'Security defaults are disabled and no enabled Conditional Access policy requires MFA for all users and all resources.' `
        -PartialCoverage {
            param ($policies)
            $roleOnly = @($policies | Where-Object {
                    (Get-PropertyValue $_ 'state') -eq 'enabled' -and
                    (Test-PolicyRequiresMfa $_) -and
                    @(Get-PropertyValue $_ 'conditions', 'users', 'includeRoles' | Where-Object { $_ }).Count -gt 0 -and
                    -not (@(Get-PropertyValue $_ 'conditions', 'users', 'includeUsers') -contains 'All')
                })
            foreach ($policy in $roleOnly) {
                "Policy $(Format-PolicyName $policy) enforces MFA for selected directory roles only; other users can sign in with a password alone."
            }
        }
}

function Test-LegacyAuthenticationBlocked {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    Resolve-PolicyBaselineCheck -CheckId 'ID-002' -Snapshot $Snapshot `
        -Predicate { param ($p) (Test-PolicyIsTenantWide $p) -and (Test-PolicyBlocksLegacyAuthentication $p) } `
        -DefaultsObservation 'Security defaults are enabled, which block legacy authentication protocols.' `
        -PolicyObservation 'Enabled Conditional Access policy {0} blocks Exchange ActiveSync and other legacy clients for all users{1}.' `
        -FailObservation 'No enabled Conditional Access policy blocks legacy authentication (Exchange ActiveSync and other clients) for all users, and security defaults are disabled.'
}

function Test-MemberMfaRegistration {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [double] $TargetPercent,
        [Parameter(Mandatory)] [double] $MinimumPercent
    )

    $checkId = 'ID-003'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'UserRegistrationDetails'
    if ($source.Status -ne 'Collected') {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $members = @(Get-SourceItem -Source $source | Where-Object { (Get-PropertyValue $_ 'userType') -eq 'member' })
    if ($members.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report contained no member accounts.'
    }

    $unregistered = @($members | Where-Object { (Get-PropertyValue $_ 'isMfaRegistered') -ne $true })
    $registeredCount = $members.Count - $unregistered.Count
    $percent = 100 * $registeredCount / $members.Count

    # Compare the exact ratio; only the displayed value is rounded.
    $status = if ($percent -ge $TargetPercent) { 'Pass' } elseif ($percent -ge $MinimumPercent) { 'Warn' } else { 'Fail' }
    $observed = Format-Invariant '{0} of {1} member accounts ({2:0.0}%) are registered for MFA. Target {3}%, minimum {4}%.' @(
        $registeredCount, $members.Count, $percent, $TargetPercent, $MinimumPercent
    )
    New-SecurityFinding -CheckId $checkId -Status $status -Observed $observed -AffectedObjects @($unregistered | ForEach-Object { Format-UserRecord $_ })
}

function Test-GlobalAdministratorCount {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [int] $Minimum,
        [Parameter(Mandatory)] [int] $Maximum
    )

    $checkId = 'PRIV-001'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'GlobalAdministrators'
    if ($source.Status -ne 'Collected') {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $members = @(Get-SourceItem -Source $source)
    $users = @($members | Where-Object { (Get-PropertyValue $_ '@odata.type') -in @($null, '', '#microsoft.graph.user') })
    $others = @($members | Where-Object { (Get-PropertyValue $_ '@odata.type') -notin @($null, '', '#microsoft.graph.user') })

    $status = if ($users.Count -gt $Maximum) { 'Fail' } elseif ($users.Count -lt $Minimum) { 'Warn' } else { 'Pass' }
    $observed = "$($users.Count) user account(s) hold an active Global Administrator assignment; the target range is $Minimum to $Maximum."
    if ($others.Count -gt 0) {
        $observed += " $($others.Count) group or service principal assignment(s) also hold the role. Group members are not expanded, so more people may have the role."
        if ($status -eq 'Pass') {
            $status = 'Warn'
        }
    }

    $affected = if ($status -eq 'Pass') { @() } else { @($members | ForEach-Object { Format-DirectoryObject $_ }) }
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
    if ($source.Status -ne 'Collected') {
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
    if ($source.Status -ne 'Collected') {
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

function Get-DefaultUserPermission {
    # Returns the defaultUserRolePermissions object, or a NotAssessed finding when it is unavailable.
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $Property
    )

    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'AuthorizationPolicy'
    if ($source.Status -ne 'Collected') {
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
    if ($source.Status -ne 'Collected') {
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

#endregion

#region Collection

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

function Get-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Collects the read-only tenant configuration that the security checks evaluate.
    .DESCRIPTION
    Requires an existing Microsoft Graph connection (Connect-MgGraph). Each data source is
    collected independently: a permission or licensing error on one source is recorded in the
    snapshot and the affected checks report NotAssessed instead of stopping the assessment.
    .EXAMPLE
    Connect-MgGraph -Scopes Policy.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All
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
    $sources.GlobalAdministrators = Invoke-SnapshotCollector -Name 'Global Administrator members' -Collector {
        Invoke-GraphCollection -Uri "v1.0/directoryRoles(roleTemplateId='$($script:GlobalAdministratorRoleTemplateId)')/members?`$select=id,displayName,userPrincipalName"
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

function Export-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Saves a snapshot as JSON so it can be re-assessed offline or compared later.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $directory = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $Snapshot | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $fullPath -Encoding utf8 -ErrorAction Stop
    Get-Item -LiteralPath $fullPath
}

function Import-M365SecuritySnapshot {
    <#
    .SYNOPSIS
    Loads a saved snapshot for offline assessment.
    .EXAMPLE
    Import-M365SecuritySnapshot -Path ./examples/sample-tenant-snapshot.json | Get-M365SecurityFinding
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $snapshot = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 64
    Assert-SnapshotSchema -Snapshot $snapshot
    $snapshot
}

#endregion

#region Assessment and reporting

function Get-M365SecurityFinding {
    <#
    .SYNOPSIS
    Evaluates a tenant snapshot against the security checks and returns one finding per check.
    .DESCRIPTION
    Pure evaluation: no Graph calls are made, so the same snapshot always produces the same
    findings. Findings are sorted by status (Fail, Warn, NotAssessed, Pass) and then severity.
    .EXAMPLE
    Get-M365SecuritySnapshot | Get-M365SecurityFinding | Format-Table Status, Severity, CheckId, Title
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)] [object] $Snapshot,

        [ValidateRange(0, 100)] [int] $MinimumGlobalAdmins = 2,
        [ValidateRange(1, 100)] [int] $MaximumGlobalAdmins = 4,
        [ValidateRange(0, 100)] [double] $MfaRegistrationTargetPercent = 95,
        [ValidateRange(0, 100)] [double] $MfaRegistrationMinimumPercent = 80
    )

    process {
        if ($MinimumGlobalAdmins -gt $MaximumGlobalAdmins) {
            throw 'MinimumGlobalAdmins cannot be greater than MaximumGlobalAdmins.'
        }
        if ($MfaRegistrationMinimumPercent -gt $MfaRegistrationTargetPercent) {
            throw 'MfaRegistrationMinimumPercent cannot be greater than MfaRegistrationTargetPercent.'
        }
        Assert-SnapshotSchema -Snapshot $Snapshot

        $findings = @(
            Test-BaselineMfa -Snapshot $Snapshot
            Test-LegacyAuthenticationBlocked -Snapshot $Snapshot
            Test-MemberMfaRegistration -Snapshot $Snapshot -TargetPercent $MfaRegistrationTargetPercent -MinimumPercent $MfaRegistrationMinimumPercent
            Test-GlobalAdministratorCount -Snapshot $Snapshot -Minimum $MinimumGlobalAdmins -Maximum $MaximumGlobalAdmins
            Test-AdministratorMfaRegistration -Snapshot $Snapshot
            Test-AdministratorPhishingResistantMethod -Snapshot $Snapshot
            Test-UserConsentRestricted -Snapshot $Snapshot
            Test-UserAppRegistration -Snapshot $Snapshot
            Test-GuestInvitation -Snapshot $Snapshot
            Test-GuestDirectoryAccess -Snapshot $Snapshot
        )

        $findings | Sort-Object `
            @{ Expression = { $script:StatusRank[$_.Status] } },
            @{ Expression = { $script:SeverityRank[$_.Severity] } },
            @{ Expression = { $script:CheckRank[$_.CheckId] } }
    }
}

function ConvertTo-HtmlText {
    param ([AllowNull()] [object] $Value)

    [System.Net.WebUtility]::HtmlEncode([string] $Value)
}

function ConvertTo-SecurityReportHtml {
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [object] $Snapshot
    )

    $summary = Get-FindingSummary -Finding $Finding
    $collectedAt = (Get-SnapshotTimestamp -Snapshot $Snapshot).ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)
    $tenantId = ConvertTo-HtmlText (Get-PropertyValue $Snapshot 'TenantId')
    $collectedBy = ConvertTo-HtmlText (Get-PropertyValue $Snapshot 'CollectedBy')
    $statusLabel = @{ Fail = 'Fail'; Warn = 'Warn'; NotAssessed = 'Not assessed'; Pass = 'Pass' }
    $affectedLimit = 25

    $rows = foreach ($item in $Finding) {
        $affectedHtml = ''
        if ($item.AffectedCount -gt 0) {
            $listItems = @($item.AffectedObjects | Select-Object -First $affectedLimit | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" })
            if ($item.AffectedCount -gt $affectedLimit) {
                $listItems += "<li class=`"more`">and $($item.AffectedCount - $affectedLimit) more (see the CSV or JSON report)</li>"
            }
            $affectedHtml = "<details><summary>$($item.AffectedCount) affected</summary><ul>$($listItems -join '')</ul></details>"
        }
        $referenceHtml = ''
        if ([string] $item.Reference -match '^https://') {
            $referenceHtml = " <a href=`"$(ConvertTo-HtmlText $item.Reference)`" rel=`"noopener noreferrer`">Guidance</a>"
        }

        @"
<tr class="status-$($item.Status.ToLowerInvariant())">
  <td><span class="badge $($item.Status.ToLowerInvariant())">$($statusLabel[$item.Status])</span></td>
  <td><span class="sev">$(ConvertTo-HtmlText $item.Severity)</span></td>
  <td class="check"><div class="id">$(ConvertTo-HtmlText $item.CheckId) &middot; $(ConvertTo-HtmlText $item.Category)</div><div class="title">$(ConvertTo-HtmlText $item.Title)</div><p>$(ConvertTo-HtmlText $item.Observed)</p>$affectedHtml</td>
  <td class="rec">$(ConvertTo-HtmlText $item.Recommendation)$referenceHtml</td>
</tr>
"@
    }

    @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>M365 Security Assessment</title>
<style>
:root { color-scheme: light dark; --bg:#f5f6f8; --panel:#ffffff; --text:#1c2230; --muted:#5a6375; --border:#dde1e8;
  --fail:#b42318; --fail-bg:#fde8e7; --warn:#8a5300; --warn-bg:#fff1d0; --na:#475467; --na-bg:#eceff3; --pass:#16794c; --pass-bg:#e2f4e9; --link:#1f5fbf; }
@media (prefers-color-scheme: dark) { :root { --bg:#11141a; --panel:#1a1f28; --text:#e5e8ee; --muted:#9aa3b2; --border:#2c3340;
  --fail:#ff8b82; --fail-bg:#3b1d1b; --warn:#f3c169; --warn-bg:#352913; --na:#b6bdc9; --na-bg:#262c36; --pass:#71d29d; --pass-bg:#15301f; --link:#82b1ff; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width:1180px; margin:0 auto; padding:32px 16px 48px; }
h1 { margin:0 0 4px; font-size:26px; }
.meta { color:var(--muted); margin:0 0 24px; }
.meta code { font-size:13px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px; margin-bottom:24px; }
.card { background:var(--panel); border:1px solid var(--border); border-left-width:5px; border-radius:8px; padding:14px 16px; }
.card .n { font-size:28px; font-weight:600; line-height:1.1; }
.card .l { color:var(--muted); }
.card.fail { border-left-color:var(--fail); } .card.warn { border-left-color:var(--warn); }
.card.notassessed { border-left-color:var(--na); } .card.pass { border-left-color:var(--pass); }
.table-wrap { overflow-x:auto; background:var(--panel); border:1px solid var(--border); border-radius:8px; }
table { width:100%; border-collapse:collapse; min-width:720px; }
th, td { text-align:left; vertical-align:top; padding:12px 14px; border-bottom:1px solid var(--border); }
th { font-size:13px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.03em; }
tr:last-child td { border-bottom:none; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:13px; font-weight:600; white-space:nowrap; }
.badge.fail { color:var(--fail); background:var(--fail-bg); } .badge.warn { color:var(--warn); background:var(--warn-bg); }
.badge.notassessed { color:var(--na); background:var(--na-bg); } .badge.pass { color:var(--pass); background:var(--pass-bg); }
.sev { font-size:13px; color:var(--muted); }
.check .id { font-size:12px; color:var(--muted); }
.check .title { font-weight:600; }
.check p { margin:4px 0 0; }
.rec { color:var(--muted); width:36%; }
a { color:var(--link); }
details { margin-top:6px; } summary { cursor:pointer; color:var(--link); font-size:14px; }
details ul { margin:6px 0 0; padding-left:18px; font-family:Consolas, "Cascadia Mono", monospace; font-size:13px; }
li.more { font-family:inherit; color:var(--muted); list-style:none; margin-left:-18px; }
footer { margin-top:20px; color:var(--muted); font-size:13px; }
</style>
</head>
<body>
<main>
<h1>Microsoft 365 security assessment</h1>
<p class="meta">Tenant <code>$tenantId</code> &middot; collected $collectedAt UTC by $collectedBy &middot; tool v$($script:ToolVersion)</p>
<section class="cards" aria-label="Summary">
  <div class="card fail"><div class="n">$($summary.Fail)</div><div class="l">Fail</div></div>
  <div class="card warn"><div class="n">$($summary.Warn)</div><div class="l">Warn</div></div>
  <div class="card notassessed"><div class="n">$($summary.NotAssessed)</div><div class="l">Not assessed</div></div>
  <div class="card pass"><div class="n">$($summary.Pass)</div><div class="l">Pass</div></div>
</section>
<div class="table-wrap">
<table>
<thead><tr><th>Status</th><th>Severity</th><th>Check and observation</th><th>Recommendation</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
</div>
<footer>Read-only configuration review. Findings describe configuration at collection time and do not replace a full security review. This report contains tenant and account details; store and share it as confidential.</footer>
</main>
</body>
</html>
"@
}

function Export-M365SecurityReport {
    <#
    .SYNOPSIS
    Writes findings to timestamped CSV, JSON, and HTML reports and returns the files.
    .EXAMPLE
    $findings | Export-M365SecurityReport -Snapshot $snapshot -OutputDirectory ./output
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $OutputDirectory,
        [ValidatePattern('^[\w.-]+$')] [string] $BaseName = 'M365-Security-Assessment',
        [ValidateSet('Csv', 'Html', 'Json')] [string[]] $Format = @('Csv', 'Html', 'Json')
    )

    $directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $collectedAt = Get-SnapshotTimestamp -Snapshot $Snapshot
    $stamp = $collectedAt.ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
    $tenantId = [string] (Get-PropertyValue $Snapshot 'TenantId')
    $assessedAt = $collectedAt.ToString('o', [cultureinfo]::InvariantCulture)

    foreach ($kind in ($Format | Select-Object -Unique)) {
        $path = Join-Path $directory "$BaseName-$stamp.$($kind.ToLowerInvariant())"
        switch ($kind) {
            'Csv' {
                $columns = 'TenantId,CollectedAtUtc,CheckId,Category,Title,Severity,Status,Observed,Recommendation,AffectedCount,AffectedObjects,Reference'
                if (@($Finding).Count -eq 0) {
                    $columns | Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
                }
                else {
                    $Finding | ForEach-Object {
                        [pscustomobject]@{
                            TenantId        = $tenantId
                            CollectedAtUtc  = $assessedAt
                            CheckId         = $_.CheckId
                            Category        = $_.Category
                            Title           = $_.Title
                            Severity        = $_.Severity
                            Status          = $_.Status
                            Observed        = $_.Observed
                            Recommendation  = $_.Recommendation
                            AffectedCount   = $_.AffectedCount
                            AffectedObjects = @($_.AffectedObjects) -join '; '
                            Reference       = $_.Reference
                        }
                    } | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8 -ErrorAction Stop
                }
            }
            'Json' {
                [pscustomobject]@{
                    Tool           = 'M365SecurityAssessment'
                    ToolVersion    = $script:ToolVersion
                    TenantId       = $tenantId
                    CollectedBy    = [string] (Get-PropertyValue $Snapshot 'CollectedBy')
                    CollectedAtUtc = $assessedAt
                    Summary        = Get-FindingSummary -Finding $Finding
                    Findings       = @($Finding)
                } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
            }
            'Html' {
                ConvertTo-SecurityReportHtml -Finding @($Finding) -Snapshot $Snapshot |
                    Set-Content -LiteralPath $path -Encoding utf8 -ErrorAction Stop
            }
        }
        Get-Item -LiteralPath $path
    }
}

#endregion

Export-ModuleMember -Function Get-M365SecuritySnapshot, Export-M365SecuritySnapshot, Import-M365SecuritySnapshot,
    Get-M365SecurityFinding, Export-M365SecurityReport
