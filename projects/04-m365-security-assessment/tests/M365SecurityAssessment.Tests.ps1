$modulePath = Join-Path $PSScriptRoot '../src/M365SecurityAssessment.psd1'
$scriptPath = Join-Path $PSScriptRoot '../src/Invoke-M365SecurityAssessment.ps1'
$samplePath = Join-Path $PSScriptRoot '../examples/sample-tenant-snapshot.json'
$previousSamplePath = Join-Path $PSScriptRoot '../examples/sample-tenant-snapshot-previous.json'
$sampleConfigurationPath = Join-Path $PSScriptRoot '../../../config/m365-security-assessment.example.json'
Import-Module $modulePath -Force

# Stand-ins so the Graph cmdlets can be mocked on machines without the Graph SDK (such as CI).
function global:Get-MgContext { [CmdletBinding()] param () }
function global:Invoke-MgGraphRequest {
    [CmdletBinding()]
    param ([string] $Method, [string] $Uri, [string] $OutputType)
}

$globalAdminRole = '62e90394-69f5-4237-9190-012177145e10'
$restrictedGuestRole = '2af84b1e-32c8-42b7-82bc-daa82404023b'

function New-TestSource {
    param ([AllowNull()] [object] $Data, [string] $Status = 'Collected', [string] $ErrorMessage)
    [pscustomobject]@{ Status = $Status; Error = $ErrorMessage; Data = $Data }
}

function New-TestRegistration {
    param (
        [string] $Upn,
        [string] $UserType = 'member',
        [bool] $IsAdmin = $false,
        [bool] $IsMfaRegistered = $true,
        [string[]] $Methods = @('microsoftAuthenticatorPush'),
        [bool] $IsSsprEnabled = $true,
        [bool] $IsSsprRegistered = $true
    )
    [pscustomobject]@{
        id                = "id-$Upn"
        userPrincipalName = $Upn
        userType          = $UserType
        isAdmin           = $IsAdmin
        isMfaRegistered   = $IsMfaRegistered
        isSsprEnabled     = $IsSsprEnabled
        isSsprRegistered  = $IsSsprRegistered
        methodsRegistered = $Methods
    }
}

function New-TestUser {
    param ([string] $Upn)
    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = "id-$Upn"; displayName = $Upn; userPrincipalName = $Upn }
}

function New-TestGroup {
    param ([string] $Id, [string] $Name)
    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $Id; displayName = $Name }
}

function New-TestSchedule {
    param ([object] $Principal, [string] $AssignmentType)
    $instance = [ordered]@{ principalId = $Principal.id; roleDefinitionId = $globalAdminRole }
    if ($AssignmentType) { $instance.assignmentType = $AssignmentType }
    $instance.principal = $Principal
    [pscustomobject] $instance
}

function New-TestPolicy {
    param (
        [string] $Id = ([guid]::NewGuid().ToString()),
        [string] $Name = 'Test policy',
        [string] $State = 'enabled',
        [string[]] $IncludeUsers = @('All'),
        [string[]] $IncludeRoles = @(),
        [string[]] $ExcludeUsers = @(),
        [string[]] $ExcludeGroups = @(),
        [string[]] $ClientAppTypes = @('all'),
        [string[]] $Controls = @('mfa'),
        [object] $AuthenticationStrength = $null
    )
    [pscustomobject]@{
        id            = $Id
        displayName   = $Name
        state         = $State
        conditions    = [pscustomobject]@{
            clientAppTypes = $ClientAppTypes
            applications   = [pscustomobject]@{ includeApplications = @('All') }
            users          = [pscustomobject]@{
                includeUsers  = $IncludeUsers
                excludeUsers  = $ExcludeUsers
                includeGroups = @()
                excludeGroups = $ExcludeGroups
                includeRoles  = $IncludeRoles
                excludeRoles  = @()
            }
        }
        grantControls = [pscustomobject]@{ builtInControls = $Controls; authenticationStrength = $AuthenticationStrength }
    }
}

function New-TestMethod {
    param ([string] $Id, [string] $State)
    [pscustomobject]@{ id = $Id; state = $State }
}

function New-TestSnapshot {
    # A tenant that passes every check when assessed with New-TestConfiguration. Tests change one setting at a time.
    $registrations = @(
        New-TestRegistration -Upn 'admin1@lab.example' -IsAdmin $true -Methods @('fido2')
        New-TestRegistration -Upn 'admin2@lab.example' -IsAdmin $true -Methods @('windowsHelloForBusiness')
    )
    $registrations += 1..18 | ForEach-Object { New-TestRegistration -Upn "user$_@lab.example" }
    $admin1 = New-TestUser 'admin1@lab.example'
    $admin2 = New-TestUser 'admin2@lab.example'

    [pscustomobject]@{
        SchemaVersion  = 1
        TenantId       = '00000000-0000-4000-8000-000000000000'
        CollectedBy    = 'reader@lab.example'
        CollectedAtUtc = '2026-01-02T03:04:05.0000000Z'
        Sources        = [pscustomobject]@{
            SecurityDefaults            = New-TestSource ([pscustomobject]@{ isEnabled = $true })
            ConditionalAccessPolicies   = New-TestSource @()
            AuthorizationPolicy         = New-TestSource ([pscustomobject]@{
                    allowInvitesFrom           = 'adminsAndGuestInviters'
                    guestUserRoleId            = $restrictedGuestRole
                    defaultUserRolePermissions = [pscustomobject]@{
                        allowedToCreateApps             = $false
                        permissionGrantPoliciesAssigned = @()
                    }
                })
            AuthenticationMethodsPolicy = New-TestSource ([pscustomobject]@{
                    policyMigrationState               = 'migrationComplete'
                    authenticationMethodConfigurations = @(
                        New-TestMethod 'Fido2' 'enabled'
                        New-TestMethod 'Sms' 'disabled'
                        New-TestMethod 'Voice' 'disabled'
                        New-TestMethod 'Email' 'disabled'
                    )
                })
            GlobalAdministrators        = New-TestSource @($admin1, $admin2)
            GlobalAdminAssignments      = New-TestSource @(
                New-TestSchedule $admin1 'Assigned'
                New-TestSchedule $admin2 'Assigned'
            )
            GlobalAdminEligibility      = New-TestSource @()
            GlobalAdminGroupMembers     = New-TestSource @()
            UserRegistrationDetails     = New-TestSource $registrations
        }
    }
}

function New-TestConfiguration {
    param (
        [string[]] $Emergency = @('admin1@lab.example', 'admin2@lab.example'),
        [object[]] $AcceptedRisks = @(),
        [hashtable] $Thresholds = @{},
        [string] $TenantId
    )
    [pscustomobject]@{
        SchemaVersion           = 1
        TenantId                = $TenantId
        EmergencyAccessAccounts = $Emergency
        Thresholds              = [pscustomobject] $Thresholds
        AcceptedRisks           = $AcceptedRisks
    }
}

function New-TestRisk {
    param ([string] $CheckId, [string[]] $AffectedObjects = @(), [string] $Expires = '2026-12-31')
    [pscustomobject]@{ CheckId = $CheckId; AffectedObjects = $AffectedObjects; Reason = 'Test reason'; Owner = 'owner@lab.example'; Expires = $Expires; Ticket = 'RISK-1' }
}

function Get-TestFinding {
    param ([object] $Snapshot, [string] $CheckId, [hashtable] $Option = @{})
    if (-not $Option.ContainsKey('Configuration')) {
        $Option = $Option.Clone()
        $Option.Configuration = New-TestConfiguration
    }
    Get-M365SecurityFinding -Snapshot $Snapshot @Option | Where-Object CheckId -EQ $CheckId
}

function Disable-SecurityDefault {
    param ([object] $Snapshot)
    $Snapshot.Sources.SecurityDefaults.Data.isEnabled = $false
}

Describe 'Get-M365SecurityFinding' {
    It 'returns one finding for each of the fourteen checks and passes a well-configured tenant' {
        $findings = @(Get-M365SecurityFinding -Snapshot (New-TestSnapshot) -Configuration (New-TestConfiguration))

        $findings.Count | Should Be 14
        (@($findings | Where-Object Status -NE 'Pass').CheckId -join ',') | Should Be ''
        @($findings.CheckId | Select-Object -Unique).Count | Should Be 14
    }

    It 'evaluates the fictional sample tenant with its configuration and sorts by status and severity' {
        $configuration = Import-M365SecurityConfiguration -Path $sampleConfigurationPath
        $findings = @(Import-M365SecuritySnapshot -Path $samplePath | Get-M365SecurityFinding -Configuration $configuration)

        ($findings.CheckId -join ',') |
            Should Be 'PRIV-001,PRIV-002,COLLAB-001,ID-001,PRIV-005,APP-001,ID-003,ID-004,PRIV-003,PRIV-004,ID-005,COLLAB-002,ID-002,APP-002'
        ($findings.Status -join ',') |
            Should Be 'Fail,Fail,Fail,Warn,Warn,Warn,Warn,Warn,Warn,Warn,Warn,Accepted,Pass,Pass'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').AffectedObjects | Should Be 'lerato.ops@lab.example.com'
    }

    It 'adds baseline control IDs to findings' {
        $finding = Get-TestFinding (New-TestSnapshot) 'PRIV-004'

        $finding.BaselineControls | Should Be 'CISA MS.AAD.7.4v1'
    }

    It 'rejects an unsupported snapshot schema version' {
        $snapshot = New-TestSnapshot
        $snapshot.SchemaVersion = 99

        { Get-M365SecurityFinding -Snapshot $snapshot } | Should Throw 'Unsupported snapshot schema version'
    }

    It 'rejects thresholds where the minimum is above the maximum' {
        # Pester 3.4 on PowerShell 7 only detects the exception when an expected message is given.
        { Get-M365SecurityFinding -Snapshot (New-TestSnapshot) -MinimumGlobalAdmins 5 -MaximumGlobalAdmins 4 } |
            Should Throw 'MinimumGlobalAdmins cannot be greater'
        { Get-M365SecurityFinding -Snapshot (New-TestSnapshot) -MfaRegistrationMinimumPercent 96 } |
            Should Throw 'MfaRegistrationMinimumPercent cannot be greater'
    }

    It 'reports NotAssessed instead of failing when a source is missing or failed' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails = New-TestSource $null -Status 'Failed' -ErrorMessage 'Forbidden'
        $snapshot.Sources.PSObject.Properties.Remove('AuthorizationPolicy')

        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot -Configuration (New-TestConfiguration))
        $notAssessed = @($findings | Where-Object Status -EQ 'NotAssessed' | ForEach-Object CheckId | Sort-Object)

        ($notAssessed -join ',') | Should Be 'APP-001,APP-002,COLLAB-001,COLLAB-002,ID-003,ID-005,PRIV-002,PRIV-003'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').Observed | Should Match 'UserRegistrationDetails.*Forbidden'
    }

    It 'assesses a v0.1 snapshot that lacks the newer sources' {
        $snapshot = New-TestSnapshot
        foreach ($name in @('AuthenticationMethodsPolicy', 'GlobalAdminAssignments', 'GlobalAdminEligibility', 'GlobalAdminGroupMembers')) {
            $snapshot.Sources.PSObject.Properties.Remove($name)
        }

        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot -Configuration (New-TestConfiguration))

        ($findings | Where-Object CheckId -EQ 'ID-004').Status | Should Be 'NotAssessed'
        ($findings | Where-Object CheckId -EQ 'PRIV-004').Status | Should Be 'NotAssessed'
        ($findings | Where-Object CheckId -EQ 'PRIV-001').Status | Should Be 'Pass'
        ($findings | Where-Object CheckId -EQ 'PRIV-001').Observed | Should Match 'Eligible \(PIM\) assignments are not included'
    }
}

Describe 'Baseline MFA and legacy authentication checks' {
    It 'passes ID-001 when an enabled policy requires MFA for all users and notes exclusions' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -Name 'Require MFA' -ExcludeUsers @('id-admin1@lab.example', 'id-admin2@lab.example'))

        $finding = Get-TestFinding $snapshot 'ID-001'

        $finding.Status | Should Be 'Pass'
        $finding.Observed | Should Match "'Require MFA'.*2 excluded users"
    }

    It 'accepts an authentication strength in place of the built-in MFA control' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $policy = New-TestPolicy -Controls @() -AuthenticationStrength ([pscustomobject]@{ displayName = 'Phishing-resistant MFA' })
        $snapshot.Sources.ConditionalAccessPolicies.Data = @($policy)

        (Get-TestFinding $snapshot 'ID-001').Status | Should Be 'Pass'
    }

    It 'warns when the all-users MFA policy is report-only or MFA covers admin roles only' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'All users MFA' -State 'enabledForReportingButNotEnforced'
            New-TestPolicy -Name 'Admin MFA' -IncludeUsers @() -IncludeRoles @($globalAdminRole)
        )

        $finding = Get-TestFinding $snapshot 'ID-001'

        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match 'report-only'
        $finding.Observed | Should Match 'selected directory roles only'
    }

    It 'fails ID-001 when no defaults or enabled policy enforce MFA, ignoring disabled policies' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -Name 'Require MFA (off)' -State 'disabled')

        $finding = Get-TestFinding $snapshot 'ID-001'
        $finding.Status | Should Be 'Fail'
        $finding.Observed | Should Match "Policy 'Require MFA \(off\)' would meet this check but is turned off\.$"
    }

    It 'reports NotAssessed when security defaults are off and policies could not be read' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies = New-TestSource $null -Status 'Failed' -ErrorMessage 'Forbidden'

        (Get-TestFinding $snapshot 'ID-001').Status | Should Be 'NotAssessed'
        (Get-TestFinding $snapshot 'ID-002').Status | Should Be 'NotAssessed'
    }

    It 'passes ID-002 only when both legacy client types are blocked for all users' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'Block EAS only' -ClientAppTypes @('exchangeActiveSync') -Controls @('block')
        )
        (Get-TestFinding $snapshot 'ID-002').Status | Should Be 'Fail'

        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'Block legacy' -ClientAppTypes @('exchangeActiveSync', 'other') -Controls @('block')
        )
        (Get-TestFinding $snapshot 'ID-002').Status | Should Be 'Pass'
    }
}

Describe 'Authentication method and SSPR checks' {
    It 'warns on ID-004 and lists the weak methods that are enabled' {
        $snapshot = New-TestSnapshot
        ($snapshot.Sources.AuthenticationMethodsPolicy.Data.authenticationMethodConfigurations | Where-Object id -EQ 'Sms').state = 'enabled'
        ($snapshot.Sources.AuthenticationMethodsPolicy.Data.authenticationMethodConfigurations | Where-Object id -EQ 'Email').state = 'enabled'

        $finding = Get-TestFinding $snapshot 'ID-004'

        $finding.Status | Should Be 'Warn'
        ($finding.AffectedObjects -join ',') | Should Be 'Sms,Email'
        $finding.Observed | Should Be 'Enabled in the authentication methods policy: SMS, email one-time passcode.'
    }

    It 'warns on ID-004 when the authentication methods migration is incomplete' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.AuthenticationMethodsPolicy.Data.policyMigrationState = 'migrationInProgress'

        $finding = Get-TestFinding $snapshot 'ID-004'

        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match "migration state is 'migrationInProgress'"
    }

    It 'grades SSPR registration among enabled non-admin members' {
        $snapshot = New-TestSnapshot
        $records = $snapshot.Sources.UserRegistrationDetails.Data
        ($records | Where-Object userPrincipalName -EQ 'user1@lab.example').isSsprRegistered = $false
        # An unregistered administrator does not count: admins use the separate admin SSPR policy.
        ($records | Where-Object userPrincipalName -EQ 'admin1@lab.example').isSsprRegistered = $false

        $finding = Get-TestFinding $snapshot 'ID-005'

        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match '^17 of 18 SSPR-enabled member accounts \(94\.4%\)'
        $finding.AffectedObjects | Should Be 'user1@lab.example'
    }

    It 'warns when SSPR is disabled or enabled only for some members' {
        $snapshot = New-TestSnapshot
        $members = @($snapshot.Sources.UserRegistrationDetails.Data | Where-Object isAdmin -EQ $false)

        $members | ForEach-Object { $_.isSsprEnabled = $false }
        (Get-TestFinding $snapshot 'ID-005').Observed | Should Be 'Self-service password reset is not enabled for any of the 18 non-admin member accounts.'

        $members | ForEach-Object { $_.isSsprEnabled = $true }
        $members[0].isSsprEnabled = $false
        $finding = Get-TestFinding $snapshot 'ID-005'
        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match '1 non-admin member account\(s\) are not enabled for SSPR'
    }

    It 'reports NotAssessed for SSPR when the registration data has no SSPR fields' {
        $snapshot = New-TestSnapshot
        foreach ($record in $snapshot.Sources.UserRegistrationDetails.Data) {
            $record.PSObject.Properties.Remove('isSsprEnabled')
            $record.PSObject.Properties.Remove('isSsprRegistered')
        }

        (Get-TestFinding $snapshot 'ID-005').Status | Should Be 'NotAssessed'
    }
}

Describe 'Privileged access checks' {
    It 'grades the Global Administrator count against the configured range' {
        $snapshot = New-TestSnapshot
        $set = {
            param ($Count)
            $users = @(1..$Count | ForEach-Object { New-TestUser "ga$_@lab.example" })
            $snapshot.Sources.GlobalAdministrators.Data = $users
        }

        & $set 1
        (Get-TestFinding $snapshot 'PRIV-001').Status | Should Be 'Warn'

        & $set 4
        $finding = Get-TestFinding $snapshot 'PRIV-001'
        $finding.Status | Should Be 'Pass'
        $finding.AffectedCount | Should Be 0

        & $set 5
        $finding = Get-TestFinding $snapshot 'PRIV-001'
        $finding.Status | Should Be 'Fail'
        $finding.AffectedCount | Should Be 5

        (Get-TestFinding $snapshot 'PRIV-001' @{ MaximumGlobalAdmins = 6 }).Status | Should Be 'Pass'
        (Get-TestFinding $snapshot 'PRIV-001' @{ Configuration = (New-TestConfiguration -Thresholds @{ MaximumGlobalAdmins = 8 }) }).Status | Should Be 'Pass'
    }

    It 'counts PIM-eligible users and members of role-assignable groups once each' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data += New-TestGroup 'group-1' 'Tier 0 Admins'
        $snapshot.Sources.GlobalAdminEligibility.Data = @(
            New-TestSchedule (New-TestUser 'jit@lab.example') $null
            New-TestSchedule (New-TestUser 'admin1@lab.example') $null
        )
        $snapshot.Sources.GlobalAdminGroupMembers.Data = @([pscustomobject]@{
                id = 'group-1'; displayName = 'Tier 0 Admins'
                members = @((New-TestUser 'tier0@lab.example'), (New-TestUser 'admin2@lab.example'))
            })

        $finding = Get-TestFinding $snapshot 'PRIV-001'

        $finding.Status | Should Be 'Pass'
        $finding.Observed | Should Match '^4 user\(s\) can hold Global Administrator: 2 with an active assignment, 1 eligible only through PIM, and 2 through role-assignable groups'

        $snapshot.Sources.GlobalAdminEligibility.Data += New-TestSchedule (New-TestUser 'jit2@lab.example') $null
        $finding = Get-TestFinding $snapshot 'PRIV-001'
        $finding.Status | Should Be 'Fail'
        ($finding.AffectedObjects -join ',') | Should Be 'admin1@lab.example,admin2@lab.example,jit@lab.example,jit2@lab.example,tier0@lab.example'
    }

    It 'warns when group members could not be expanded' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data += New-TestGroup 'group-1' 'Tier 0 Admins'
        $snapshot.Sources.GlobalAdminGroupMembers = New-TestSource $null -Status 'Failed' -ErrorMessage 'Forbidden'

        $finding = Get-TestFinding $snapshot 'PRIV-001'

        $finding.Status | Should Be 'Warn'
        $finding.AffectedObjects -contains 'group: Tier 0 Admins' | Should Be $true
    }

    It 'fails PRIV-002 and lists administrators without MFA registration' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails.Data += New-TestRegistration -Upn 'noreg.admin@lab.example' -IsAdmin $true -IsMfaRegistered $false -Methods @()

        $finding = Get-TestFinding $snapshot 'PRIV-002'

        $finding.Status | Should Be 'Fail'
        $finding.Observed | Should Be '1 of 3 administrator account(s) have not registered an MFA method.'
        $finding.AffectedObjects | Should Be 'noreg.admin@lab.example'
    }

    It 'warns on PRIV-003 for administrators without FIDO2, passkey, or Windows Hello methods' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails.Data += New-TestRegistration -Upn 'passkey.admin@lab.example' -IsAdmin $true -Methods @('passKeyDeviceBoundAuthenticator')
        (Get-TestFinding $snapshot 'PRIV-003').Status | Should Be 'Pass'

        $snapshot.Sources.UserRegistrationDetails.Data += New-TestRegistration -Upn 'sms.admin@lab.example' -IsAdmin $true -Methods @('mobilePhone', 'microsoftAuthenticatorPush')
        $finding = Get-TestFinding $snapshot 'PRIV-003'

        $finding.Status | Should Be 'Warn'
        $finding.AffectedObjects | Should Be 'sms.admin@lab.example'
    }

    It 'reports NotAssessed for admin checks when the report identifies no administrators' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails.Data = @(New-TestRegistration -Upn 'user@lab.example')

        (Get-TestFinding $snapshot 'PRIV-002').Status | Should Be 'NotAssessed'
        (Get-TestFinding $snapshot 'PRIV-003').Status | Should Be 'NotAssessed'
    }

    It 'warns on PRIV-004 for standing Global Administrator access outside emergency accounts' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdminAssignments.Data += New-TestSchedule (New-TestUser 'standing@lab.example') 'Assigned'
        $snapshot.Sources.GlobalAdminAssignments.Data += New-TestSchedule (New-TestUser 'activated@lab.example') 'Activated'

        $finding = Get-TestFinding $snapshot 'PRIV-004'

        $finding.Status | Should Be 'Warn'
        $finding.AffectedObjects | Should Be 'standing@lab.example'
        $finding.Observed | Should Match 'PIM eligibility is not used'
    }

    It 'expands groups with standing assignments and counts emergency accounts when none are configured' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdminAssignments.Data += New-TestSchedule (New-TestGroup 'group-1' 'Tier 0 Admins') 'Assigned'
        $snapshot.Sources.GlobalAdminGroupMembers.Data = @([pscustomobject]@{
                id = 'group-1'; displayName = 'Tier 0 Admins'; members = @(New-TestUser 'tier0@lab.example')
            })

        (Get-TestFinding $snapshot 'PRIV-004').AffectedObjects | Should Be 'tier0@lab.example'

        $finding = Get-TestFinding $snapshot 'PRIV-004' @{ Configuration = (New-TestConfiguration -Emergency @()) }
        $finding.AffectedCount | Should Be 3
        $finding.Observed | Should Match 'No emergency-access accounts are configured'
    }

    It 'reports NotAssessed for PRIV-005 when no emergency-access accounts are configured' {
        $finding = Get-TestFinding (New-TestSnapshot) 'PRIV-005' @{ Configuration = (New-TestConfiguration -Emergency @()) }

        $finding.Status | Should Be 'NotAssessed'
        $finding.Observed | Should Match 'EmergencyAccessAccounts'
    }

    It 'fails PRIV-005 when an emergency-access account does not hold Global Administrator' {
        $configuration = New-TestConfiguration -Emergency @('admin1@lab.example', 'missing@lab.example')

        $finding = Get-TestFinding (New-TestSnapshot) 'PRIV-005' @{ Configuration = $configuration }

        $finding.Status | Should Be 'Fail'
        $finding.AffectedObjects | Should Be 'missing@lab.example'
    }

    It 'warns on PRIV-005 when a policy could lock out every emergency-access account' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'Excludes one emergency account' -ExcludeUsers @('id-admin1@lab.example')
            New-TestPolicy -Name 'Admin roles, no exclusions' -IncludeUsers @() -IncludeRoles @($globalAdminRole)
            New-TestPolicy -Name 'Excludes a group' -ExcludeGroups @('group-bg')
            New-TestPolicy -Name 'Disabled' -State 'disabled'
        )

        $finding = Get-TestFinding $snapshot 'PRIV-005'

        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match "every emergency-access account: 'Admin roles, no exclusions'\."
        $finding.Observed | Should Match "'Excludes a group' exclude groups only"
    }

    It 'warns on PRIV-005 when policies exclude users who are not emergency-access accounts' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'Require MFA' -ExcludeUsers @('id-admin1@lab.example', 'id-user3@lab.example', 'GuestsOrExternalUsers')
        )

        $finding = Get-TestFinding $snapshot 'PRIV-005'

        $finding.Status | Should Be 'Warn'
        $finding.AffectedObjects | Should Be 'user3@lab.example'
        $finding.Observed | Should Match "'Require MFA' \(user3@lab.example\)"
    }

    It 'passes PRIV-005 when an emergency account is excluded from every policy that applies to it' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(
            New-TestPolicy -Name 'Require MFA' -ExcludeUsers @('id-admin2@lab.example')
            New-TestPolicy -Name 'Block legacy' -ClientAppTypes @('exchangeActiveSync', 'other') -Controls @('block') -ExcludeUsers @('id-admin1@lab.example')
        )

        (Get-TestFinding $snapshot 'PRIV-005').Status | Should Be 'Pass'
    }
}

Describe 'Member MFA registration coverage' {
    function New-CoverageSnapshot {
        param ([int] $Registered, [int] $Unregistered)
        $snapshot = New-TestSnapshot
        $records = @()
        $records += 1..$Registered | ForEach-Object { New-TestRegistration -Upn "reg$_@lab.example" }
        if ($Unregistered -gt 0) {
            $records += 1..$Unregistered | ForEach-Object { New-TestRegistration -Upn "unreg$_@lab.example" -IsMfaRegistered $false -Methods @() }
        }
        $records += New-TestRegistration -Upn 'guest#EXT#@lab.example' -UserType 'guest' -IsMfaRegistered $false -Methods @()
        $snapshot.Sources.UserRegistrationDetails.Data = $records
        $snapshot
    }

    It 'passes at exactly the target and excludes guests from the calculation' {
        $finding = Get-TestFinding (New-CoverageSnapshot -Registered 19 -Unregistered 1) 'ID-003'

        $finding.Status | Should Be 'Pass'
        $finding.Observed | Should Match '^19 of 20 member accounts \(95\.0%\)'
        $finding.AffectedObjects | Should Be 'unreg1@lab.example'
    }

    It 'does not round a value just below the target up to a pass' {
        # 1899 of 2000 is 94.95%, which displays as 95.0% but is still below target.
        (Get-TestFinding (New-CoverageSnapshot -Registered 1899 -Unregistered 101) 'ID-003').Status | Should Be 'Warn'
    }

    It 'warns between the minimum and target and fails below the minimum' {
        (Get-TestFinding (New-CoverageSnapshot -Registered 17 -Unregistered 3) 'ID-003').Status | Should Be 'Warn'
        (Get-TestFinding (New-CoverageSnapshot -Registered 15 -Unregistered 5) 'ID-003').Status | Should Be 'Fail'
        (Get-TestFinding (New-CoverageSnapshot -Registered 15 -Unregistered 5) 'ID-003' @{ MfaRegistrationMinimumPercent = 70 }).Status | Should Be 'Warn'
    }
}

Describe 'Application and external collaboration checks' {
    It 'grades user consent by permission grant policy and ignores owner consent policies' {
        $snapshot = New-TestSnapshot
        $permissions = $snapshot.Sources.AuthorizationPolicy.Data.defaultUserRolePermissions

        $permissions.permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team')
        (Get-TestFinding $snapshot 'APP-001').Status | Should Be 'Pass'

        $permissions.permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
        (Get-TestFinding $snapshot 'APP-001').Status | Should Be 'Warn'

        $permissions.permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        (Get-TestFinding $snapshot 'APP-001').Status | Should Be 'Fail'
    }

    It 'reports NotAssessed when consent settings are absent rather than assuming a pass' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.AuthorizationPolicy.Data.defaultUserRolePermissions.PSObject.Properties.Remove('permissionGrantPoliciesAssigned')

        (Get-TestFinding $snapshot 'APP-001').Status | Should Be 'NotAssessed'
    }

    It 'warns when users can register applications' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.AuthorizationPolicy.Data.defaultUserRolePermissions.allowedToCreateApps = $true

        (Get-TestFinding $snapshot 'APP-002').Status | Should Be 'Warn'
    }

    It 'maps guest invitation settings to Fail, Warn, and Pass' {
        $snapshot = New-TestSnapshot
        $expected = [ordered]@{
            everyone                         = 'Fail'
            adminsGuestInvitersAndAllMembers = 'Warn'
            adminsAndGuestInviters           = 'Pass'
            none                             = 'Pass'
            somethingNew                     = 'Warn'
        }
        foreach ($value in $expected.Keys) {
            $snapshot.Sources.AuthorizationPolicy.Data.allowInvitesFrom = $value
            (Get-TestFinding $snapshot 'COLLAB-001').Status | Should Be $expected[$value]
        }
    }

    It 'maps the guest user role to Fail, Warn, and Pass' {
        $snapshot = New-TestSnapshot
        $expected = [ordered]@{
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Fail'
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Warn'
            $restrictedGuestRole                   = 'Pass'
        }
        foreach ($value in $expected.Keys) {
            $snapshot.Sources.AuthorizationPolicy.Data.guestUserRoleId = $value
            (Get-TestFinding $snapshot 'COLLAB-002').Status | Should Be $expected[$value]
        }
    }
}

Describe 'Assessment configuration' {
    It 'loads the example configuration' {
        $configuration = Import-M365SecurityConfiguration -Path $sampleConfigurationPath

        $configuration.EmergencyAccessAccounts.Count | Should Be 2
        $configuration.AcceptedRisks.Count | Should Be 3
        $configuration.AcceptedRisks[0].Expires | Should Be ([datetime] '2027-03-31')
    }

    It 'lists every validation problem at once' {
        $path = Join-Path $TestDrive 'invalid.json'
        @{
            SchemaVersion = 1
            Thresholds    = @{ MaximumAdmins = 3; MfaRegistrationTargetPercent = 120 }
            AcceptedRisks = @(@{ CheckId = 'NOPE-1'; Reason = ''; Owner = 'x'; Expires = '31/12/2026' })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path

        try {
            $null = Import-M365SecurityConfiguration -Path $path
            $message = 'no error'
        }
        catch {
            $message = $_.Exception.Message
        }

        $message | Should Match "Unknown threshold 'MaximumAdmins'"
        $message | Should Match "'MfaRegistrationTargetPercent' must be a number from 0 to 100"
        $message | Should Match "unknown CheckId 'NOPE-1'"
        $message | Should Match 'Reason is required'
        $message | Should Match 'Expires is required in yyyy-MM-dd format'
    }

    It 'refuses a configuration written for a different tenant' {
        $configuration = New-TestConfiguration -TenantId 'another-tenant'

        { Get-M365SecurityFinding -Snapshot (New-TestSnapshot) -Configuration $configuration } |
            Should Throw "The configuration is for tenant 'another-tenant'"
    }

    It 'applies configured thresholds and lets explicit parameters override them' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data = @(1..6 | ForEach-Object { New-TestUser "ga$_@lab.example" })
        $configuration = New-TestConfiguration -Thresholds @{ MaximumGlobalAdmins = 6 }

        (Get-TestFinding $snapshot 'PRIV-001' @{ Configuration = $configuration }).Status | Should Be 'Pass'
        (Get-TestFinding $snapshot 'PRIV-001' @{ Configuration = $configuration; MaximumGlobalAdmins = 5 }).Status | Should Be 'Fail'
    }
}

Describe 'Accepted risks' {
    It 'marks a whole finding as Accepted and keeps the original status and reason' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.AuthorizationPolicy.Data.allowInvitesFrom = 'everyone'
        $configuration = New-TestConfiguration -AcceptedRisks @(New-TestRisk 'COLLAB-001')

        $finding = Get-TestFinding $snapshot 'COLLAB-001' @{ Configuration = $configuration }

        $finding.Status | Should Be 'Accepted'
        $finding.OriginalStatus | Should Be 'Fail'
        $finding.AcceptanceNote | Should Be 'Risk accepted by owner@lab.example until 2026-12-31, RISK-1: Test reason'
    }

    It 'accepts object-scoped risks only while every affected object is covered' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails.Data += New-TestRegistration -Upn 'otp.admin@lab.example' -IsAdmin $true -Methods @('softwareOneTimePasscode')
        $configuration = New-TestConfiguration -AcceptedRisks @(New-TestRisk 'PRIV-003' -AffectedObjects @('OTP.Admin@lab.example'))

        (Get-TestFinding $snapshot 'PRIV-003' @{ Configuration = $configuration }).Status | Should Be 'Accepted'

        $snapshot.Sources.UserRegistrationDetails.Data += New-TestRegistration -Upn 'new.admin@lab.example' -IsAdmin $true -Methods @('mobilePhone')
        $finding = Get-TestFinding $snapshot 'PRIV-003' @{ Configuration = $configuration }
        $finding.Status | Should Be 'Warn'
        $finding.AcceptanceNote | Should Match 'covers 1 of 2 affected object\(s\); not covered: new.admin@lab.example'
    }

    It 'stops applying a risk after its expiry date, judged by the snapshot collection date' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.AuthorizationPolicy.Data.allowInvitesFrom = 'everyone'
        $configuration = New-TestConfiguration -AcceptedRisks @(New-TestRisk 'COLLAB-001' -Expires '2026-01-01')

        $finding = Get-TestFinding $snapshot 'COLLAB-001' @{ Configuration = $configuration }
        $finding.Status | Should Be 'Fail'
        $finding.AcceptanceNote | Should Match 'expired on 2026-01-01'

        $snapshot.CollectedAtUtc = '2026-01-01T23:59:00Z'
        (Get-TestFinding $snapshot 'COLLAB-001' @{ Configuration = $configuration }).Status | Should Be 'Accepted'
    }

    It 'flags accepted risks that are no longer needed and ignores NotAssessed findings' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.UserRegistrationDetails = New-TestSource $null -Status 'Failed' -ErrorMessage 'Forbidden'
        $configuration = New-TestConfiguration -AcceptedRisks @((New-TestRisk 'COLLAB-001'), (New-TestRisk 'PRIV-002'))
        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot -Configuration $configuration)

        ($findings | Where-Object CheckId -EQ 'COLLAB-001').AcceptanceNote | Should Match 'no longer needed'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').Status | Should Be 'NotAssessed'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').AcceptanceNote | Should BeNullOrEmpty
    }
}

Describe 'Compare-M365SecuritySnapshot' {
    $configuration = Import-M365SecurityConfiguration -Path $sampleConfigurationPath
    $previous = Import-M365SecuritySnapshot -Path $previousSamplePath
    $current = Import-M365SecuritySnapshot -Path $samplePath

    It 'reports regressions, improvements, and configuration changes between the sample snapshots' {
        $changes = @(Compare-M365SecuritySnapshot -ReferenceSnapshot $previous -DifferenceSnapshot $current -Configuration $configuration)
        $summary = @($changes | ForEach-Object { "$($_.ChangeType)|$($_.Item)" })

        $summary -contains 'Regressed|ID-001 MFA is enforced for all users' | Should Be $true
        $summary -contains 'Regressed|PRIV-001 Global Administrator count is within range' | Should Be $true
        $summary -contains 'Improved|APP-002 Users cannot register applications' | Should Be $true
        $summary -contains 'Added|lerato.ops@lab.example.com' | Should Be $true
        $summary -contains 'Added|ops.contractor@lab.example.com' | Should Be $true

        $state = $changes | Where-Object { $_.Item -eq 'CA002 - Require MFA for all users' -and $_.Detail -eq 'Policy state changed.' }
        $state.Before | Should Be 'enabled'
        $state.After | Should Be 'enabledForReportingButNotEnforced'
        ($changes | Where-Object Item -EQ 'CA003 - Block legacy authentication').Detail | Should Be 'excludeUsers: added finance.reports@lab.example.com.'
        ($changes | Where-Object Item -EQ 'allowInvitesFrom').After | Should Be 'everyone'
        ($changes | Where-Object { $_.Category -eq 'Authentication methods' -and $_.Item -eq 'Voice' }).After | Should Be 'disabled'
        $changes[0].ChangeType | Should Be 'Regressed'
    }

    It 'reports no changes for identical snapshots' {
        @(Compare-M365SecuritySnapshot -ReferenceSnapshot $current -DifferenceSnapshot $current -Configuration $configuration).Count | Should Be 0
    }

    It 'reports added and removed policies and collection changes' {
        $before = New-TestSnapshot
        $after = New-TestSnapshot
        $before.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -Id 'p1' -Name 'Old policy')
        $after.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -Id 'p2' -Name 'New policy' -Controls @('block'))
        $after.Sources.UserRegistrationDetails = New-TestSource $null -Status 'Failed' -ErrorMessage 'Forbidden'

        $changes = @(Compare-M365SecuritySnapshot -ReferenceSnapshot $before -DifferenceSnapshot $after)

        ($changes | Where-Object Item -EQ 'New policy').ChangeType | Should Be 'Added'
        ($changes | Where-Object Item -EQ 'Old policy').ChangeType | Should Be 'Removed'
        $collection = $changes | Where-Object Category -EQ 'Collection'
        $collection.Item | Should Be 'UserRegistrationDetails'
        $collection.After | Should Be 'Failed'
    }

    It 'refuses to compare snapshots from different tenants' {
        $other = New-TestSnapshot
        $other.TenantId = 'another-tenant'

        { Compare-M365SecuritySnapshot -ReferenceSnapshot (New-TestSnapshot) -DifferenceSnapshot $other } |
            Should Throw 'Cannot compare snapshots from different tenants'
    }
}

Describe 'Get-M365SecuritySnapshot' {
    It 'follows paging, falls back when PIM expansion fails, expands admin groups, and keeps going after a failed source' {
        Mock Get-MgContext -ModuleName M365SecurityAssessment {
            [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'reader@lab.example'; Scopes = @() }
        }
        Mock Invoke-MgGraphRequest -ModuleName M365SecurityAssessment {
            switch -Wildcard ($Uri) {
                '*identitySecurityDefaultsEnforcementPolicy' { [pscustomobject]@{ isEnabled = $false }; break }
                'v1.0/identity/conditionalAccess/policies' {
                    [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Page 1' }); '@odata.nextLink' = 'https://graph.example/ca-page-2' }
                    break
                }
                '*ca-page-2' { [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Page 2' }) }; break }
                '*authorizationPolicy' { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'authorizationPolicy'; allowInvitesFrom = 'none' }) }; break }
                '*authenticationMethodsPolicy' { [pscustomobject]@{ policyMigrationState = 'migrationComplete'; authenticationMethodConfigurations = @() }; break }
                '*directoryRoles*' { [pscustomobject]@{ value = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Tier 0' }) }; break }
                '*roleAssignmentScheduleInstances*expand=principal' { throw 'Response status code does not indicate success: BadRequest (Bad Request).' }
                '*roleAssignmentScheduleInstances' {
                    [pscustomobject]@{ value = @(
                            [pscustomobject]@{ principalId = 'u1'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned' }
                            [pscustomobject]@{ principalId = 'u9'; roleDefinitionId = 'another-role'; assignmentType = 'Assigned' }
                        )
                    }
                    break
                }
                '*roleEligibilityScheduleInstances*' {
                    [pscustomobject]@{ value = @([pscustomobject]@{ principalId = 'g2'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = 'g2'; displayName = 'PIM Admins' } }) }
                    break
                }
                '*groups/g1/transitiveMembers*' { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'm1'; userPrincipalName = 'm1@lab.example' }) }; break }
                '*groups/g2/transitiveMembers*' { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'm2'; userPrincipalName = 'm2@lab.example' }) }; break }
                '*userRegistrationDetails' { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
                default { throw "Unexpected URI $Uri" }
            }
        }

        $snapshot = Get-M365SecuritySnapshot -WarningAction SilentlyContinue

        $snapshot.SchemaVersion | Should Be 1
        $snapshot.TenantId | Should Be 'tenant-1'
        @($snapshot.Sources.ConditionalAccessPolicies.Data).Count | Should Be 2
        $snapshot.Sources.AuthorizationPolicy.Data.allowInvitesFrom | Should Be 'none'
        $snapshot.Sources.GlobalAdminAssignments.Error | Should BeNullOrEmpty
        $snapshot.Sources.GlobalAdminAssignments.Status | Should Be 'Collected'
        (@($snapshot.Sources.GlobalAdminAssignments.Data).principalId -join ',') | Should Be 'u1'
        (@($snapshot.Sources.GlobalAdminGroupMembers.Data).id -join ',') | Should Be 'g1,g2'
        $snapshot.Sources.UserRegistrationDetails.Status | Should Be 'Failed'
        $snapshot.Sources.UserRegistrationDetails.Error | Should Match 'Forbidden'
        Assert-MockCalled Invoke-MgGraphRequest -ModuleName M365SecurityAssessment -Times 12 -Exactly
        Assert-MockCalled Invoke-MgGraphRequest -ModuleName M365SecurityAssessment -Times 1 -Exactly -ParameterFilter {
            $Uri -eq "v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal"
        }

        $finding = Get-TestFinding $snapshot 'PRIV-001' @{ Configuration = (New-TestConfiguration -Emergency @()) }
        $finding.Observed | Should Match '^2 user\(s\) can hold Global Administrator: 0 with an active assignment, 0 eligible only through PIM, and 2 through role-assignable groups'
        (Get-TestFinding $snapshot 'ID-003').Status | Should Be 'NotAssessed'
    }

    It 'records the Graph error code and message from the response body when PIM reads fail' {
        Mock Get-MgContext -ModuleName M365SecurityAssessment {
            [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'reader@lab.example'; Scopes = @() }
        }
        Mock Invoke-MgGraphRequest -ModuleName M365SecurityAssessment {
            if ($Uri -like '*ScheduleInstances*') {
                $record = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new('Response status code does not indicate success: BadRequest (Bad Request).'),
                    'GraphError', 'InvalidOperation', $null)
                $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AadPremiumLicenseRequired","message":"The tenant needs a Microsoft Entra ID P2 license."}}')
                throw $record
            }
            [pscustomobject]@{ value = @() }
        }

        $snapshot = Get-M365SecuritySnapshot -WarningAction SilentlyContinue
        $source = $snapshot.Sources.GlobalAdminEligibility

        $source.Status | Should Be 'Failed'
        $source.Error | Should Match '^With principal expansion: .*Graph error AadPremiumLicenseRequired: The tenant needs a Microsoft Entra ID P2 license\. Without: '
        (Get-TestFinding $snapshot 'PRIV-004').Observed | Should Match 'AadPremiumLicenseRequired'
    }

    It 'stops with a clear message when Graph is not connected' {
        Mock Get-MgContext -ModuleName M365SecurityAssessment { $null }

        { Get-M365SecuritySnapshot } | Should Throw 'Not connected to Microsoft Graph'
    }
}

Describe 'Snapshot files and reports' {
    It 'round-trips a snapshot through JSON with the same findings' {
        $path = Join-Path $TestDrive 'snapshots/snapshot.json'
        $snapshot = Import-M365SecuritySnapshot -Path $samplePath

        $null = Export-M365SecuritySnapshot -Snapshot $snapshot -Path $path
        $reloaded = Import-M365SecuritySnapshot -Path $path

        (@(Get-M365SecurityFinding -Snapshot $reloaded).Status -join ',') |
            Should Be (@(Get-M365SecurityFinding -Snapshot $snapshot).Status -join ',')
    }

    It 'writes CSV, JSON, HTML, and drift reports with acceptance details' {
        $configuration = Import-M365SecurityConfiguration -Path $sampleConfigurationPath
        $snapshot = Import-M365SecuritySnapshot -Path $samplePath
        $previous = Import-M365SecuritySnapshot -Path $previousSamplePath
        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot -Configuration $configuration)
        $drift = @(Compare-M365SecuritySnapshot -ReferenceSnapshot $previous -DifferenceSnapshot $snapshot -Configuration $configuration)
        $directory = Join-Path $TestDrive 'reports'

        $files = @(Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -Drift $drift -ReferenceSnapshot $previous -OutputDirectory $directory)
        $csv = @(Import-Csv -LiteralPath (Join-Path $directory 'M365-Security-Assessment-20261007-083000.csv'))
        $driftCsv = @(Import-Csv -LiteralPath (Join-Path $directory 'M365-Security-Assessment-Drift-20261007-083000.csv'))
        $json = Get-Content -LiteralPath (Join-Path $directory 'M365-Security-Assessment-20261007-083000.json') -Raw | ConvertFrom-Json
        $html = Get-Content -LiteralPath (Join-Path $directory 'M365-Security-Assessment-20261007-083000.html') -Raw

        $files.Count | Should Be 4
        $csv.Count | Should Be 14
        $accepted = $csv | Where-Object CheckId -EQ 'COLLAB-002'
        $accepted.Status | Should Be 'Accepted'
        $accepted.OriginalStatus | Should Be 'Warn'
        $accepted.BaselineControls | Should Be 'CISA MS.AAD.8.1v1'
        ($csv | Where-Object CheckId -EQ 'PRIV-003').AffectedObjects |
            Should Be 'thandi.admin@lab.example.com; lerato.ops@lab.example.com; helpdesk.lead@lab.example.com'
        $driftCsv.Count | Should Be $drift.Count
        $driftCsv[0].ReferenceCollectedAtUtc | Should Match '^2026-09-07T08:30:00'
        $json.Summary.Accepted | Should Be 1
        @($json.Drift).Count | Should Be $drift.Count
        $html | Should Match 'Changes since 2026-09-07 08:30 UTC'
        $html | Should Match '<span class="badge accepted">Accepted</span>'
    }

    It 'HTML-encodes tenant-supplied names in the report' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data = @(1..4 | ForEach-Object { New-TestUser "ga$_@lab.example" }) + [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.user'
            displayName   = '<script>alert(1)</script>'
        }
        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot)

        $file = Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -OutputDirectory $TestDrive -Format Html
        $html = Get-Content -LiteralPath $file.FullName -Raw

        $html | Should Not Match '<script>alert'
        $html | Should Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'writes a header-only CSV when there are no findings' {
        $file = Export-M365SecurityReport -Finding @() -Snapshot (New-TestSnapshot) -OutputDirectory $TestDrive -Format Csv
        $lines = @(Get-Content -LiteralPath $file.FullName)

        $lines.Count | Should Be 1
        $lines[0] | Should Match '^TenantId,CollectedAtUtc,CheckId,'
    }
}

Describe 'Invoke-M365SecurityAssessment.ps1' {
    $pwsh = Join-Path $PSHOME 'pwsh'

    It 'exits with code 1 when a check at or above -FailOnSeverity fails' {
        & $pwsh -NoProfile -File $scriptPath -SnapshotPath $samplePath -OutputDirectory (Join-Path $TestDrive 'fail') -Format Json -FailOnSeverity High *> $null

        $LASTEXITCODE | Should Be 1
    }

    It 'exits with code 0 when no failed check reaches the threshold' {
        $passing = Join-Path $TestDrive 'passing.json'
        $null = Export-M365SecuritySnapshot -Snapshot (New-TestSnapshot) -Path $passing

        & $pwsh -NoProfile -File $scriptPath -SnapshotPath $passing -OutputDirectory (Join-Path $TestDrive 'pass') -Format Json -FailOnSeverity Low *> $null

        $LASTEXITCODE | Should Be 0
    }
}

Remove-Item -Path 'function:global:Get-MgContext', 'function:global:Invoke-MgGraphRequest' -ErrorAction SilentlyContinue
