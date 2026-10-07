$modulePath = Join-Path $PSScriptRoot '../src/M365SecurityAssessment.psd1'
$samplePath = Join-Path $PSScriptRoot '../examples/sample-tenant-snapshot.json'
Import-Module $modulePath -Force

# Stand-ins so the Graph cmdlets can be mocked on machines without the Graph SDK (such as CI).
function global:Get-MgContext { [CmdletBinding()] param () }
function global:Invoke-MgGraphRequest {
    [CmdletBinding()]
    param ([string] $Method, [string] $Uri, [string] $OutputType)
}

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
        [string[]] $Methods = @('microsoftAuthenticatorPush')
    )
    [pscustomobject]@{
        id                = [guid]::NewGuid().ToString()
        userPrincipalName = $Upn
        userType          = $UserType
        isAdmin           = $IsAdmin
        isMfaRegistered   = $IsMfaRegistered
        methodsRegistered = $Methods
    }
}

function New-TestPolicy {
    param (
        [string] $Name = 'Test policy',
        [string] $State = 'enabled',
        [string[]] $IncludeUsers = @('All'),
        [string[]] $IncludeRoles = @(),
        [string[]] $ExcludeUsers = @(),
        [string[]] $ClientAppTypes = @('all'),
        [string[]] $Controls = @('mfa'),
        [object] $AuthenticationStrength = $null
    )
    [pscustomobject]@{
        displayName   = $Name
        state         = $State
        conditions    = [pscustomobject]@{
            clientAppTypes = $ClientAppTypes
            applications   = [pscustomobject]@{ includeApplications = @('All') }
            users          = [pscustomobject]@{
                includeUsers  = $IncludeUsers
                excludeUsers  = $ExcludeUsers
                excludeGroups = @()
                includeRoles  = $IncludeRoles
                excludeRoles  = @()
            }
        }
        grantControls = [pscustomobject]@{ builtInControls = $Controls; authenticationStrength = $AuthenticationStrength }
    }
}

function New-TestSnapshot {
    # A tenant that passes every check. Tests change one setting at a time.
    $registrations = @(
        New-TestRegistration -Upn 'admin1@lab.example' -IsAdmin $true -Methods @('fido2')
        New-TestRegistration -Upn 'admin2@lab.example' -IsAdmin $true -Methods @('windowsHelloForBusiness')
    )
    $registrations += 1..18 | ForEach-Object { New-TestRegistration -Upn "user$_@lab.example" }

    [pscustomobject]@{
        SchemaVersion  = 1
        TenantId       = '00000000-0000-4000-8000-000000000000'
        CollectedBy    = 'reader@lab.example'
        CollectedAtUtc = '2026-01-02T03:04:05.0000000Z'
        Sources        = [pscustomobject]@{
            SecurityDefaults          = New-TestSource ([pscustomobject]@{ isEnabled = $true })
            ConditionalAccessPolicies = New-TestSource @()
            AuthorizationPolicy       = New-TestSource ([pscustomobject]@{
                    allowInvitesFrom           = 'adminsAndGuestInviters'
                    guestUserRoleId            = $restrictedGuestRole
                    defaultUserRolePermissions = [pscustomobject]@{
                        allowedToCreateApps             = $false
                        permissionGrantPoliciesAssigned = @()
                    }
                })
            GlobalAdministrators      = New-TestSource @(
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin 1'; userPrincipalName = 'admin1@lab.example' }
                [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin 2'; userPrincipalName = 'admin2@lab.example' }
            )
            UserRegistrationDetails   = New-TestSource $registrations
        }
    }
}

function New-TestGlobalAdmin {
    param ([int] $Count)
    @(1..$Count | ForEach-Object {
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; displayName = "Admin $_"; userPrincipalName = "ga$_@lab.example" }
        })
}

function Get-TestFinding {
    param ([object] $Snapshot, [string] $CheckId, [hashtable] $Option = @{})
    Get-M365SecurityFinding -Snapshot $Snapshot @Option | Where-Object CheckId -EQ $CheckId
}

function Disable-SecurityDefault {
    param ([object] $Snapshot)
    $Snapshot.Sources.SecurityDefaults.Data.isEnabled = $false
}

Describe 'Get-M365SecurityFinding' {
    It 'returns one finding for each of the ten checks and passes a well-configured tenant' {
        $findings = @(Get-M365SecurityFinding -Snapshot (New-TestSnapshot))

        $findings.Count | Should Be 10
        @($findings | Where-Object Status -NE 'Pass').Count | Should Be 0
        @($findings.CheckId | Select-Object -Unique).Count | Should Be 10
    }

    It 'evaluates the fictional sample tenant and sorts failures first by severity' {
        $findings = @(Import-M365SecuritySnapshot -Path $samplePath | Get-M365SecurityFinding)
        $status = @{}
        $findings | ForEach-Object { $status[$_.CheckId] = $_.Status }

        ($findings.CheckId -join ',') | Should Be 'PRIV-001,PRIV-002,COLLAB-001,ID-001,APP-001,ID-003,PRIV-003,COLLAB-002,ID-002,APP-002'
        $status['PRIV-001'] | Should Be 'Fail'
        $status['PRIV-002'] | Should Be 'Fail'
        $status['COLLAB-001'] | Should Be 'Fail'
        $status['ID-001'] | Should Be 'Warn'
        $status['ID-002'] | Should Be 'Pass'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').AffectedObjects | Should Be 'lerato.ops@lab.example.com'
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

        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot)
        $notAssessed = @($findings | Where-Object Status -EQ 'NotAssessed' | ForEach-Object CheckId | Sort-Object)

        ($notAssessed -join ',') | Should Be 'APP-001,APP-002,COLLAB-001,COLLAB-002,ID-003,PRIV-002,PRIV-003'
        ($findings | Where-Object CheckId -EQ 'PRIV-002').Observed | Should Match 'UserRegistrationDetails.*Forbidden'
    }
}

Describe 'Baseline MFA and legacy authentication checks' {
    It 'passes ID-001 when an enabled policy requires MFA for all users and notes exclusions' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -Name 'Require MFA' -ExcludeUsers @('bg1', 'bg2'))

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
            New-TestPolicy -Name 'Admin MFA' -IncludeUsers @() -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10')
        )

        $finding = Get-TestFinding $snapshot 'ID-001'

        $finding.Status | Should Be 'Warn'
        $finding.Observed | Should Match 'report-only'
        $finding.Observed | Should Match 'selected directory roles only'
    }

    It 'fails ID-001 when no defaults or enabled policy enforce MFA, ignoring disabled policies' {
        $snapshot = New-TestSnapshot
        Disable-SecurityDefault $snapshot
        $snapshot.Sources.ConditionalAccessPolicies.Data = @(New-TestPolicy -State 'disabled')

        (Get-TestFinding $snapshot 'ID-001').Status | Should Be 'Fail'
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

Describe 'Privileged access checks' {
    It 'grades the Global Administrator count against the configured range' {
        $snapshot = New-TestSnapshot

        $snapshot.Sources.GlobalAdministrators.Data = New-TestGlobalAdmin 1
        (Get-TestFinding $snapshot 'PRIV-001').Status | Should Be 'Warn'

        $snapshot.Sources.GlobalAdministrators.Data = New-TestGlobalAdmin 4
        $finding = Get-TestFinding $snapshot 'PRIV-001'
        $finding.Status | Should Be 'Pass'
        $finding.AffectedCount | Should Be 0

        $snapshot.Sources.GlobalAdministrators.Data = New-TestGlobalAdmin 5
        $finding = Get-TestFinding $snapshot 'PRIV-001'
        $finding.Status | Should Be 'Fail'
        $finding.AffectedCount | Should Be 5

        (Get-TestFinding $snapshot 'PRIV-001' @{ MaximumGlobalAdmins = 6 }).Status | Should Be 'Pass'
    }

    It 'warns when a group holds Global Administrator because its members are not counted' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data = @(New-TestGlobalAdmin 2) + [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.group'
            displayName   = 'Tier 0 Admins'
        }

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
        # 949 of 1000 is 94.9%; 1899 of 2000 is 94.95%, which displays as 95.0% but is still below target.
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

Describe 'Get-M365SecuritySnapshot' {
    It 'follows paging, unwraps the authorization policy, and keeps going after a failed source' {
        Mock Get-MgContext -ModuleName M365SecurityAssessment {
            [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'reader@lab.example'; Scopes = @() }
        }
        Mock Invoke-MgGraphRequest -ModuleName M365SecurityAssessment {
            switch -Wildcard ($Uri) {
                '*identitySecurityDefaultsEnforcementPolicy' { [pscustomobject]@{ isEnabled = $false } }
                'v1.0/identity/conditionalAccess/policies' {
                    [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Page 1' }); '@odata.nextLink' = 'https://graph.example/ca-page-2' }
                }
                '*ca-page-2' { [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Page 2' }) } }
                '*authorizationPolicy' { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'authorizationPolicy'; allowInvitesFrom = 'none' }) } }
                '*directoryRoles*' { [pscustomobject]@{ value = @() } }
                '*userRegistrationDetails' { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
                default { throw "Unexpected URI $Uri" }
            }
        }

        $snapshot = Get-M365SecuritySnapshot -WarningAction SilentlyContinue

        $snapshot.SchemaVersion | Should Be 1
        $snapshot.TenantId | Should Be 'tenant-1'
        $snapshot.Sources.ConditionalAccessPolicies.Status | Should Be 'Collected'
        @($snapshot.Sources.ConditionalAccessPolicies.Data).Count | Should Be 2
        $snapshot.Sources.AuthorizationPolicy.Data.allowInvitesFrom | Should Be 'none'
        $snapshot.Sources.GlobalAdministrators.Status | Should Be 'Collected'
        $snapshot.Sources.UserRegistrationDetails.Status | Should Be 'Failed'
        $snapshot.Sources.UserRegistrationDetails.Error | Should Match 'Forbidden'
        Assert-MockCalled Invoke-MgGraphRequest -ModuleName M365SecurityAssessment -Times 6 -Exactly
        Assert-MockCalled Invoke-MgGraphRequest -ModuleName M365SecurityAssessment -Times 1 -Exactly -ParameterFilter {
            $Uri -like "*directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members*"
        }

        (Get-TestFinding $snapshot 'ID-003').Status | Should Be 'NotAssessed'
        (Get-TestFinding $snapshot 'COLLAB-001').Status | Should Be 'Pass'
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

    It 'writes timestamped CSV, JSON, and HTML reports' {
        $snapshot = Import-M365SecuritySnapshot -Path $samplePath
        $findings = @(Get-M365SecurityFinding -Snapshot $snapshot)
        $directory = Join-Path $TestDrive 'reports'

        $files = @(Export-M365SecurityReport -Finding $findings -Snapshot $snapshot -OutputDirectory $directory)
        $csv = @(Import-Csv -LiteralPath ($files | Where-Object Extension -EQ '.csv').FullName)
        $json = Get-Content -LiteralPath ($files | Where-Object Extension -EQ '.json').FullName -Raw | ConvertFrom-Json

        ($files.Name | Sort-Object) -join ',' |
            Should Be 'M365-Security-Assessment-20261007-083000.csv,M365-Security-Assessment-20261007-083000.html,M365-Security-Assessment-20261007-083000.json'
        $csv.Count | Should Be 10
        $csv[0].TenantId | Should Be '8a7b6c5d-0000-4e1f-9a2b-3c4d5e6f7a8b'
        ($csv | Where-Object CheckId -EQ 'PRIV-003').AffectedObjects |
            Should Be 'thandi.admin@lab.example.com; lerato.ops@lab.example.com; helpdesk.lead@lab.example.com'
        $json.Summary.Fail | Should Be 3
        $json.Summary.Pass | Should Be 2
        @($json.Findings).Count | Should Be 10
    }

    It 'HTML-encodes tenant-supplied names in the report' {
        $snapshot = New-TestSnapshot
        $snapshot.Sources.GlobalAdministrators.Data = @(New-TestGlobalAdmin 4) + [pscustomobject]@{
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

Remove-Item -Path 'function:global:Get-MgContext', 'function:global:Invoke-MgGraphRequest' -ErrorAction SilentlyContinue
