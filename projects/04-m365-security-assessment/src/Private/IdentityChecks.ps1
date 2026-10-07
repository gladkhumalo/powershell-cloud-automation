function Get-CoverageStatus {
    param (
        [Parameter(Mandatory)] [double] $Percent,
        [Parameter(Mandatory)] [double] $Target,
        [Parameter(Mandatory)] [double] $Minimum
    )

    # Compare the exact ratio; only the displayed value is rounded.
    if ($Percent -ge $Target) { 'Pass' } elseif ($Percent -ge $Minimum) { 'Warn' } else { 'Fail' }
}

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
                    (Test-PolicyEnabled $_) -and
                    (Test-PolicyRequiresMfa $_) -and
                    @(Get-PolicyUserCondition -Policy $_ -Name includeRoles).Count -gt 0 -and
                    -not ((Get-PolicyUserCondition -Policy $_ -Name includeUsers) -contains 'All')
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
        [Parameter(Mandatory)] [object] $Thresholds
    )

    $checkId = 'ID-003'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'UserRegistrationDetails'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $members = @(Get-SourceItem -Source $source | Where-Object { (Get-PropertyValue $_ 'userType') -eq 'member' })
    if ($members.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report contained no member accounts.'
    }

    $unregistered = @($members | Where-Object { (Get-PropertyValue $_ 'isMfaRegistered') -ne $true })
    $registeredCount = $members.Count - $unregistered.Count
    $percent = 100 * $registeredCount / $members.Count
    $status = Get-CoverageStatus -Percent $percent -Target $Thresholds.MfaRegistrationTargetPercent -Minimum $Thresholds.MfaRegistrationMinimumPercent
    $observed = Format-Invariant '{0} of {1} member accounts ({2:0.0}%) are registered for MFA. Target {3}%, minimum {4}%.' @(
        $registeredCount, $members.Count, $percent, $Thresholds.MfaRegistrationTargetPercent, $Thresholds.MfaRegistrationMinimumPercent
    )
    New-SecurityFinding -CheckId $checkId -Status $status -Observed $observed -AffectedObjects @($unregistered | ForEach-Object { Format-UserRecord $_ })
}

function Test-WeakAuthenticationMethod {
    param ([Parameter(Mandatory)] [object] $Snapshot)

    $checkId = 'ID-004'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'AuthenticationMethodsPolicy'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    $configurations = @(Get-PropertyValue $source.Data 'authenticationMethodConfigurations' | Where-Object { $_ })
    if ($configurations.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The authentication methods policy did not include method configurations.'
    }

    $weakMethods = [ordered]@{ Sms = 'SMS'; Voice = 'voice call'; Email = 'email one-time passcode' }
    $enabled = @(foreach ($methodId in $weakMethods.Keys) {
            $configuration = $configurations | Where-Object { (Get-PropertyValue $_ 'id') -eq $methodId } | Select-Object -First 1
            if ($configuration -and (Get-PropertyValue $configuration 'state') -eq 'enabled') {
                $methodId
            }
        })

    $notes = [System.Collections.Generic.List[string]]::new()
    if ($enabled.Count -gt 0) {
        $notes.Add("Enabled in the authentication methods policy: $(@($enabled | ForEach-Object { $weakMethods[$_] }) -join ', ').")
    }
    $migration = [string] (Get-PropertyValue $source.Data 'policyMigrationState')
    if ($migration -and $migration -ne 'migrationComplete') {
        $notes.Add("The authentication methods migration state is '$migration', so the legacy MFA and SSPR policies can still allow other methods.")
    }

    if ($notes.Count -gt 0) {
        return New-SecurityFinding -CheckId $checkId -Status Warn -Observed ($notes -join ' ') -AffectedObjects $enabled
    }
    $observed = 'SMS, voice call, and email one-time passcode are disabled in the authentication methods policy.'
    if ($migration) {
        $observed += ' The authentication methods migration is complete.'
    }
    New-SecurityFinding -CheckId $checkId -Status Pass -Observed $observed
}

function Test-SelfServicePasswordReset {
    param (
        [Parameter(Mandatory)] [object] $Snapshot,
        [Parameter(Mandatory)] [object] $Thresholds
    )

    $checkId = 'ID-005'
    $source = Get-SnapshotSource -Snapshot $Snapshot -Name 'UserRegistrationDetails'
    if (-not (Test-SourceCollected $source)) {
        return New-NotAssessedFinding -CheckId $checkId -Source $source
    }

    # Administrators always have SSPR through the separate admin policy, so only non-admin members count.
    $members = @(Get-SourceItem -Source $source | Where-Object {
            (Get-PropertyValue $_ 'userType') -eq 'member' -and (Get-PropertyValue $_ 'isAdmin') -ne $true
        })
    if ($members.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report contained no non-admin member accounts.'
    }
    if (-not ($members | Where-Object { Test-PropertyPresent -InputObject $_ -Name 'isSsprEnabled' })) {
        return New-SecurityFinding -CheckId $checkId -Status NotAssessed -Observed 'The registration report does not include self-service password reset fields (isSsprEnabled, isSsprRegistered).'
    }

    $enabled = @($members | Where-Object { (Get-PropertyValue $_ 'isSsprEnabled') -eq $true })
    if ($enabled.Count -eq 0) {
        return New-SecurityFinding -CheckId $checkId -Status Warn -Observed "Self-service password reset is not enabled for any of the $($members.Count) non-admin member accounts."
    }

    $unregistered = @($enabled | Where-Object { (Get-PropertyValue $_ 'isSsprRegistered') -ne $true })
    $registeredCount = $enabled.Count - $unregistered.Count
    $percent = 100 * $registeredCount / $enabled.Count
    $status = Get-CoverageStatus -Percent $percent -Target $Thresholds.MfaRegistrationTargetPercent -Minimum $Thresholds.MfaRegistrationMinimumPercent
    $observed = Format-Invariant '{0} of {1} SSPR-enabled member accounts ({2:0.0}%) are registered for self-service password reset. Target {3}%, minimum {4}%.' @(
        $registeredCount, $enabled.Count, $percent, $Thresholds.MfaRegistrationTargetPercent, $Thresholds.MfaRegistrationMinimumPercent
    )

    $notEnabled = $members.Count - $enabled.Count
    if ($notEnabled -gt 0) {
        $observed += " $notEnabled non-admin member account(s) are not enabled for SSPR."
        if ($status -eq 'Pass') {
            $status = 'Warn'
        }
    }
    New-SecurityFinding -CheckId $checkId -Status $status -Observed $observed -AffectedObjects @($unregistered | ForEach-Object { Format-UserRecord $_ })
}
