function Test-PolicyIsTenantWide {
    param ([Parameter(Mandatory)] [object] $Policy)

    (@(Get-PropertyValue $Policy 'conditions', 'users', 'includeUsers') -contains 'All') -and
    (@(Get-PropertyValue $Policy 'conditions', 'applications', 'includeApplications') -contains 'All')
}

function Test-PolicyEnabled {
    param ([Parameter(Mandatory)] [object] $Policy)

    (Get-PropertyValue $Policy 'state') -eq 'enabled'
}

function Test-PolicyRequiresMfa {
    param ([Parameter(Mandatory)] [object] $Policy)

    (@(Get-PropertyValue $Policy 'grantControls', 'builtInControls') -contains 'mfa') -or
    ($null -ne (Get-PropertyValue $Policy 'grantControls', 'authenticationStrength'))
}

function Test-PolicyHasGrantControl {
    param ([Parameter(Mandatory)] [object] $Policy)

    @(Get-PropertyValue $Policy 'grantControls', 'builtInControls' | Where-Object { $_ }).Count -gt 0 -or
    ($null -ne (Get-PropertyValue $Policy 'grantControls', 'authenticationStrength'))
}

function Test-PolicyBlocksLegacyAuthentication {
    param ([Parameter(Mandatory)] [object] $Policy)

    $clientApps = @(Get-PropertyValue $Policy 'conditions', 'clientAppTypes')
    ($clientApps -contains 'exchangeActiveSync') -and
    ($clientApps -contains 'other') -and
    (@(Get-PropertyValue $Policy 'grantControls', 'builtInControls') -contains 'block')
}

function Get-PolicyUserCondition {
    param (
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [ValidateSet('includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles')] [string] $Name
    )

    @(Get-PropertyValue $Policy 'conditions', 'users', $Name | Where-Object { $_ })
}

function Format-PolicyName {
    param ([Parameter(Mandatory)] [object] $Policy)

    "'$(Get-PropertyValue $Policy 'displayName')'"
}

function Format-PolicyExclusion {
    param ([Parameter(Mandatory)] [object] $Policy)

    $parts = foreach ($kind in @('User', 'Group', 'Role')) {
        $count = @(Get-PolicyUserCondition -Policy $Policy -Name "exclude${kind}s").Count
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

    if ((Test-SourceCollected $defaults) -and (Get-PropertyValue $defaults.Data 'isEnabled') -eq $true) {
        return New-SecurityFinding -CheckId $CheckId -Status Pass -Observed $DefaultsObservation
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    $turnedOff = [System.Collections.Generic.List[string]]::new()
    if (Test-SourceCollected $conditionalAccess) {
        $policies = @(Get-SourceItem -Source $conditionalAccess)
        $matching = @($policies | Where-Object { & $Predicate $_ })
        $enabled = @($matching | Where-Object { Test-PolicyEnabled $_ })
        $reportOnly = @($matching | Where-Object { (Get-PropertyValue $_ 'state') -eq 'enabledForReportingButNotEnforced' })

        if ($enabled.Count -gt 0) {
            $policy = $enabled[0]
            $observed = Format-Invariant $PolicyObservation @((Format-PolicyName $policy), (Format-PolicyExclusion $policy))
            return New-SecurityFinding -CheckId $CheckId -Status Pass -Observed $observed
        }
        # A matching policy that is switched off doesn't change the status, but it is the quickest fix.
        foreach ($policy in @($matching | Where-Object { (Get-PropertyValue $_ 'state') -eq 'disabled' })) {
            $turnedOff.Add("Policy $(Format-PolicyName $policy) would meet this check but is turned off.")
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

    $failed = @($defaults, $conditionalAccess | Where-Object { -not (Test-SourceCollected $_) })
    if ($failed.Count -gt 0) {
        $observed = (@(Format-SourceError -Source $failed) + $notes + $turnedOff) -join ' '
        return New-SecurityFinding -CheckId $CheckId -Status NotAssessed -Observed $observed
    }
    if ($notes.Count -gt 0) {
        return New-SecurityFinding -CheckId $CheckId -Status Warn -Observed ((@($notes) + $turnedOff) -join ' ')
    }
    New-SecurityFinding -CheckId $CheckId -Status Fail -Observed ((@($FailObservation) + $turnedOff) -join ' ')
}
