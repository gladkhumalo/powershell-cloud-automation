function Get-M365SecurityFinding {
    <#
    .SYNOPSIS
    Evaluates a tenant snapshot against the security checks and returns one finding per check.
    .DESCRIPTION
    Pure evaluation: no Graph calls are made, so the same snapshot and configuration always produce
    the same findings. Accepted risks are applied as of the snapshot's collection date. Findings are
    sorted by status (Fail, Warn, NotAssessed, Accepted, Pass) and then severity.
    .EXAMPLE
    Get-M365SecuritySnapshot | Get-M365SecurityFinding | Format-Table Status, Severity, CheckId, Title
    .EXAMPLE
    $snapshot | Get-M365SecurityFinding -Configuration (Import-M365SecurityConfiguration ./config/tenant.json)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)] [object] $Snapshot,

        [AllowNull()] [object] $Configuration,

        [ValidateRange(0, 100)] [int] $MinimumGlobalAdmins,
        [ValidateRange(1, 100)] [int] $MaximumGlobalAdmins,
        [ValidateRange(0, 100)] [double] $MfaRegistrationTargetPercent,
        [ValidateRange(0, 100)] [double] $MfaRegistrationMinimumPercent
    )

    process {
        Assert-SnapshotSchema -Snapshot $Snapshot
        $config = ConvertTo-SecurityConfiguration -InputObject $Configuration

        $snapshotTenant = [string] (Get-PropertyValue $Snapshot 'TenantId')
        if ($config.TenantId -and $snapshotTenant -and $config.TenantId -ne $snapshotTenant) {
            throw "The configuration is for tenant '$($config.TenantId)' but the snapshot is for tenant '$snapshotTenant'."
        }

        $overrides = @{}
        foreach ($name in $script:DefaultThresholds.Keys) {
            if ($PSBoundParameters.ContainsKey($name)) {
                $overrides[$name] = $PSBoundParameters[$name]
            }
        }
        $thresholds = Resolve-AssessmentThreshold -Configuration $config -Override $overrides

        $context = [pscustomobject]@{
            Thresholds              = $thresholds
            EmergencyAccessAccounts = @($config.EmergencyAccessAccounts)
            IdentityMap             = Get-DirectoryIdentityMap -Snapshot $Snapshot
        }

        $findings = @(
            Test-BaselineMfa -Snapshot $Snapshot
            Test-LegacyAuthenticationBlocked -Snapshot $Snapshot
            Test-MemberMfaRegistration -Snapshot $Snapshot -Thresholds $thresholds
            Test-WeakAuthenticationMethod -Snapshot $Snapshot
            Test-SelfServicePasswordReset -Snapshot $Snapshot -Thresholds $thresholds
            Test-GlobalAdministratorCount -Snapshot $Snapshot -Context $context
            Test-AdministratorMfaRegistration -Snapshot $Snapshot
            Test-AdministratorPhishingResistantMethod -Snapshot $Snapshot
            Test-StandingGlobalAdministrator -Snapshot $Snapshot -Context $context
            Test-EmergencyAccess -Snapshot $Snapshot -Context $context
            Test-UserConsentRestricted -Snapshot $Snapshot
            Test-UserAppRegistration -Snapshot $Snapshot
            Test-GuestInvitation -Snapshot $Snapshot
            Test-GuestDirectoryAccess -Snapshot $Snapshot
        )

        if ($config.AcceptedRisks.Count -gt 0) {
            $findings = @(Resolve-AcceptedRisk -Finding $findings -AcceptedRisk $config.AcceptedRisks -AsOf (Get-SnapshotTimestamp -Snapshot $Snapshot))
        }

        $findings | Sort-Object `
            @{ Expression = { $script:StatusRank[$_.Status] } },
            @{ Expression = { $script:SeverityRank[$_.Severity] } },
            @{ Expression = { $script:CheckRank[$_.CheckId] } }
    }
}
