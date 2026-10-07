function Get-ObjectProperty {
    # Enumerates name/value pairs from a hashtable or an object.
    param ([AllowNull()] [object] $InputObject)

    if ($null -eq $InputObject) {
        return
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            [pscustomobject]@{ Name = [string] $key; Value = $InputObject[$key] }
        }
        return
    }
    foreach ($property in $InputObject.PSObject.Properties) {
        [pscustomobject]@{ Name = $property.Name; Value = $property.Value }
    }
}

function ConvertTo-ExpiryDate {
    param ([AllowNull()] [object] $Value)

    if ($Value -is [datetime]) {
        return $Value.Date
    }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact([string] $Value, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref] $parsed)) {
        return $parsed
    }
    return $null
}

function ConvertTo-SecurityConfiguration {
    # Validates and normalizes assessment configuration. Safe to call on an already-normalized object.
    param ([AllowNull()] [object] $InputObject)

    if ($null -eq $InputObject) {
        return [pscustomobject]@{
            SchemaVersion           = $script:ConfigurationSchemaVersion
            TenantId                = $null
            EmergencyAccessAccounts = [string[]] @()
            Thresholds              = [pscustomobject]@{}
            AcceptedRisks           = @()
        }
    }

    $version = Get-PropertyValue $InputObject 'SchemaVersion'
    if ($version -ne $script:ConfigurationSchemaVersion) {
        throw "Unsupported configuration schema version '$version'. This tool reads version $($script:ConfigurationSchemaVersion)."
    }

    $problems = [System.Collections.Generic.List[string]]::new()
    $tenantId = [string] (Get-PropertyValue $InputObject 'TenantId')
    $emergency = [string[]] @(Get-PropertyValue $InputObject 'EmergencyAccessAccounts' | Where-Object { $_ } | ForEach-Object { ([string] $_).Trim() })

    $thresholds = [ordered]@{}
    foreach ($item in @(Get-ObjectProperty (Get-PropertyValue $InputObject 'Thresholds'))) {
        if ($item.Name -notin $script:DefaultThresholds.Keys) {
            $problems.Add("Unknown threshold '$($item.Name)'. Valid names: $($script:DefaultThresholds.Keys -join ', ').")
            continue
        }
        $number = $item.Value -as [double]
        if ($null -eq $number -or $number -lt 0 -or $number -gt 100) {
            $problems.Add("Threshold '$($item.Name)' must be a number from 0 to 100.")
            continue
        }
        $thresholds[$item.Name] = $number
    }

    $risks = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($entry in @(Get-PropertyValue $InputObject 'AcceptedRisks' | Where-Object { $_ })) {
        $index++
        $label = "AcceptedRisks entry $index"
        $checkId = [string] (Get-PropertyValue $entry 'CheckId')
        $reason = [string] (Get-PropertyValue $entry 'Reason')
        $owner = [string] (Get-PropertyValue $entry 'Owner')
        $expires = ConvertTo-ExpiryDate (Get-PropertyValue $entry 'Expires')

        if ($checkId -notin $script:CheckCatalog.Keys) { $problems.Add("${label}: unknown CheckId '$checkId'.") }
        if (-not $reason.Trim()) { $problems.Add("${label}: Reason is required.") }
        if (-not $owner.Trim()) { $problems.Add("${label}: Owner is required.") }
        if ($null -eq $expires) { $problems.Add("${label}: Expires is required in yyyy-MM-dd format.") }

        $risks.Add([pscustomobject]@{
                CheckId         = $checkId
                AffectedObjects = [string[]] @(Get-PropertyValue $entry 'AffectedObjects' | Where-Object { $_ })
                Reason          = $reason.Trim()
                Owner           = $owner.Trim()
                Expires         = $expires
                Ticket          = [string] (Get-PropertyValue $entry 'Ticket')
            })
    }

    if ($problems.Count -gt 0) {
        throw "The assessment configuration is invalid:`n - $($problems -join "`n - ")"
    }

    [pscustomobject]@{
        SchemaVersion           = $script:ConfigurationSchemaVersion
        TenantId                = if ($tenantId) { $tenantId } else { $null }
        EmergencyAccessAccounts = $emergency
        Thresholds              = [pscustomobject] $thresholds
        AcceptedRisks           = $risks.ToArray()
    }
}

function Resolve-AssessmentThreshold {
    # Precedence: explicit parameters, then configuration, then defaults.
    param (
        [Parameter(Mandatory)] [object] $Configuration,
        [Parameter(Mandatory)] [hashtable] $Override
    )

    $values = [ordered]@{}
    foreach ($name in $script:DefaultThresholds.Keys) {
        $values[$name] = $script:DefaultThresholds[$name]
        $configured = Get-PropertyValue $Configuration.Thresholds $name
        if ($null -ne $configured) { $values[$name] = $configured }
        if ($Override.ContainsKey($name)) { $values[$name] = $Override[$name] }
    }

    if ($values.MinimumGlobalAdmins -gt $values.MaximumGlobalAdmins) {
        throw 'MinimumGlobalAdmins cannot be greater than MaximumGlobalAdmins.'
    }
    if ($values.MfaRegistrationMinimumPercent -gt $values.MfaRegistrationTargetPercent) {
        throw 'MfaRegistrationMinimumPercent cannot be greater than MfaRegistrationTargetPercent.'
    }
    [pscustomobject] $values
}

function Resolve-AcceptedRisk {
    # Marks Fail or Warn findings as Accepted when a current, matching risk acceptance covers them.
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $AcceptedRisk,
        [Parameter(Mandatory)] [datetime] $AsOf
    )

    foreach ($item in $Finding) {
        $risks = @($AcceptedRisk | Where-Object { $_.CheckId -eq $item.CheckId })
        $notes = [System.Collections.Generic.List[string]]::new()
        $applied = $null

        foreach ($risk in $risks) {
            $until = $risk.Expires.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
            if ($item.OriginalStatus -eq 'Pass') {
                $notes.Add("An accepted risk (owner $($risk.Owner), until $until) is no longer needed because the check passes; remove it from the configuration.")
                continue
            }
            if ($item.OriginalStatus -notin @('Fail', 'Warn')) {
                continue
            }
            if ($AsOf.Date -gt $risk.Expires) {
                $notes.Add("Accepted risk expired on $until (owner $($risk.Owner)); renew it or fix the finding.")
                continue
            }
            if ($risk.AffectedObjects.Count -gt 0) {
                if ($item.AffectedCount -eq 0) {
                    $notes.Add("An accepted risk (owner $($risk.Owner)) is limited to specific objects, but this finding lists none, so it was not applied.")
                    continue
                }
                $uncovered = @($item.AffectedObjects | Where-Object { $_ -notin $risk.AffectedObjects })
                if ($uncovered.Count -gt 0) {
                    $notes.Add("Accepted risk (owner $($risk.Owner), until $until) covers $($item.AffectedCount - $uncovered.Count) of $($item.AffectedCount) affected object(s); not covered: $($uncovered -join ', ').")
                    continue
                }
            }
            if (-not $applied) {
                $applied = $risk
            }
        }

        if ($applied) {
            $item.Status = 'Accepted'
            $ticket = if ($applied.Ticket) { ", $($applied.Ticket)" } else { '' }
            $until = $applied.Expires.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
            $notes.Insert(0, "Risk accepted by $($applied.Owner) until $until$ticket`: $($applied.Reason)")
        }
        if ($notes.Count -gt 0) {
            $item.AcceptanceNote = $notes -join ' '
        }
        $item
    }
}
