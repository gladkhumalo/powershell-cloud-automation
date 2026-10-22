$inventoryScriptPath = Join-Path $PSScriptRoot '../src/Export-AzureResourceInventory.ps1'
$samplePath = Join-Path $PSScriptRoot '../examples/sample-resources.json'

Describe 'Azure resource inventory offline exports' {
    It 'exports sorted resources across subscriptions with matching CSV and JSON fields' {
        $result = & $inventoryScriptPath -SnapshotPath $samplePath -OutputDirectory (Join-Path $TestDrive 'nested/report')
        $csv = @(Import-Csv -LiteralPath $result.CsvPath)
        $json = @(Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json)
        $result.ResourceCount | Should Be 2
        $csv.Count | Should Be 2
        $json.Count | Should Be 2
        $csv[0].Name | Should Be 'vm-example'
        $csv[1].Location | Should Be 'southafricanorth'
        foreach ($row in 0..1) {
            foreach ($field in $csv[$row].PSObject.Properties.Name) {
                $json[$row].$field | Should Be $csv[$row].$field
            }
        }
    }

    It 'writes a header-only CSV and an empty JSON array for an empty subscription' {
        $snapshot = Join-Path $TestDrive 'empty.json'
        '{"Resources":[]}' | Set-Content -LiteralPath $snapshot
        $result = & $inventoryScriptPath -SnapshotPath $snapshot -OutputDirectory (Join-Path $TestDrive 'empty')
        $result.ResourceCount | Should Be 0
        @(Get-Content -LiteralPath $result.CsvPath).Count | Should Be 1
        (Get-Content -LiteralPath $result.JsonPath -Raw).Trim() | Should Be '[]'
    }

    It 'preserves CSV punctuation and Unicode and keeps single-resource JSON as an array' {
        $snapshot = Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json
        $snapshot.Resources = @($snapshot.Resources[0])
        $snapshot.Resources[0].SubscriptionName = 'Example, "Cape Town" — café'
        $path = Join-Path $TestDrive 'single.json'
        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding utf8
        $result = & $inventoryScriptPath -SnapshotPath $path -OutputDirectory (Join-Path $TestDrive 'single')
        (Import-Csv -LiteralPath $result.CsvPath).SubscriptionName | Should Be $snapshot.Resources[0].SubscriptionName
        (Get-Content -LiteralPath $result.JsonPath -Raw).Trim().StartsWith('[') | Should Be $true
    }

    It 'rejects malformed snapshots before creating reports' {
        foreach ($content in @('{', '{}', '{"Resources":[{}]}', '{"Resources":null}')) {
            $path = Join-Path $TestDrive 'bad.json'
            $content | Set-Content -LiteralPath $path
            $caught = $false
            try { & $inventoryScriptPath -SnapshotPath $path -OutputDirectory (Join-Path $TestDrive 'invalid') } catch { $caught = $true }
            $caught | Should Be $true
        }
        Test-Path (Join-Path $TestDrive 'invalid') | Should Be $false
    }
}

Describe 'Azure resource inventory live collection' {
    # Stubs let Pester mock Azure commands without installing Az or signing in.
    function Get-AzContext { [CmdletBinding()] param() }
    function Get-AzSubscription { [CmdletBinding()] param($SubscriptionId) }
    function Set-AzContext { [CmdletBinding()] param($Subscription, $Tenant, $Scope, $Context) }
    function Get-AzResource { [CmdletBinding()] param($DefaultProfile) }

    BeforeEach {
        Mock Import-Module {} -ParameterFilter { $Name -like 'Az.*' }
        Mock Get-AzContext { [pscustomobject]@{ Name = 'original' } }
        Mock Get-AzSubscription { [pscustomobject]@{ Id = $SubscriptionId; Name = 'Example'; TenantId = 'tenant' } }
        Mock Set-AzContext { [pscustomobject]@{ Name = $Subscription } }
        Mock Get-AzResource {
            [pscustomobject]@{ Name = 'vm'; ResourceGroupName = 'rg'; ResourceType = 'Microsoft.Compute/virtualMachines'; Location = 'westeurope'; ResourceId = '/example/vm' }
        }
    }

    It 'collects each requested subscription once and restores the original context' {
        $result = & $inventoryScriptPath -SubscriptionId @('one', 'two', 'one') -OutputDirectory (Join-Path $TestDrive 'live')
        $rows = @(Import-Csv $result.CsvPath)
        $result.ResourceCount | Should Be 2
        $rows[0].SubscriptionId | Should Be 'one'
        $rows[1].SubscriptionId | Should Be 'two'
        Assert-MockCalled Get-AzResource -Times 2 -Exactly -Scope It
        Assert-MockCalled Set-AzContext -Times 1 -Exactly -Scope It -ParameterFilter { $Context.Name -eq 'original' -and $Scope -eq 'Process' }
    }

    It 'stops on a failed subscription and restores context without writing partial reports' {
        Mock Get-AzResource { throw 'Access denied' } -ParameterFilter { $DefaultProfile.Name -eq 'two' }
        $caught = $false
        try { & $inventoryScriptPath -SubscriptionId @('one', 'two') -OutputDirectory (Join-Path $TestDrive 'failed') } catch { $caught = $true }
        $caught | Should Be $true
        Test-Path (Join-Path $TestDrive 'failed') | Should Be $false
        Assert-MockCalled Set-AzContext -Times 1 -Exactly -Scope It -ParameterFilter { $Context.Name -eq 'original' }
    }

    It 'requires an existing Azure sign-in' {
        Mock Get-AzContext { $null }
        $caught = $false
        try { & $inventoryScriptPath -SubscriptionId 'one' -OutputDirectory (Join-Path $TestDrive 'unsigned') } catch { $caught = $true }
        $caught | Should Be $true
        Assert-MockCalled Get-AzResource -Times 0 -Exactly -Scope It
    }
}
