. (Join-Path $PSScriptRoot '../src/Export-M365LicenseReport.ps1')

Describe 'Export-M365LicenseReport' {
    It 'exports sorted SKU counts and calculates available units' {
        $path = Join-Path $TestDrive 'nested/license-report.csv'
        $skus = @(
            [pscustomobject]@{
                SkuPartNumber = 'Z_TEST'
                SkuId = '22222222-2222-2222-2222-222222222222'
                CapabilityStatus = 'Enabled'
                PrepaidUnits = [pscustomobject]@{ Enabled = 50 }
                ConsumedUnits = 10
            }
            [pscustomobject]@{
                SkuPartNumber = 'A_TEST'
                SkuId = '11111111-1111-1111-1111-111111111111'
                CapabilityStatus = 'Enabled'
                PrepaidUnits = [pscustomobject]@{ Enabled = 100 }
                ConsumedUnits = 75
            }
        )

        $count = Export-M365LicenseReport -Skus $skus -OutputPath $path
        $rows = @(Import-Csv -LiteralPath $path)

        $count | Should Be 2
        $rows.Count | Should Be 2
        $rows[0].SkuPartNumber | Should Be 'A_TEST'
        $rows[0].EnabledUnits | Should Be '100'
        $rows[0].ConsumedUnits | Should Be '75'
        $rows[0].AvailableUnits | Should Be '25'
        $rows[1].AvailableUnits | Should Be '40'
    }

    It 'writes a header-only CSV when there are no SKUs' {
        $path = Join-Path $TestDrive 'empty.csv'

        $count = Export-M365LicenseReport -Skus @() -OutputPath $path
        $lines = @(Get-Content -LiteralPath $path)

        $count | Should Be 0
        $lines.Count | Should Be 1
        $lines[0] | Should Be 'SkuPartNumber,SkuId,CapabilityStatus,EnabledUnits,ConsumedUnits,AvailableUnits'
    }

    It 'preserves a negative available count when consumption exceeds enabled units' {
        $path = Join-Path $TestDrive 'over-consumed.csv'
        $sku = [pscustomobject]@{
            SkuPartNumber = 'OVER_TEST'
            SkuId = '33333333-3333-3333-3333-333333333333'
            CapabilityStatus = 'Enabled'
            PrepaidUnits = [pscustomobject]@{ Enabled = 5 }
            ConsumedUnits = 7
        }

        $null = Export-M365LicenseReport -Skus @($sku) -OutputPath $path
        $row = Import-Csv -LiteralPath $path

        $row.AvailableUnits | Should Be '-2'
    }
}
