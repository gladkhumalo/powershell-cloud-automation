. (Join-Path $PSScriptRoot '../src/Export-M365UserReport.ps1')

Describe 'Export-M365UserReport' {
    It 'exports only the six report fields and preserves account status' {
        $path = Join-Path $TestDrive 'nested/users.csv'
        $users = @(
            [pscustomobject]@{
                DisplayName = 'Alex Example'
                UserPrincipalName = 'alex@example.test'
                AccountEnabled = $true
                UserType = 'Member'
                Department = 'Operations'
                JobTitle = 'Analyst'
                Id = 'should-not-be-exported'
            }
            [pscustomobject]@{
                DisplayName = 'Sam Example'
                UserPrincipalName = 'sam@example.test'
                AccountEnabled = $false
                UserType = 'Guest'
                Department = $null
                JobTitle = $null
                Id = 'also-excluded'
            }
        )

        $count = Export-M365UserReport -Users $users -OutputPath $path
        $rows = @(Import-Csv -LiteralPath $path)

        $count | Should Be 2
        $rows.Count | Should Be 2
        @($rows[0].PSObject.Properties.Name) -join ',' | Should Be 'DisplayName,UserPrincipalName,AccountEnabled,UserType,Department,JobTitle'
        $rows[0].AccountEnabled | Should Be 'True'
        $rows[1].AccountEnabled | Should Be 'False'
        $rows[1].Department | Should BeNullOrEmpty
    }

    It 'round-trips commas, quotes, and Unicode text through CSV' {
        $path = Join-Path $TestDrive 'special-characters.csv'
        $user = [pscustomobject]@{
            DisplayName = 'Renée, Example'
            UserPrincipalName = 'renee@example.test'
            AccountEnabled = $true
            UserType = 'Member'
            Department = 'Research, Design'
            JobTitle = 'Lead "Cloud" Analyst'
        }

        $null = Export-M365UserReport -Users @($user) -OutputPath $path
        $row = Import-Csv -LiteralPath $path

        $row.DisplayName | Should Be 'Renée, Example'
        $row.Department | Should Be 'Research, Design'
        $row.JobTitle | Should Be 'Lead "Cloud" Analyst'
    }

    It 'writes a header-only CSV when Graph returns no users' {
        $path = Join-Path $TestDrive 'empty.csv'

        $count = Export-M365UserReport -Users @() -OutputPath $path
        $lines = @(Get-Content -LiteralPath $path)

        $count | Should Be 0
        $lines.Count | Should Be 1
        $lines[0] | Should Be 'DisplayName,UserPrincipalName,AccountEnabled,UserType,Department,JobTitle'
    }
}
