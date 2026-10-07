function ConvertTo-SecurityReportHtml {
    param (
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Finding,
        [Parameter(Mandatory)] [object] $Snapshot,
        [AllowEmptyCollection()] [object[]] $Drift,
        [AllowNull()] [object] $ReferenceSnapshot
    )

    $summary = Get-FindingSummary -Finding $Finding
    $collectedAt = Format-SnapshotDate -Snapshot $Snapshot
    $tenantId = ConvertTo-HtmlText (Get-PropertyValue $Snapshot 'TenantId')
    $collectedBy = ConvertTo-HtmlText (Get-PropertyValue $Snapshot 'CollectedBy')
    $statusLabel = @{ Fail = 'Fail'; Warn = 'Warn'; NotAssessed = 'Not assessed'; Accepted = 'Accepted'; Pass = 'Pass' }
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
        $noteHtml = if ($item.AcceptanceNote) { "<p class=`"note`">$(ConvertTo-HtmlText $item.AcceptanceNote)</p>" } else { '' }
        $baseline = @($item.BaselineControls | Where-Object { $_ })
        $baselineHtml = if ($baseline.Count -gt 0) { " &middot; $(ConvertTo-HtmlText ($baseline -join ', '))" } else { '' }
        $referenceHtml = ''
        if ([string] $item.Reference -match '^https://') {
            $referenceHtml = " <a href=`"$(ConvertTo-HtmlText $item.Reference)`" rel=`"noopener noreferrer`">Guidance</a>"
        }
        $statusClass = $item.Status.ToLowerInvariant()

        @"
<tr>
  <td><span class="badge $statusClass">$($statusLabel[$item.Status])</span></td>
  <td><span class="sev">$(ConvertTo-HtmlText $item.Severity)</span></td>
  <td class="check"><div class="id">$(ConvertTo-HtmlText $item.CheckId) &middot; $(ConvertTo-HtmlText $item.Category)$baselineHtml</div><div class="title">$(ConvertTo-HtmlText $item.Title)</div><p>$(ConvertTo-HtmlText $item.Observed)</p>$noteHtml$affectedHtml</td>
  <td class="rec">$(ConvertTo-HtmlText $item.Recommendation)$referenceHtml</td>
</tr>
"@
    }

    $driftHtml = ''
    if ($ReferenceSnapshot) {
        $changes = @($Drift)
        $since = Format-SnapshotDate -Snapshot $ReferenceSnapshot
        $regressed = @($changes | Where-Object ChangeType -EQ 'Regressed').Count
        $improved = @($changes | Where-Object ChangeType -EQ 'Improved').Count
        $configuration = @($changes | Where-Object Category -NE 'Finding').Count
        $driftRows = foreach ($change in $changes) {
            $class = switch ($change.ChangeType) {
                'Regressed' { 'fail' }
                'NewlyAffected' { 'warn' }
                'Improved' { 'pass' }
                'NoLongerAffected' { 'pass' }
                default { 'notassessed' }
            }
            $beforeAfter = if ($change.Before -or $change.After) { "$(ConvertTo-HtmlText $change.Before) &rarr; $(ConvertTo-HtmlText $change.After)" } else { '' }
            @"
<tr>
  <td><span class="badge $class">$(ConvertTo-HtmlText (($change.ChangeType -creplace '(?<=[a-z])([A-Z])', ' $1').ToLowerInvariant() -replace '^.', { $_.Value.ToUpperInvariant() }))</span></td>
  <td class="sev">$(ConvertTo-HtmlText $change.Category)</td>
  <td class="check"><div class="title">$(ConvertTo-HtmlText $change.Item)</div><p>$(ConvertTo-HtmlText $change.Detail)</p></td>
  <td class="rec">$beforeAfter</td>
</tr>
"@
        }
        $body = if ($changes.Count -eq 0) {
            '<p class="meta">No changes were detected.</p>'
        }
        else {
            @"
<div class="table-wrap">
<table>
<thead><tr><th>Change</th><th>Area</th><th>Item and detail</th><th>Before &rarr; after</th></tr></thead>
<tbody>
$($driftRows -join "`n")
</tbody>
</table>
</div>
"@
        }
        $driftHtml = @"
<h2>Changes since $since UTC</h2>
<p class="meta">$regressed regressed &middot; $improved improved &middot; $configuration configuration change(s)</p>
$body
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
  --fail:#b42318; --fail-bg:#fde8e7; --warn:#8a5300; --warn-bg:#fff1d0; --na:#475467; --na-bg:#eceff3;
  --acc:#3a4fb8; --acc-bg:#e6eafc; --pass:#16794c; --pass-bg:#e2f4e9; --link:#1f5fbf; }
@media (prefers-color-scheme: dark) { :root { --bg:#11141a; --panel:#1a1f28; --text:#e5e8ee; --muted:#9aa3b2; --border:#2c3340;
  --fail:#ff8b82; --fail-bg:#3b1d1b; --warn:#f3c169; --warn-bg:#352913; --na:#b6bdc9; --na-bg:#262c36;
  --acc:#a9b8ff; --acc-bg:#232a4a; --pass:#71d29d; --pass-bg:#15301f; --link:#82b1ff; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width:1180px; margin:0 auto; padding:32px 16px 48px; }
h1 { margin:0 0 4px; font-size:26px; }
h2 { margin:36px 0 4px; font-size:20px; }
.meta { color:var(--muted); margin:0 0 20px; }
.meta code { font-size:13px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:12px; margin-bottom:24px; }
.card { background:var(--panel); border:1px solid var(--border); border-left-width:5px; border-radius:8px; padding:14px 16px; }
.card .n { font-size:28px; font-weight:600; line-height:1.1; }
.card .l { color:var(--muted); }
.card.fail { border-left-color:var(--fail); } .card.warn { border-left-color:var(--warn); }
.card.notassessed { border-left-color:var(--na); } .card.accepted { border-left-color:var(--acc); } .card.pass { border-left-color:var(--pass); }
.table-wrap { overflow-x:auto; background:var(--panel); border:1px solid var(--border); border-radius:8px; }
table { width:100%; border-collapse:collapse; min-width:720px; }
th, td { text-align:left; vertical-align:top; padding:12px 14px; border-bottom:1px solid var(--border); }
th { font-size:13px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.03em; }
tr:last-child td { border-bottom:none; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:13px; font-weight:600; white-space:nowrap; }
.badge.fail { color:var(--fail); background:var(--fail-bg); } .badge.warn { color:var(--warn); background:var(--warn-bg); }
.badge.notassessed { color:var(--na); background:var(--na-bg); } .badge.accepted { color:var(--acc); background:var(--acc-bg); }
.badge.pass { color:var(--pass); background:var(--pass-bg); }
.sev { font-size:13px; color:var(--muted); }
.check .id { font-size:12px; color:var(--muted); }
.check .title { font-weight:600; }
.check p { margin:4px 0 0; }
.check p.note { color:var(--acc); font-size:14px; }
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
  <div class="card accepted"><div class="n">$($summary.Accepted)</div><div class="l">Accepted risk</div></div>
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
$driftHtml
<footer>Read-only configuration review. Findings describe configuration at collection time and do not replace a full security review. Baseline IDs refer to the CISA SCuBA Microsoft Entra ID baseline. This report contains tenant and account details; store and share it as confidential.</footer>
</main>
</body>
</html>
"@
}
