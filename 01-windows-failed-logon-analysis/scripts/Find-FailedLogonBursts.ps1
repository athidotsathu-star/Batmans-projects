param(
    [int]$Hours = 24,
    [int]$Threshold = 5,
    [string]$CsvPath,
    [string]$EvtxPath,
    [string]$OutputDirectory = ".\output"
)

# Parse Windows Security Event ID 4625 from the live log, an EVTX export,
# or the normalized CSV supplied with this training project.
# A threshold match is a triage lead, not proof of malicious activity.

$ErrorActionPreference = "Stop"

if ($Hours -lt 1) { throw "Hours must be at least 1." }
if ($Threshold -lt 1) { throw "Threshold must be at least 1." }

function Get-EventField {
    param(
        [xml]$Xml,
        [string]$Name
    )
    $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $node) { return "" }
    return [string]$node.'#text'
}

$events = @()

if ($CsvPath) {
    if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
    $rows = Import-Csv -LiteralPath $CsvPath
    foreach ($row in $rows) {
        $events += [pscustomobject]@{
            TimeCreated    = [datetime]$row.TimeCreated
            EventId        = 4625
            TargetUserName = [string]$row.TargetUserName
            IpAddress      = [string]$row.IpAddress
            WorkstationName= [string]$row.WorkstationName
            LogonType      = [string]$row.LogonType
            Status         = [string]$row.Status
            SubStatus      = [string]$row.SubStatus
        }
    }
}
else {
    if ($EvtxPath) {
        if (-not (Test-Path -LiteralPath $EvtxPath)) { throw "EVTX file not found: $EvtxPath" }
        $rawEvents = Get-WinEvent -Path $EvtxPath -FilterXPath "*[System[(EventID=4625)]]"
    }
    else {
        $startTime = (Get-Date).AddHours(-$Hours)
        $rawEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = 4625
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
    }

    foreach ($event in $rawEvents) {
        [xml]$xml = $event.ToXml()
        $events += [pscustomobject]@{
            TimeCreated     = $event.TimeCreated
            EventId         = $event.Id
            TargetUserName  = Get-EventField -Xml $xml -Name "TargetUserName"
            IpAddress       = Get-EventField -Xml $xml -Name "IpAddress"
            WorkstationName = Get-EventField -Xml $xml -Name "WorkstationName"
            LogonType       = Get-EventField -Xml $xml -Name "LogonType"
            Status          = Get-EventField -Xml $xml -Name "Status"
            SubStatus       = Get-EventField -Xml $xml -Name "SubStatus"
        }
    }
}

if (-not $events -or $events.Count -eq 0) {
    Write-Warning "No Event ID 4625 records were found for the selected source and time range."
    return
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$eventFile = Join-Path $OutputDirectory "failed-logons-$stamp.csv"
$summaryFile = Join-Path $OutputDirectory "source-summary-$stamp.csv"

$events |
    Sort-Object TimeCreated |
    Export-Csv -LiteralPath $eventFile -NoTypeInformation -Encoding UTF8

$summary = $events |
    Where-Object {
        $_.IpAddress -and
        $_.IpAddress -notin @("-", "::1", "127.0.0.1", "0.0.0.0")
    } |
    Group-Object IpAddress |
    ForEach-Object {
        $group = $_.Group
        [pscustomobject]@{
            SourceIP       = $_.Name
            FailedAttempts = $group.Count
            FirstSeen      = ($group | Measure-Object TimeCreated -Minimum).Minimum
            LastSeen       = ($group | Measure-Object TimeCreated -Maximum).Maximum
            TargetAccounts = (($group.TargetUserName | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            LogonTypes     = (($group.LogonType | Where-Object { $_ } | Sort-Object -Unique) -join ";")
            TriageFlag     = if ($group.Count -ge $Threshold) { "REVIEW" } else { "Below threshold" }
        }
    } |
    Sort-Object FailedAttempts -Descending

$summary | Export-Csv -LiteralPath $summaryFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Parsed events: $($events.Count)"
Write-Host "Event export:  $eventFile"
Write-Host "Source report: $summaryFile"
Write-Host ""
$summary | Format-Table -AutoSize

Write-Warning "A threshold match is not proof of brute force or compromise. Validate context and correlate with successful logons (4624) and other telemetry."
