[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\output\windows_events.jsonl",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 168)]
    [int]$Hours = 24
)

$ErrorActionPreference = "Stop"
$startTime = (Get-Date).AddHours(-$Hours)
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutput

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

$queries = @(
    @{ LogName = "Security"; Id = @(4624, 4625, 4663, 4688) },
    @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Id = @(4104) },
    @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Id = @(1, 3, 11) }
)

function Get-FirstValue {
    param([object[]]$Values)
    foreach ($value in $Values) {
        if ($null -ne $value -and [string]$value -ne "") { return [string]$value }
    }
    return ""
}

$events = foreach ($query in $queries) {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $query.LogName
            Id = $query.Id
            StartTime = $startTime
        } -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning "Could not read $($query.LogName): $($_.Exception.Message)"
    }
}

$normalized = foreach ($event in ($events | Sort-Object TimeCreated)) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $name = if ($node.Name) { [string]$node.Name } else { "Data$($data.Count)" }
        $data[$name] = [string]$node.'#text'
    }

    $outcome = ""
    if ($event.Id -eq 4624) { $outcome = "success" }
    if ($event.Id -eq 4625) { $outcome = "failure" }

    [ordered]@{
        timestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
        event_id = [string]$event.Id
        channel = [string]$event.LogName
        host = [string]$event.MachineName
        username = Get-FirstValue @($data.TargetUserName, $data.User)
        source_ip = Get-FirstValue @($data.IpAddress, $data.SourceIp)
        destination_ip = [string]$data.DestinationIp
        destination_port = if ($data.DestinationPort) { [int]$data.DestinationPort } else { $null }
        image = [string]$data.Image
        command_line = Get-FirstValue @($data.CommandLine, $data.ScriptBlockText)
        target_path = Get-FirstValue @($data.ObjectName, $data.TargetFilename)
        action = Get-FirstValue @($data.AccessList, $data.GrantedAccess)
        outcome = $outcome
        record_id = [string]$event.RecordId
        provider = [string]$event.ProviderName
    }
}

$jsonLines = @($normalized | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 })
[System.IO.File]::WriteAllLines($resolvedOutput, $jsonLines, [System.Text.UTF8Encoding]::new($false))

Write-Output "Exported $(@($normalized).Count) events to $resolvedOutput"
Write-Output "This collector reads local event logs only. It does not modify logging policy, services, or security controls."
