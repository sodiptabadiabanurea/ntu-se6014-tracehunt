$ErrorActionPreference = "Stop"

function Require-Env([string]$Name) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Name environment variable is required."
    }
    return $value
}

function New-BasicAuthHeader([string]$User, [string]$Password) {
    $pair = $User + ":" + $Password
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
    return @{ Authorization = "Basic $encoded" }
}

function Wait-TcpPort([string]$HostName, [int]$Port, [int]$Attempts = 60) {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($HostName, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(1000) -and $client.Connected) {
                $client.EndConnect($async)
                $client.Close()
                return
            }
        } catch {
        } finally {
            $client.Close()
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for ${HostName}:${Port}."
}

$EsUrl = if ($env:ES_URL) { $env:ES_URL.TrimEnd("/") } else { "http://127.0.0.1:9200" }
$LogstashHost = if ($env:LOGSTASH_HOST) { $env:LOGSTASH_HOST } else { "127.0.0.1" }
$LogstashPort = if ($env:LOGSTASH_PORT) { [int]$env:LOGSTASH_PORT } else { 5000 }
$KibanaHost = if ($env:KIBANA_HOST) { $env:KIBANA_HOST } else { "127.0.0.1" }
$KibanaPort = if ($env:KIBANA_PORT) { [int]$env:KIBANA_PORT } else { 5601 }

$ElasticPassword = Require-Env "ELASTIC_PASSWORD"
$ReadOnlyPassword = Require-Env "TRACEHUNT_RO_PASSWORD"
$AdminHeader = New-BasicAuthHeader "elastic" $ElasticPassword
$ReadOnlyHeader = New-BasicAuthHeader "tracehunt_ro" $ReadOnlyPassword

Write-Host "--- 1. Elasticsearch authenticated health ---"
$cluster = Invoke-RestMethod -Uri "$EsUrl/_cluster/health" -Headers $AdminHeader -Method Get -TimeoutSec 10
if ($cluster.status -ne "green" -and $cluster.status -ne "yellow") {
    throw "Elasticsearch cluster status is '$($cluster.status)'."
}
Write-Host "[OK] Elasticsearch is $($cluster.status)."

Write-Host "--- 2. Logstash and Kibana ports ---"
Wait-TcpPort $LogstashHost $LogstashPort
Wait-TcpPort $KibanaHost $KibanaPort
Write-Host "[OK] Logstash and Kibana are accepting connections."

Write-Host "--- 3. Raw Logstash ingestion ---"
$runId = [Guid]::NewGuid().ToString("N")
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$rawIndex = "tracehunt-raw-" + (Get-Date).ToUniversalTime().ToString("yyyy.MM.dd")
$eventObject = [ordered]@{
    "@timestamp" = $timestamp
    "run_id" = $runId
    "event" = [ordered]@{
        "category" = "healthcheck"
        "type" = "synthetic"
    }
    "host" = [ordered]@{
        "name" = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "tracehunt-healthcheck" }
    }
}
$jsonPayload = $eventObject | ConvertTo-Json -Compress -Depth 8

$searchBody = @{
    query = @{
        term = @{
            run_id = $runId
        }
    }
} | ConvertTo-Json -Compress -Depth 6

$found = $false
for ($attempt = 1; $attempt -le 40; $attempt++) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($LogstashHost, $LogstashPort)
        $stream = $tcp.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.NewLine = [Environment]::NewLine
        $writer.WriteLine($jsonPayload)
        $writer.Flush()
        $writer.Dispose()
        $stream.Dispose()
        $tcp.Close()
    } catch {
    }

    Start-Sleep -Seconds 1
    try {
        $result = Invoke-RestMethod -Uri "$EsUrl/$rawIndex/_search" -Headers $AdminHeader -Method Post -ContentType "application/json" -Body $searchBody -TimeoutSec 10
        if ($result.hits.total.value -gt 0) {
            $found = $true
            break
        }
    } catch {
    }
}
if (-not $found) {
    throw "Synthetic Logstash event $runId was not found in $rawIndex."
}
Write-Host "[OK] Logstash event reached $rawIndex."

Write-Host "--- 4. M3 mapping and M4 read-only access ---"
$docId = "healthcheck-$runId"
$normalized = [ordered]@{
    "@timestamp" = $timestamp
    "ecs" = @{ "version" = "8.11.0" }
    "event" = @{
        "code" = "4625"
        "outcome" = "failure"
        "original" = "TraceHunt synthetic health check"
    }
    "host" = @{ "name" = "WS-HEALTH" }
    "user" = @{ "name" = "healthcheck-user" }
    "tracehunt" = @{
        "source_type" = "windows-security"
        "source_hash" = $runId
        "schema" = @{
            "id" = "windows-security"
            "version" = "1.0.0"
            "hash" = $runId
        }
    }
}
$normalizedJson = $normalized | ConvertTo-Json -Compress -Depth 10
$created = $false

try {
    $indexResult = Invoke-RestMethod -Uri "$EsUrl/windows-security/_doc/${docId}?refresh=true" -Headers $AdminHeader -Method Put -ContentType "application/json" -Body $normalizedJson -TimeoutSec 10
    if ($indexResult._id -ne $docId) {
        throw "Elasticsearch indexed the synthetic event under unexpected id '$($indexResult._id)'."
    }
    $created = $true

    $readResult = Invoke-RestMethod -Uri "$EsUrl/windows-security/_doc/$docId" -Headers $ReadOnlyHeader -Method Get -TimeoutSec 10
    if (-not $readResult.found) {
        throw "tracehunt_ro could not read the synthetic normalized event."
    }

    $deniedId = "denied-$runId"
    $writeWasDenied = $false
    try {
        Invoke-WebRequest -Uri "$EsUrl/windows-security/_doc/$deniedId" -Headers $ReadOnlyHeader -Method Put -ContentType "application/json" -Body $normalizedJson -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop | Out-Null
    } catch {
        if ($_.Exception.Response -and ([int]$_.Exception.Response.StatusCode -eq 403)) {
            $writeWasDenied = $true
        } else {
            throw
        }
    }

    if (-not $writeWasDenied) {
        throw "tracehunt_ro unexpectedly obtained write access."
    }
    Write-Host "[OK] M3-shaped event indexed; M4 read access works; write access is denied."
}
finally {
    if ($created) {
        try {
            Invoke-RestMethod -Uri "$EsUrl/windows-security/_doc/${docId}?refresh=true" -Headers $AdminHeader -Method Delete -TimeoutSec 10 | Out-Null
        } catch {
            Write-Warning "Could not remove synthetic normalized event $docId."
        }
    }
}

Write-Host "[SUCCESS] TraceHunt M1 ELK integration checks passed."
