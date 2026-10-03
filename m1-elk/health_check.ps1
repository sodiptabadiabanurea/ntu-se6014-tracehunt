Write-Host "=== TraceHunt ELK Stack Comprehensive Health Check ===" -ForegroundColor Cyan

# Generate a unique run ID for exact verification
$runId = [Guid]::NewGuid().ToString()
Write-Host "Run ID for this execution: $runId" -ForegroundColor Gray

# 1. Elasticsearch Check
try {
    $es = Invoke-RestMethod -Uri "http://localhost:9200/_cluster/health" -Method Get
    Write-Host "[OK] Elasticsearch Status: $($es.status) | Nodes: $($es.number_of_nodes)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Elasticsearch unreachable on port 9200!" -ForegroundColor Red
}

# 2. Kibana Check
try {
    $kibana = Invoke-WebRequest -Uri "http://localhost:5601/status" -Method Get -UseBasicParsing
    if ($kibana.StatusCode -eq 200) {
        Write-Host "[OK] Kibana running on port 5601" -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Kibana unreachable on port 5601!" -ForegroundColor Red
}

# 3. Logstash Port Check & Unique Event Dispatch
$logstashPort = 5000
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("localhost", $logstashPort)
    if ($tcp.Connected) {
        Write-Host "[OK] Logstash TCP listening on port $logstashPort" -ForegroundColor Green
        
        # Send Test Event with unique run_id and host object aligned with M3
        $writer = New-Object System.IO.StreamWriter($tcp.GetStream())$testEvent = "{`"event_type`": `"health_check`", `"run_id`": `"$runId`", `"message`": `"Test event from health check script`", `"severity`": `"info`", `"host`": {`"name`": `"health-check-host`"}}"
        $writer.WriteLine($testEvent)
        $writer.Flush()$tcp.Close()
        Write-Host "[OK] Test event (Run ID: $runId) dispatched to Logstash successfully!" -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Could not connect to Logstash on port $logstashPort!" -ForegroundColor Red
}

# 4. Verify End-to-End Event Ingestion for THIS specific run ID
Start-Sleep -Seconds 3
try {
    $search = Invoke-RestMethod -Uri "http://localhost:9200/_search?q=run_id:$runId" -Method Get
    $total =$search.hits.total.value
    if ($total -gt 0) {
        Write-Host "[OK] End-to-End Test Passed: Verified event for Run ID $runId in Elasticsearch!" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] End-to-End Test Failed: Event for Run ID $runId not found in Elasticsearch." -ForegroundColor Red
    }
} catch {
    Write-Host "[FAIL] Failed to query Elasticsearch for test event." -ForegroundColor Red
}
