param(
    [string]$Python = "python",
    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $runName = "demo-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff")
    $OutputDirectory = Join-Path $PSScriptRoot ("output/" + $runName)
}
$demoOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $demoOutput) {
    throw "The demo output directory already exists. Choose a new directory."
}
New-Item -ItemType Directory -Path $demoOutput | Out-Null

function Invoke-DemoStage {
    param([string]$Name, [int]$ExpectedExit, [string[]]$Arguments)
    Write-Host $Name -ForegroundColor Cyan
    & $Python -m tracehunt_schema @Arguments
    if ($LASTEXITCODE -ne $ExpectedExit) {
        throw "$Name returned exit code $LASTEXITCODE; expected $ExpectedExit."
    }
}

Push-Location $PSScriptRoot
try {
    Invoke-DemoStage -Name "Normalize the three lab sources" -ExpectedExit 0 -Arguments @(
        "normalize", "--input", "fixtures/known-mixed.ndjson",
        "--output", (Join-Path $demoOutput "known/accepted.jsonl"),
        "--quarantine", (Join-Path $demoOutput "known/quarantine.jsonl"),
        "--events-output", (Join-Path $demoOutput "known/events.ndjson"),
        "--bulk-output", (Join-Path $demoOutput "known/bulk.ndjson")
    )
    Invoke-DemoStage -Name "Normalize nested Winlogbeat records" -ExpectedExit 0 -Arguments @(
        "normalize", "--input", "fixtures/winlogbeat.ndjson",
        "--output", (Join-Path $demoOutput "winlogbeat/accepted.jsonl"),
        "--quarantine", (Join-Path $demoOutput "winlogbeat/quarantine.jsonl")
    )
    Invoke-DemoStage -Name "Normalize dotted Zeek records" -ExpectedExit 0 -Arguments @(
        "normalize", "--input", "fixtures/zeek.ndjson",
        "--output", (Join-Path $demoOutput "zeek/accepted.jsonl"),
        "--quarantine", (Join-Path $demoOutput "zeek/quarantine.jsonl")
    )
    Invoke-DemoStage -Name "Normalize flat Sysmon records without a source hint" -ExpectedExit 0 -Arguments @(
        "normalize", "--input", "fixtures/sysmon-flat.ndjson",
        "--output", (Join-Path $demoOutput "sysmon-flat/accepted.jsonl"),
        "--quarantine", (Join-Path $demoOutput "sysmon-flat/quarantine.jsonl")
    )
    Invoke-DemoStage -Name "Quarantine invalid records" -ExpectedExit 2 -Arguments @(
        "normalize", "--input", "fixtures/invalid.ndjson",
        "--output", (Join-Path $demoOutput "invalid/accepted.jsonl"),
        "--quarantine", (Join-Path $demoOutput "invalid/quarantine.jsonl")
    )
    $registryPath = Join-Path $demoOutput "custom/registry"
    $candidatePath = Join-Path $demoOutput "custom/candidate.json"
    $quarantinePath = Join-Path $demoOutput "custom/quarantine.jsonl"
    Invoke-DemoStage -Name "Quarantine an unregistered custom format" -ExpectedExit 2 -Arguments @(
        "normalize", "--input", "fixtures/custom-unknown.ndjson",
        "--output", (Join-Path $demoOutput "custom/before.jsonl"),
        "--quarantine", $quarantinePath, "--registry", $registryPath
    )
    Invoke-DemoStage -Name "Generate and validate a custom candidate" -ExpectedExit 0 -Arguments @(
        "infer", "--samples", "fixtures/custom-unknown.ndjson", "--output", $candidatePath
    )
    # Approval here applies only to the bundled, reviewed synthetic demo fixture.
    Invoke-DemoStage -Name "Approve the reviewed demo parser" -ExpectedExit 0 -Arguments @(
        "approve", "--candidate", $candidatePath, "--samples", "fixtures/custom-unknown.ndjson",
        "--registry", $registryPath
    )
    Invoke-DemoStage -Name "Reuse the approved custom parser" -ExpectedExit 0 -Arguments @(
        "normalize", "--input", "fixtures/custom-unknown.ndjson",
        "--output", (Join-Path $demoOutput "custom/after.jsonl"),
        "--quarantine", $quarantinePath, "--registry", $registryPath
    )
    $agentRegistry = Join-Path $demoOutput "agent/registry"
    Invoke-DemoStage -Name "Automatically generate, validate, register, and apply a schema" -ExpectedExit 0 -Arguments @(
        "onboard", "--input", "fixtures/custom-unknown.ndjson",
        "--output", (Join-Path $demoOutput "agent/first.jsonl"),
        "--quarantine", (Join-Path $demoOutput "agent/quarantine.jsonl"),
        "--audit", (Join-Path $demoOutput "agent/first-decisions.jsonl"),
        "--registry", $agentRegistry
    )
    Invoke-DemoStage -Name "Reuse the agent parser in a frozen run" -ExpectedExit 0 -Arguments @(
        "onboard", "--input", "fixtures/custom-unknown.ndjson",
        "--output", (Join-Path $demoOutput "agent/frozen.jsonl"),
        "--quarantine", (Join-Path $demoOutput "agent/quarantine.jsonl"),
        "--audit", (Join-Path $demoOutput "agent/frozen-decisions.jsonl"),
        "--registry", $agentRegistry, "--frozen"
    )
    Write-Host "Demo completed. Inspect output at: $demoOutput" -ForegroundColor Green
} finally {
    Pop-Location
}
