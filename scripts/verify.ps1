[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $projectRoot "src"

Push-Location $projectRoot
try {
    python -m ruff check src tests
    python -m unittest discover -s tests -v
    python -m soc_lab data/sample_events.jsonl `
        --json output/findings.json `
        --markdown output/findings.md `
        --html output/dashboard.html | Out-Null
    Write-Output "Verification complete. Open output\dashboard.html to review the analyst dashboard."
}
finally {
    Pop-Location
}
