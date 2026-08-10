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
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw "Git whitespace validation failed." }
    Write-Output "Verification complete. Open output\dashboard.html to review the analyst dashboard."
}
finally {
    Pop-Location
}
