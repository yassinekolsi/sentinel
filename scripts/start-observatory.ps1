#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

Push-Location -LiteralPath $repoRoot
try {
    if (Test-Path -LiteralPath 'artifacts/phase-final/real') {
        & py -3.12 -m uv run --frozen python scripts/export-next-data.py
        if ($LASTEXITCODE -ne 0) { throw 'Trace export failed.' }
    }
    elseif (-not (Test-Path -LiteralPath 'frontend/data/index.json')) {
        throw 'No raw artifacts or exported demo traces are available.'
    }
    Push-Location -LiteralPath (Join-Path $repoRoot 'frontend')
    try {
        if (-not (Test-Path -LiteralPath 'node_modules')) {
            & npm.cmd ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
        }
        & npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        Write-Host 'Open http://127.0.0.1:3000 in the browser.'
        & npm.cmd run start
        if ($LASTEXITCODE -ne 0) { throw 'Frontend server exited with an error.' }
    }
    finally { Pop-Location }
}
finally { Pop-Location }
