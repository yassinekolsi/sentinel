#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch] $InstallUv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher `py` was not found. Install 64-bit Python 3.12, then retry.'
}

& py -3.12 -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.12 is required. Confirm that `py -3.12` selects a 64-bit Python 3.12 installation.'
}

& py -3.12 -m uv --version *> $null
if ($LASTEXITCODE -ne 0) {
    if (-not $InstallUv) {
        throw 'uv is unavailable for Python 3.12. Install uv, or rerun this script with -InstallUv.'
    }
    & py -3.12 -m pip install --user uv
    if ($LASTEXITCODE -ne 0) {
        throw 'uv installation failed.'
    }
}

Push-Location -LiteralPath $repoRoot
try {
    & py -3.12 -m uv sync --frozen
    if ($LASTEXITCODE -ne 0) {
        throw 'Dependency synchronization failed.'
    }

    & py -3.12 -m uv run --frozen sentiel doctor
    if ($LASTEXITCODE -ne 0) {
        throw 'The sentiel runtime check failed.'
    }
}
finally {
    Pop-Location
}
