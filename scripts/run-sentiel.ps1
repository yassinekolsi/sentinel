#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('doctor', 'serve', 'run', 'evaluate', 'view', 'thinking', 'report')]
    [string] $Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]] $SentielArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher `py` was not found. Run scripts/setup-windows.ps1 after installing Python 3.12.'
}

Push-Location -LiteralPath $repoRoot
try {
    & py -3.12 -m uv run --frozen sentiel $Command @SentielArguments
    if ($LASTEXITCODE -ne 0) {
        throw "sentiel $Command failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
