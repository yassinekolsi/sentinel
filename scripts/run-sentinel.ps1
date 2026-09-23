#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('doctor', 'serve', 'run', 'evaluate', 'view', 'dashboard', 'bundle', 'verify-bundle', 'thinking', 'report')]
    [string] $Command,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]] $SentinelArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher `py` was not found. Run scripts/setup-windows.ps1 after installing Python 3.12.'
}

Push-Location -LiteralPath $repoRoot
try {
    & py -3.12 -m uv run --frozen sentinel-firewall $Command @SentinelArguments
    if ($LASTEXITCODE -ne 0) {
        throw "sentinel-firewall $Command failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
