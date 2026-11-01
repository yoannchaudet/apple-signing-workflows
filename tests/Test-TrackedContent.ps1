#!/usr/bin/env pwsh
#Requires -Version 7.3

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$forbiddenExtensions = @('.cer', '.key', '.mobileprovision', '.p12', '.pem')
$violations = [Collections.Generic.List[string]]::new()

$files = Get-ChildItem -Path $root -Recurse -Force -File |
    Where-Object { $_.FullName -notlike "$root/.git/*" }

foreach ($file in $files) {
    if ($file.Extension.ToLowerInvariant() -in $forbiddenExtensions) {
        $violations.Add("Signing file is present: $($file.FullName)")
        continue
    }

    $text = [IO.File]::ReadAllText($file.FullName)
    if ($text -match '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b') {
        $violations.Add("GUID-shaped identifier in $($file.FullName)")
    }
    if ($text -match '(?i)/subscriptions/[0-9a-f-]{36}\b') {
        $violations.Add("Azure subscription path in $($file.FullName)")
    }
    if ($text -match '(?i)https://[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net') {
        $violations.Add("Concrete Key Vault URI in $($file.FullName)")
    }
    if ($text -match '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----') {
        $violations.Add("PEM private key in $($file.FullName)")
    }
}

$history = git -C $root log --all --format= -p
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to inspect git history.'
}
$historyText = $history -join [Environment]::NewLine
if ($historyText -match '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b') {
    $violations.Add('GUID-shaped identifier in git history')
}
if ($historyText -match '(?i)/subscriptions/[0-9a-f-]{36}\b') {
    $violations.Add('Azure subscription path in git history')
}
if ($historyText -match '(?i)https://[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net') {
    $violations.Add('Concrete Key Vault URI in git history')
}
if ($historyText -match '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----') {
    $violations.Add('PEM private key in git history')
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
}

Write-Output 'Tracked-content guard passed.'
