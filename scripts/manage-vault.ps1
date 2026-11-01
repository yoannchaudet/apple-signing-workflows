#!/usr/bin/env pwsh
#Requires -Version 7.3
<#
.SYNOPSIS
    Hydrate, verify, rotate, or roll back Apple signing values in Azure Key Vault.

.DESCRIPTION
    Secret values are accepted only through hidden prompts or file paths. Rotation
    creates new Key Vault versions. No action purges or automatically disables history.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Hydrate', 'Verify', 'Rotate', 'Rollback', 'List')]
    [string] $Action,

    [string] $Repository,
    [string] $VaultName,
    [string] $TauriProjectPath,

    [ValidateSet(
        'apple-certificate',
        'apple-notarization-password',
        'tauri-private-key',
        'tauri-private-key-password'
    )]
    [string] $Secret
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Import-Module (Join-Path $PSScriptRoot 'AppleSigning.Common.psm1') -Force

$emptyPasswordMarker = '__EMPTY__'
$maximumSecretBytes = 25KB

function Read-ExistingFile {
    param([Parameter(Mandatory)][string] $Prompt)

    $path = (Read-Host $Prompt).Trim()
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "File not found: $path"
    }
    return (Resolve-Path -LiteralPath $path).Path
}

function Read-PasswordText {
    param(
        [Parameter(Mandatory)][string] $Prompt,
        [switch] $AllowEmpty
    )

    $secure = Read-ConfirmedSecureString -Prompt $Prompt -AllowEmpty:$AllowEmpty
    return ConvertFrom-ProtectedString -Value $secure
}

function Assert-SecretSize {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $Value
    )

    if (-not (Test-SecretValueSize -Value $Value -MaximumBytes $maximumSecretBytes)) {
        $size = [Text.Encoding]::UTF8.GetByteCount($Value)
        throw "Encoded value '$Name' is $size bytes; Key Vault secrets support at most $maximumSecretBytes bytes."
    }
}

function Assert-Pkcs12 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        '',
        Justification = 'The shared PKCS#12 validator requires the decoded password.'
    )]
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][string] $Password
    )

    if (-not (Test-Pkcs12Bundle -Bytes $Bytes -Password $Password)) {
        throw 'The PKCS#12 file/password is invalid or does not contain a certificate with a private key.'
    }
}

function Publish-VaultSecret {
    param(
        [Parameter(Mandatory)][string] $Vault,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $Value,
        [Parameter(Mandatory)][string] $ContentType
    )

    Assert-SecretSize -Name $Name -Value $Value
    $path = New-ProtectedTempFile -Bytes ([Text.Encoding]::UTF8.GetBytes($Value))
    try {
        Invoke-Tool -Name az -Arguments @(
            'keyvault', 'secret', 'set',
            '--vault-name', $Vault,
            '--name', $Name,
            '--file', $path,
            '--encoding', 'utf-8',
            '--content-type', $ContentType,
            '--output', 'none'
        ) -Sensitive -AllowEmpty | Out-Null
    }
    finally {
        Remove-ProtectedTempFile -Path $path
    }
}

function Get-SecretRecord {
    param(
        [Parameter(Mandatory)][string] $Vault,
        [Parameter(Mandatory)][string] $Name
    )

    return Invoke-AzJson -Arguments @(
        'keyvault', 'secret', 'show',
        '--vault-name', $Vault,
        '--name', $Name,
        '--query', '{id:id,enabled:attributes.enabled,expires:attributes.expires,updated:attributes.updated,contentType:contentType}'
    )
}

function Format-SecretRecord {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)] $Metadata
    )

    $version = ($Metadata.id -split '/')[-1]
    [pscustomobject]@{
        Name        = $Name
        Version     = $version
        Enabled     = $Metadata.enabled
        Updated     = $Metadata.updated
        Expires     = $Metadata.expires
        ContentType = $Metadata.contentType
    }
}

function Read-CertificatePair {
    $path = Read-ExistingFile -Prompt 'Path to the Developer ID PKCS#12 file'
    $bytes = [IO.File]::ReadAllBytes($path)
    $password = Read-PasswordText -Prompt 'PKCS#12 export password'
    Assert-Pkcs12 -Bytes $bytes -Password $password
    return @{
        Certificate = ConvertTo-Base64 -Bytes $bytes
        Password    = $password
    }
}

function Read-UpdaterKey {
    $path = Read-ExistingFile -Prompt 'Path to the Tauri updater private key'
    return ConvertTo-Base64 -Bytes ([IO.File]::ReadAllBytes($path))
}

function Read-UpdaterPassword {
    $password = Read-PasswordText -Prompt 'Tauri updater-key password (may be empty)' -AllowEmpty
    if ($password.Length -eq 0) {
        return $emptyPasswordMarker
    }
    if ($password -ceq $emptyPasswordMarker) {
        throw "The literal value '$emptyPasswordMarker' is reserved to represent an empty password."
    }
    return $password
}

function Get-HydrationSet {
    param([Parameter(Mandatory)][bool] $IncludeRepositoryValues)

    $certificate = Read-CertificatePair
    $values = [ordered]@{
        Certificate          = $certificate.Certificate
        CertificatePassword  = $certificate.Password
        NotarizationPassword = Read-PasswordText -Prompt 'Apple notarization app-specific password'
    }
    if ($IncludeRepositoryValues) {
        $values.UpdaterKey = Read-UpdaterKey
        $values.UpdaterPassword = Read-UpdaterPassword
    }
    return $values
}

function Publish-VaultSecretSet {
    param(
        [Parameter(Mandatory)][string] $Vault,
        [Parameter(Mandatory)] $Names,
        [Parameter(Mandatory)] $Values
    )

    $contentTypes = @{
        Certificate          = 'application/x-pkcs12;base64'
        CertificatePassword  = 'text/plain'
        NotarizationPassword = 'text/plain'
        UpdaterKey           = 'application/vnd.tauri.updater-key;base64'
        UpdaterPassword      = 'text/plain'
    }
    foreach ($key in $Values.Keys) {
        Publish-VaultSecret -Vault $Vault -Name $Names[$key] -Value $Values[$key] -ContentType $contentTypes[$key]
    }
}

function Select-PreviousVersion {
    param(
        [Parameter(Mandatory)][string] $Vault,
        [Parameter(Mandatory)][string] $Name
    )

    $current = Get-SecretRecord -Vault $Vault -Name $Name
    $versions = @(Invoke-AzJson -Arguments @(
            'keyvault', 'secret', 'list-versions',
            '--vault-name', $Vault,
            '--name', $Name
        ) | Where-Object { $_.attributes.enabled -and $_.id -ne $current.id })
    if ($versions.Count -lt 1) {
        throw "Secret '$Name' has no previous enabled version."
    }

    for ($index = 0; $index -lt $versions.Count; $index++) {
        $version = ($versions[$index].id -split '/')[-1]
        Write-Information "[$($index + 1)] $version ($($versions[$index].attributes.updated))" -InformationAction Continue
    }
    $selection = Read-Host "Select a version of '$Name' to promote"
    $number = 0
    if (-not [int]::TryParse($selection, [ref] $number) -or
        $number -lt 1 -or $number -gt $versions.Count) {
        throw 'Invalid version selection.'
    }
    return ($versions[$number - 1].id -split '/')[-1]
}

function Get-SecretVersionValue {
    param(
        [Parameter(Mandatory)][string] $Vault,
        [Parameter(Mandatory)][string] $Name,
        [string] $Version
    )

    $arguments = @(
        'keyvault', 'secret', 'show',
        '--vault-name', $Vault,
        '--name', $Name
    )
    if ($Version) {
        $arguments += @('--version', $Version)
    }
    $arguments += @('--query', 'value', '--output', 'tsv')
    return Invoke-Tool -Name az -Arguments $arguments -Sensitive
}

try {
    Assert-Tool -Name az
    $null = Get-ActiveAzureAccount
    $vault = Resolve-ManagedVault -VaultName $VaultName
    $names = Get-SigningSecretCatalog -Repository $Repository

    if ($Action -in @('Hydrate', 'Verify') -and -not $Repository) {
        throw '-Repository is required so repository-specific updater credentials can be managed.'
    }
    if ($Action -in @('Rotate', 'Rollback') -and -not $Secret) {
        throw "-Secret is required for $Action."
    }
    if ($Secret -like 'tauri-*' -and -not $Repository) {
        throw '-Repository is required for Tauri updater credentials.'
    }

    switch ($Action) {
        'Hydrate' {
            $values = Get-HydrationSet -IncludeRepositoryValues $true
            if ($PSCmdlet.ShouldProcess($vault.name, 'Create new versions for the complete signing credential set')) {
                Publish-VaultSecretSet -Vault $vault.name -Names $names -Values $values
            }
        }
        { $_ -in @('Verify', 'List') } {
            $rows = foreach ($name in $names.Values) {
                try {
                    Format-SecretRecord -Name $name -Metadata (Get-SecretRecord -Vault $vault.name -Name $name)
                }
                catch {
                    if ($Action -eq 'Verify') { throw "Required secret '$name' is missing or inaccessible." }
                    [pscustomobject]@{
                        Name = $name; Version = '<missing>'; Enabled = $false
                        Updated = $null; Expires = $null; ContentType = $null
                    }
                }
            }
            $rows | Format-Table -AutoSize
            if ($Action -eq 'Verify') {
                $certificateValue = Get-SecretVersionValue -Vault $vault.name -Name $names.Certificate
                $certificatePassword = Get-SecretVersionValue -Vault $vault.name -Name $names.CertificatePassword
                try {
                    $certificateBytes = [Convert]::FromBase64String($certificateValue)
                }
                catch {
                    throw "Secret '$($names.Certificate)' is not valid base64."
                }
                Assert-Pkcs12 -Bytes $certificateBytes -Password $certificatePassword

                $updaterValue = Get-SecretVersionValue -Vault $vault.name -Name $names.UpdaterKey
                try {
                    $updaterBytes = [Convert]::FromBase64String($updaterValue)
                }
                catch {
                    throw "Secret '$($names.UpdaterKey)' is not valid base64."
                }
                if ($updaterBytes.Length -eq 0) {
                    throw "Secret '$($names.UpdaterKey)' decodes to an empty updater key."
                }
                if (-not $TauriProjectPath) {
                    throw '-TauriProjectPath is required for Verify so the stored updater key and password can be tested with the project Tauri CLI.'
                }
                $updaterPassword = Get-SecretVersionValue -Vault $vault.name -Name $names.UpdaterPassword
                if ($updaterPassword -ceq $emptyPasswordMarker) {
                    $updaterPassword = ''
                }
                Test-TauriUpdaterCredential `
                    -PrivateKeyBytes $updaterBytes `
                    -Password $updaterPassword `
                    -TauriProjectPath $TauriProjectPath | Out-Null
            }
        }
        'Rotate' {
            if ($Secret -eq 'tauri-private-key') {
                $confirmation = Read-Host 'Updater-key replacement can strand existing clients. Type ROTATE UPDATER KEY'
                if (-not (Test-ExactConfirmation -Actual $confirmation -Expected 'ROTATE UPDATER KEY')) {
                    throw 'Updater-key rotation was not confirmed.'
                }
            }
            else {
                $confirmation = Read-Host 'Confirm no release is running. Type ROTATE'
                if (-not (Test-ExactConfirmation -Actual $confirmation -Expected 'ROTATE')) {
                    throw 'Rotation was not confirmed.'
                }
            }

            $values = [ordered]@{}
            switch ($Secret) {
                'apple-certificate' {
                    $pair = Read-CertificatePair
                    $values.Certificate = $pair.Certificate
                    $values.CertificatePassword = $pair.Password
                }
                'apple-notarization-password' {
                    $values.NotarizationPassword = Read-PasswordText -Prompt 'New Apple notarization app-specific password'
                }
                'tauri-private-key' {
                    $values.UpdaterKey = Read-UpdaterKey
                }
                'tauri-private-key-password' {
                    $values.UpdaterPassword = Read-UpdaterPassword
                }
            }
            if ($PSCmdlet.ShouldProcess($vault.name, "Rotate $Secret")) {
                Publish-VaultSecretSet -Vault $vault.name -Names $names -Values $values
            }
        }
        'Rollback' {
            $keys = switch ($Secret) {
                'apple-certificate' { @('Certificate', 'CertificatePassword') }
                'apple-notarization-password' { @('NotarizationPassword') }
                'tauri-private-key' { @('UpdaterKey') }
                'tauri-private-key-password' { @('UpdaterPassword') }
            }
            $values = [ordered]@{}
            foreach ($key in $keys) {
                $name = $names[$key]
                $version = Select-PreviousVersion -Vault $vault.name -Name $name
                $values[$key] = Get-SecretVersionValue -Vault $vault.name -Name $name -Version $version
            }
            if ($Secret -eq 'apple-certificate') {
                $bytes = [Convert]::FromBase64String($values.Certificate)
                Assert-Pkcs12 -Bytes $bytes -Password $values.CertificatePassword
            }
            $confirmation = Read-Host "Type ROLLBACK to promote the selected version of $Secret"
            if (-not (Test-ExactConfirmation -Actual $confirmation -Expected 'ROLLBACK')) {
                throw 'Rollback was not confirmed.'
            }
            if ($PSCmdlet.ShouldProcess($vault.name, "Roll back $Secret by creating a new current version")) {
                Publish-VaultSecretSet -Vault $vault.name -Names $names -Values $values
            }
        }
    }

    Write-Information "$Action completed for vault '$($vault.name)'." -InformationAction Continue
}
catch {
    [Console]::Error.WriteLine("manage-vault: $($_.Exception.Message)")
    exit 1
}
