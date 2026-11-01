#!/usr/bin/env pwsh
#Requires -Version 7.3
<#
.SYNOPSIS
    Create or reuse the Azure resource group and Key Vault used for Apple signing.

.DESCRIPTION
    Uses the active Azure CLI subscription. Concrete Azure identifiers are neither
    required in repository files nor persisted by default. Existing managed resources
    are reused; incompatible resources fail closed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $Location,
    [string] $ResourceGroup,
    [string] $VaultName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Import-Module (Join-Path $PSScriptRoot 'AppleSigning.Common.psm1') -Force

try {
    $account = Get-ActiveAzureAccount
    Write-Information "Active Azure account: $($account.name)" -InformationAction Continue

    $keyVaultProvider = Invoke-AzJson -Arguments @(
        'provider', 'show',
        '--namespace', 'Microsoft.KeyVault'
    )
    if ($keyVaultProvider.registrationState -ne 'Registered') {
        if (-not $PSCmdlet.ShouldProcess(
                'Microsoft.KeyVault',
                'Register Azure resource provider and wait for completion'
            )) {
            Write-Information 'Microsoft.KeyVault registration is required; no resources were changed.' -InformationAction Continue
            exit 0
        }

        Write-Information 'Registering the Microsoft.KeyVault resource provider...' -InformationAction Continue
        Invoke-Tool -Name az -Arguments @(
            'provider', 'register',
            '--namespace', 'Microsoft.KeyVault',
            '--wait',
            '--output', 'none'
        ) -AllowEmpty | Out-Null

        $keyVaultProvider = Invoke-AzJson -Arguments @(
            'provider', 'show',
            '--namespace', 'Microsoft.KeyVault'
        )
        if ($keyVaultProvider.registrationState -ne 'Registered') {
            throw "Microsoft.KeyVault registration did not complete; current state is '$($keyVaultProvider.registrationState)'."
        }
    }

    $managedVaults = @(Find-ManagedVault)
    if (-not $VaultName -and $managedVaults.Count -eq 1) {
        $VaultName = $managedVaults[0].name
        $ResourceGroup = $managedVaults[0].resourceGroup
        Write-Information "Reusing managed vault: $VaultName" -InformationAction Continue
    }
    elseif (-not $VaultName -and $managedVaults.Count -gt 1) {
        throw 'Multiple managed vaults exist. Rerun with -VaultName.'
    }

    if (-not $Location) {
        $Location = Read-Host 'Azure location'
    }
    if ([string]::IsNullOrWhiteSpace($Location)) {
        throw 'Azure location is required.'
    }

    if (-not $ResourceGroup) {
        $entered = Read-Host 'Resource group name [apple-signing]'
        $ResourceGroup = if ($entered) { $entered } else { 'apple-signing' }
    }
    if (-not $VaultName) {
        $defaultVault = "apple-signing-$(Get-RandomSuffix)"
        $entered = Read-Host "Globally unique Key Vault name [$defaultVault]"
        $VaultName = if ($entered) { $entered } else { $defaultVault }
    }
    if (-not (Test-KeyVaultName -Name $VaultName)) {
        throw 'Key Vault names must be 3-24 lowercase alphanumeric or hyphen characters, without consecutive hyphens.'
    }

    $tags = Get-ManagedTagArgument
    $groups = @(Invoke-AzJson -Arguments @('group', 'list'))
    $group = $groups | Where-Object { $_.name -eq $ResourceGroup }
    $groupAction = Get-ManagedResourceAction -Resource $group -ExpectedLocation $Location
    if ($groupAction -eq 'Create') {
        if ($PSCmdlet.ShouldProcess($ResourceGroup, "Create resource group in $Location")) {
            $arguments = @(
                'group', 'create',
                '--name', $ResourceGroup,
                '--location', $Location,
                '--tags'
            ) + $tags
            $group = Invoke-AzJson -Arguments $arguments
        }
    }

    $vaults = @(Invoke-AzJson -Arguments @('keyvault', 'list'))
    $vault = $vaults | Where-Object { $_.name -eq $VaultName }
    $vaultAction = Get-ManagedResourceAction -Resource $vault -ExpectedLocation $Location
    if ($vaultAction -eq 'Create') {
        if ($PSCmdlet.ShouldProcess($VaultName, 'Create RBAC-enabled, purge-protected Key Vault')) {
            $arguments = @(
                'keyvault', 'create',
                '--name', $VaultName,
                '--resource-group', $ResourceGroup,
                '--location', $Location,
                '--enable-rbac-authorization', 'true',
                '--enable-purge-protection', 'true',
                '--retention-days', '90',
                '--public-network-access', 'Enabled',
                '--tags'
            ) + $tags
            $vault = Invoke-AzJson -Arguments $arguments
        }
    }

    if (-not $vault) {
        Write-Information 'WhatIf complete; no resources were changed.' -InformationAction Continue
        exit 0
    }
    if (-not $vault.properties.enableRbacAuthorization) {
        throw "Vault '$VaultName' exists without Azure RBAC authorization."
    }
    if (-not $vault.properties.enablePurgeProtection) {
        throw "Vault '$VaultName' exists without purge protection."
    }
    if ($vault.resourceGroup -ne $ResourceGroup) {
        throw "Vault '$VaultName' belongs to resource group '$($vault.resourceGroup)', not '$ResourceGroup'."
    }

    $operatorId = (Invoke-Tool -Name az -Arguments @(
            'ad', 'signed-in-user', 'show', '--query', 'id', '--output', 'tsv'
        )).Trim()
    $assignments = @(Invoke-AzJson -Arguments @(
            'role', 'assignment', 'list',
            '--assignee-object-id', $operatorId,
            '--scope', $vault.id,
            '--role', 'Key Vault Secrets Officer'
        ))
    if ($assignments.Count -eq 0 -and
        $PSCmdlet.ShouldProcess($operatorId, "Grant Key Vault Secrets Officer on $VaultName")) {
        Invoke-Tool -Name az -Arguments @(
            'role', 'assignment', 'create',
            '--assignee-object-id', $operatorId,
            '--assignee-principal-type', 'User',
            '--role', 'Key Vault Secrets Officer',
            '--scope', $vault.id,
            '--output', 'none'
        ) -AllowEmpty | Out-Null
    }

    Write-Information 'Azure signing foundation is ready.' -InformationAction Continue
    Write-Information "Resource group: $ResourceGroup" -InformationAction Continue
    Write-Information "Vault: $VaultName" -InformationAction Continue
}
catch {
    [Console]::Error.WriteLine("provision-azure: $($_.Exception.Message)")
    exit 1
}
