#!/usr/bin/env pwsh
#Requires -Version 7.3
<#
.SYNOPSIS
    Register a GitHub repository as an OIDC-authenticated signing caller.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $Repository,

    [string] $Environment = 'release',
    [string] $VaultName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Import-Module (Join-Path $PSScriptRoot 'AppleSigning.Common.psm1') -Force

try {
    Assert-Tool -Name az
    Assert-Tool -Name gh
    if ($Environment -notmatch '^[A-Za-z0-9_.-]+$') {
        throw 'Environment may contain only letters, numbers, underscores, periods, and hyphens.'
    }
    $account = Get-ActiveAzureAccount
    $repositoryProfile = Get-RepositoryProfile -Repository $Repository
    $vault = Resolve-ManagedVault -VaultName $VaultName
    $displayName = "github-apple-signing-$repositoryProfile"
    $managementReference = 'https://github.com/yoannchaudet/apple-signing-workflows'

    $apps = @(Invoke-AzJson -Arguments @('ad', 'app', 'list', '--display-name', $displayName))
    $exactApps = @($apps | Where-Object { $_.displayName -eq $displayName })
    if ($exactApps.Count -gt 1) {
        throw "Multiple Entra applications use display name '$displayName'."
    }
    if ($exactApps.Count -eq 0) {
        if (-not $PSCmdlet.ShouldProcess($displayName, 'Create Entra application and service principal')) {
            Write-Information 'WhatIf complete; no caller was registered.' -InformationAction Continue
            exit 0
        }
        $app = Invoke-AzJson -Arguments @(
            'ad', 'app', 'create',
            '--display-name', $displayName,
            '--service-management-reference', $managementReference
        )
        $servicePrincipal = Invoke-AzJson -Arguments @('ad', 'sp', 'create', '--id', $app.appId)
    }
    else {
        $app = Invoke-AzJson -Arguments @('ad', 'app', 'show', '--id', $exactApps[0].id)
        if ($app.serviceManagementReference -ne $managementReference) {
            throw "Entra application '$displayName' exists without the required management reference."
        }
        $servicePrincipals = @(Invoke-AzJson -Arguments @('ad', 'sp', 'list', '--filter', "appId eq '$($app.appId)'"))
        if ($servicePrincipals.Count -eq 0) {
            if (-not $PSCmdlet.ShouldProcess($displayName, 'Create missing service principal')) {
                exit 0
            }
            $servicePrincipal = Invoke-AzJson -Arguments @('ad', 'sp', 'create', '--id', $app.appId)
        }
        else {
            $servicePrincipal = $servicePrincipals[0]
        }
    }

    $subject = "repo:${Repository}:environment:${Environment}"
    $credentialName = ConvertTo-SafeName -Value "$repositoryProfile-$Environment"
    $credentials = @(Invoke-AzJson -Arguments @(
            'ad', 'app', 'federated-credential', 'list', '--id', $app.id
        ))
    $credential = $credentials | Where-Object { $_.name -eq $credentialName }
    if ($credential) {
        if (-not (Test-FederatedCredentialTrust -FederatedIdentity $credential -Subject $subject)) {
            throw "Federated credential '$credentialName' exists with incompatible trust settings."
        }
    }
    elseif ($PSCmdlet.ShouldProcess($subject, 'Create GitHub OIDC federated credential')) {
        $definition = @{
            name        = $credentialName
            issuer      = 'https://token.actions.githubusercontent.com'
            subject     = $subject
            description = "GitHub Actions signing for $Repository"
            audiences   = @('api://AzureADTokenExchange')
        } | ConvertTo-Json
        $path = New-ProtectedTempFile -Bytes ([Text.Encoding]::UTF8.GetBytes($definition))
        try {
            Invoke-Tool -Name az -Arguments @(
                'ad', 'app', 'federated-credential', 'create',
                '--id', $app.id,
                '--parameters', "@$path",
                '--output', 'none'
            ) -AllowEmpty | Out-Null
        }
        finally {
            Remove-ProtectedTempFile -Path $path
        }
    }

    $assignments = @(Invoke-AzJson -Arguments @(
            'role', 'assignment', 'list',
            '--assignee-object-id', $servicePrincipal.id,
            '--scope', $vault.id,
            '--role', 'Key Vault Secrets User'
        ))
    if ($assignments.Count -eq 0 -and
        $PSCmdlet.ShouldProcess($servicePrincipal.id, 'Grant Key Vault Secrets User')) {
        $created = $false
        for ($attempt = 1; $attempt -le 6 -and -not $created; $attempt++) {
            try {
                Invoke-Tool -Name az -Arguments @(
                    'role', 'assignment', 'create',
                    '--assignee-object-id', $servicePrincipal.id,
                    '--assignee-principal-type', 'ServicePrincipal',
                    '--role', 'Key Vault Secrets User',
                    '--scope', $vault.id,
                    '--output', 'none'
                ) -AllowEmpty | Out-Null
                $created = $true
            }
            catch {
                if ($attempt -eq 6) { throw }
                Start-Sleep -Seconds ([Math]::Min(5 * $attempt, 20))
            }
        }
    }

    if ($PSCmdlet.ShouldProcess("$Repository/$Environment", 'Configure GitHub environment identifiers')) {
        Invoke-Tool -Name gh -Arguments @(
            'api', '--method', 'PUT',
            "repos/$Repository/environments/$Environment",
            '--input', '-',
            '--silent'
        ) -StandardInput '{}' -AllowEmpty | Out-Null
    }

    # gh secret set reads the value from standard input when --body is omitted, keeping
    # identifiers out of process arguments and repository content.
    $githubValues = @{
        AZURE_CLIENT_ID     = "$($app.appId)"
        AZURE_TENANT_ID     = "$($account.tenantId)"
        AZURE_KEY_VAULT_URI = "$($vault.properties.vaultUri)"
    }
    foreach ($entry in $githubValues.GetEnumerator()) {
        if ($PSCmdlet.ShouldProcess("$Repository/$Environment", "Set $($entry.Key) environment variable")) {
            Invoke-Tool -Name gh -Arguments @(
                'variable', 'set', $entry.Key,
                '--repo', $Repository,
                '--env', $Environment
            ) -StandardInput $entry.Value -Sensitive -AllowEmpty | Out-Null
        }
    }

    Write-Information "Caller '$Repository' is registered for environment '$Environment'." -InformationAction Continue
}
catch {
    [Console]::Error.WriteLine("register-caller: $($_.Exception.Message)")
    exit 1
}
