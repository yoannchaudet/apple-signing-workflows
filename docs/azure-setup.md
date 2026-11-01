# Azure setup

## Provision the foundation

Sign in to the intended subscription, verify it locally, then run:

```powershell
az login
az account show --query '{name:name, tenantId:tenantId}' --output table
./scripts/provision-azure.ps1
```

The script creates or reuses:

- one resource group;
- one Azure Key Vault using Azure RBAC;
- an operator assignment for `Key Vault Secrets Officer`.

The vault has soft delete and purge protection enabled. It keeps public network access
because GitHub-hosted runner addresses are not stable. Use a private endpoint only with
a network-connected self-hosted runner.

Names are prompted or generated at runtime. Resources receive generic discovery tags.
No subscription ID, resource-group name, or vault name is written to tracked files.

Use `-WhatIf` to inspect changes. The script never deletes or purges resources.

## Register a caller

```powershell
./scripts/register-caller.ps1 -Repository owner/application
```

The script:

1. Selects the tagged vault in the active Azure account.
2. Creates or reuses an Entra application and service principal for the caller.
3. Adds an exact federated credential for
   `repo:owner/application:environment:release`.
4. Grants `Key Vault Secrets User` at the vault scope.
5. Creates the caller's `release` environment and stores the client ID, tenant ID, and
   vault URI as GitHub environment variables.

Those values are identifiers rather than credentials. Environment variables keep them
out of repository content while making them available to the reusable workflow through
GitHub's `vars` context. No subscription ID is configured. The workflow uses
`allow-no-subscriptions` and direct Key Vault data-plane calls.

Protect the caller's `release` environment so only version tags can deploy, and require
manual approval when appropriate.

## Teardown

Teardown is deliberately manual. Purge protection prevents immediate permanent deletion.
Before removing anything, inventory callers, vault versions, backups, role assignments,
and federated credentials in Azure.
