# Apple signing workflows

Reusable GitHub Actions workflows and operator tooling for signing and notarizing Apple
applications with credentials stored in Azure Key Vault.

## Security model

- GitHub Actions authenticates to Azure with OIDC. There is no Azure client secret.
- Entra federation authorizes an exact caller repository and its protected `release`
  environment.
- Key Vault stores exportable signing material. The workflow repository stores none.
- Concrete Azure identifiers live in caller environment settings, not in git.
- Public callers require this reusable-workflow repository to be public. Public workflow
  code does not grant vault access; Entra federation and Key Vault RBAC do.

The first workflow supports universal Tauri applications distributed outside the Mac
App Store with a Developer ID Application certificate. iOS requires a separate workflow,
Apple Distribution credentials, and provisioning profiles.

## Operator quick start

Prerequisites: PowerShell 7.3+, Azure CLI, GitHub CLI, an active Apple Developer Program
membership, and permission to create Azure resources and role assignments.

```powershell
az login
gh auth login

./scripts/provision-azure.ps1
./scripts/register-caller.ps1 -Repository owner/application
./scripts/manage-vault.ps1 -Action Hydrate -Repository owner/application
./scripts/manage-vault.ps1 -Action Verify -Repository owner/application
```

These commands discover the active Azure subscription at runtime. They do not persist
its identifier. See [Azure setup](docs/azure-setup.md) and
[credential operations](docs/credentials.md).

## Calling the workflow

The caller keeps a small tag-triggered workflow. Its protected `release` environment
contains the values installed by `register-caller.ps1` plus Apple metadata:

- Variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_KEY_VAULT_URI`, `APPLE_ID`,
  `APPLE_TEAM_ID`, `APPLE_SIGNING_IDENTITY`

```yaml
jobs:
  release:
    permissions:
      contents: write
      id-token: write
    uses: yoannchaudet/apple-signing-workflows/.github/workflows/release-macos-tauri.yml@WORKFLOW_COMMIT_SHA
```

Replace `WORKFLOW_COMMIT_SHA` with a reviewed full commit SHA. Never use a mutable
branch for a signing workflow.

The identifiers are protected environment variables, so the called workflow reads them
through the `vars` context without embedding values in repository content or passing
secrets.

## Project status

The repository foundation is ready for disposable Azure and sample-application
integration testing. Do not migrate a production release until the checklist in
[security.md](docs/security.md) passes.
