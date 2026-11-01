# Security model and release gate

## Trust boundary

A reusable workflow standardizes signing but is not a secret-isolation boundary. Code
and dependencies running in the signing job can read its credentials. Protect release
tags, require approval on the `release` environment, review dependency changes, and pin
the reusable workflow and every third-party action to immutable commits.

Each caller has its own Entra workload identity. Its federated credential matches the
caller repository and `release` environment exactly. Key Vault RBAC grants CI read-only
access. Operators receive write access separately. Client, tenant, and vault identifiers
are protected GitHub environment variables; they are not credentials.

## Before production migration

Use disposable resources and a sample Tauri application to prove:

- OIDC login succeeds without a subscription ID.
- A caller outside the allowlist cannot exchange a token.
- Direct Key Vault data-plane reads work without management-plane Reader access.
- Secrets are masked and absent from logs, outputs, caches, and artifacts.
- The Developer ID signature, notarization, stapling, Gatekeeper assessment, universal
  architectures, updater signature, and draft release assets are valid.
- Cleanup runs after both successful and deliberately failed builds.

Audit the complete repository history before changing this repository from private to
public. Public visibility is required for public callers.

## Backups and incidents

Keep encrypted offline backups of exportable Apple credentials and updater keys. Losing
the updater private key can strand existing installations. If exposure is suspected,
disable the affected Key Vault version and federated credential, preserve audit logs,
and follow the appropriate Apple revocation and release-recovery process.
