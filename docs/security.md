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

For a native caller, use a sample XcodeGen app with an embedded framework. Verify both
architectures, tag and bundle-version agreement, every nested signature, hardened
runtime, the Developer ID team, an `Accepted` notarization result, the stapled ticket,
Gatekeeper assessment, and the final ZIP. Confirm that rejected notarization and cleanup
failures cannot create or publish a release. The native workflow deliberately rejects
custom entitlements, App Sandbox, and nested apps, extensions, or XPC services.

The native build job has no signing environment or OIDC permission. The signing job
receives a tar archive, safely extracts its data, and does not execute the app or caller
scripts. This reduces exposure but does not make untrusted release code safe. Review
the application, dependencies, and workflow before approving the signing environment.
Local synthetic credential tests prove import and stdin handling without sending Apple
requests; they do not replace this production gate.

## Native signing diagnostics and recovery

Native signing errors identify the operation and an escaped, length-limited path relative
to the application bundle. Only fixed, recognized `codesign` diagnostic phrases appear;
raw output, signer metadata, absolute paths, and unknown diagnostics remain withheld.
Other subprocess failures retain blanket output protection. A diagnostic identifies what
the tool reported, not an independently established root cause.

A tagged caller pins an immutable shared workflow commit. Updating the shared workflow
or the caller's default branch does not update an existing tag or its reruns. After a
reviewed fix is published, update the caller's pin and use its normal new-version release
process. Do not move an existing release tag. Recovering an unreleased version through a
separate workflow requires explicit review and approval, including the source commit,
version checks, shared workflow SHA, signing environment, and release destination.

Audit the complete repository history before changing this repository from private to
public. Public visibility is required for public callers.

## Backups and incidents

Keep encrypted offline backups of exportable Apple credentials and updater keys. Losing
the updater private key can strand existing installations. If exposure is suspected,
disable the affected Key Vault version and federated credential, preserve audit logs,
and follow the appropriate Apple revocation and release-recovery process.
