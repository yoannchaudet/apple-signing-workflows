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
Gatekeeper assessment, and the final ZIP. Mount the final DMG read-only and verify
that it contains the same stapled app and a usable `/Applications` symlink, with
readable files, executable modes, and framework symlinks intact. Verify the DMG's
Developer ID team, timestamp, separate `Accepted` notarization result, stapled ticket,
container integrity, and Gatekeeper assessment. This separate outer-image submission
is a native offline-distribution safeguard; it does not describe Tauri's flow.
Confirm that the two uploaded assets match their final local SHA-256 digests and sizes.
Confirm that rejected app or DMG notarization and cleanup failures cannot create or
publish a release, and that partial uploads cannot publish a draft. The native workflow
deliberately rejects custom entitlements, App Sandbox, and nested apps, extensions,
or XPC services.

For a native caller with custom Finder artwork, the no-secret `macos-15` CI job drives
Finder to save and reopen a synthetic layout and checks the final image's geometry
and icon positions. The check fails when automation times out; it does not establish
that Finder renders the background. Before production use, inspect a final signed
DMG on a clean Mac and verify the complete artwork in light mode. Confirm the
transferred `.DS_Store` and `.background/background.tiff` survive creation of the
final compressed image. Verify
the app's bytes, permissions, symlink targets, extended attributes (including
FinderInfo), and codesign verification are unchanged in the final read-only image.
The workflow does not set the app's hidden-extension FinderInfo flag; users who show
all extensions globally may see `.app`.

The native build job has no signing environment or OIDC permission, but it does run
caller-controlled Xcode build phases and Finder automation when artwork is enabled.
It validates optional artwork paths, PNG signatures and dimensions, sizes, and layout
numbers. Digests passed through job outputs are checked before the signing job
extracts the app or uses the regular Finder metadata files to create a fresh final
image. It does not mount a caller-produced image while signing credentials are
available. These checks detect transfer mismatch, not a compromised build job.
Review the application, dependencies, and workflow before approving the signing
environment.
Local synthetic credential tests prove import and stdin handling without sending Apple
requests; they do not replace this production gate.

## Native signing diagnostics and recovery

Native signing errors identify the operation and an escaped, length-limited path relative
to the application bundle or, for the DMG, the release asset directory. Only fixed,
recognized `codesign` diagnostic phrases appear;
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
