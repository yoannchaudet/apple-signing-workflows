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

The workflows support universal Tauri and native XcodeGen macOS applications distributed
outside the Mac App Store with a Developer ID Application certificate. iOS requires a
separate workflow, Apple Distribution credentials, and provisioning profiles.

## Operator quick start

Prerequisites: PowerShell 7.3+, Azure CLI, GitHub CLI, an active Apple Developer Program
membership, and permission to create Azure resources and role assignments.

```powershell
az login
gh auth login

./scripts/provision-azure.ps1
./scripts/register-caller.ps1 -Repository owner/application
./scripts/manage-vault.ps1 -Action Hydrate -Repository owner/application
./scripts/manage-vault.ps1 -Action Verify -Repository owner/application -TauriProjectPath ../application
```

These commands discover the active Azure subscription at runtime. They do not persist
its identifier. See [Azure setup](docs/azure-setup.md) and
[credential operations](docs/credentials.md).

## Calling the Tauri workflow

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

## Calling the native workflow

Use `release-macos-xcode.yml` for a native XcodeGen project with a shared application
scheme. The workflow builds an unsigned universal Release app in a read-only job.
A separate job enters the caller's protected `release` environment, signs the app and
embedded frameworks, notarizes it, staples the accepted ticket, and packages the app
as a ZIP and a drag-to-Applications disk image (DMG).
The signing job does not check out or run caller build scripts.

The caller supplies a stable `vMAJOR.MINOR.PATCH` tag, with `contents: write` and
`id-token: write` permissions. The app's version must match the tag. The workflow sets
the marketing version from the tag and the build version from `github.run_number`.

```yaml
on:
  push:
    tags: ["v*"]
  workflow_dispatch:

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

jobs:
  release:
    permissions:
      contents: write
      id-token: write
    uses: yoannchaudet/apple-signing-workflows/.github/workflows/release-macos-xcode.yml@WORKFLOW_COMMIT_SHA
    with:
      project: Application.xcodeproj
      scheme: Application
      app-name: Application
      dmg-background-path: installer/background.png
      dmg-background-2x-path: installer/background@2x.png
```

Replace `WORKFLOW_COMMIT_SHA` with the full reviewed commit SHA after that commit is
published to this repository. A local commit is not available to GitHub Actions. If a
caller is public, this repository must also be public before that caller can use it.
Omit both background inputs to keep the existing headless DMG layout. Artwork paths are
relative to `working-directory`; provide both 1x and 2x PNGs. The defaults below
expect 680×400 and 1360×800 images; set the layout inputs for different artwork.

The native workflow accepts these inputs:

| Input | Required | Default | Meaning |
|---|---|---|---|
| `project` | Yes | None | Generated `.xcodeproj` filename, not a path |
| `scheme` | Yes | None | Shared application scheme |
| `app-name` | Yes | None | Built product name, without `.app` |
| `working-directory` | No | `.` | Directory containing `project.yml` |
| `release-name` | No | Repository name and tag | Release title |
| `release-body` | No | DMG installation and manual-update text | Text before generated release notes |
| `release-draft` | No | `true` | Keep the release as a draft |
| `dmg-background-path` | No | Empty | 1x PNG path relative to `working-directory`; requires the 2x path |
| `dmg-background-2x-path` | No | Empty | 2x PNG path relative to `working-directory`; requires the 1x path |
| `dmg-window-width` | No | `680` | Finder window width in points |
| `dmg-window-height` | No | `428` | Finder window height including its title bar |
| `dmg-icon-size` | No | `120` | Finder icon size in points |
| `dmg-text-size` | No | `13` | Finder icon-label text size in points |
| `dmg-app-x`, `dmg-app-y` | No | `180`, `170` | Center coordinates for the app icon |
| `dmg-applications-x`, `dmg-applications-y` | No | `500`, `170` | Center coordinates for the Applications icon |

It uses the same six `release` environment variables as the Tauri workflow. It reads
only `apple-developer-id-certificate`, `apple-developer-id-password`, and
`apple-notarization-password` from Key Vault. It needs no Tauri updater key, Azure client
secret, subscription variable, or caller-provided GitHub secret. The built-in
`GITHUB_TOKEN` creates the release.

The workflow creates two release assets:

| Asset | Contents |
|---|---|
| `APP_NAME-vMAJOR.MINOR.PATCH-universal-macos.dmg` | Stapled `.app` and an `Applications` symlink for drag-to-install |
| `APP_NAME-vMAJOR.MINOR.PATCH-universal-macos.zip` | Standalone stapled `.app`, preserving the existing ZIP filename |

In asset filenames only, spaces in `APP_NAME` become dots to avoid GitHub's upload
filename rewriting. Application bundle and volume names keep their spaces.

Both formats preserve executable permissions and framework symlinks and use
distributable directory and file permissions. With no background inputs, the DMG
retains its existing headless `hdiutil` layout. When artwork is enabled, the no-secret
macOS build job validates both regular PNG files (each at most 20 MiB), combines them
into a multi-resolution TIFF with the system `tiffutil`, and uses Finder to save and
reopen a read-write layout image. The 1x image width must equal the window width; its
height must fit within the window height minus 28 points for Finder's title bar. The
2x image must have exactly twice both dimensions. Window width must be an integer from
160 to 10000 and height from 100 to 10000; icon size must be from 16 to 512 and text
size from 8 to 32. Icon center coordinates must be integers within the window width
and usable height, inclusive. Finder must also be able to persist the requested bounds
and settings on the runner's display. The default layout has a 680×428-point window,
120-point icons, 13-point labels, app and Applications centers at (180,170) and
(500,170), and no toolbar, sidebar, status bar, or path bar. The `.DS_Store` and
`.background/background.tiff` payloads are transferred with SHA-256 checks. The
signing job creates a fresh compressed image from the verified app and those files,
without mounting a caller-produced image or running Finder. Finder automation is
bounded and fails the build if it is unavailable or required layout records are
missing. Inspect the final image on a clean Mac before publication; record presence
alone does not establish that Finder renders the artwork.

The workflow does not modify the signed app's FinderInfo or explicitly hide its `.app`
extension. Finder controls the label; users who globally show all extensions may see
`.app`. After app notarization, the workflow signs the DMG with
Developer ID and a timestamp, submits it separately for notarization, staples and
validates its ticket, and verifies its signature, team, integrity, mounted app, and
Gatekeeper assessment. This second submission is an additional native distribution
safeguard, not a requirement for parity with Tauri. The release job allows 60 minutes,
including two bounded 15-minute notarization waits.

The workflow prepares and verifies both assets before creating or updating a release.
It computes SHA-256 digests of the final files and checks GitHub's uploaded asset
digests and sizes before publication. It does not create a checksum-text asset.
If GitHub does not provide an asset digest, verification fails and leaves the draft
for review or retry.
Re-runs replace only these two known asset names on an existing draft, preserve
unrelated assets and release notes, and fail rather than modify an already published
release or choose between duplicate releases. Set `release-draft: false` only when
automatic publication is intended; the workflow publishes only after both uploads
pass verification. Upload failures leave the release as a draft.

The intermediate `unsigned-macos-app` Actions artifact has one-day retention and is not
an installable release asset. It contains `unsigned-app.tar`; when artwork is enabled,
it also contains Finder's `.DS_Store` and `.background/` payloads. The signing job
checks each payload against SHA-256 outputs from the build job, then creates a fresh
compressed image from the verified app and those files. It does not mount a
caller-produced image while signing credentials are loaded. These hashes detect
transfer corruption or mismatch, not malicious output from the caller-controlled
build job.
Native apps have no automatic updater under this contract. Users install new versions
manually. The workflow does not produce Tauri updater tarballs, `.sig` files, or
`latest.json`. The Tauri workflow and its updater behavior remain unchanged.

The supported signing contract excludes custom entitlements, App Sandbox, nested
applications, app extensions, and XPC services. Such projects need a reviewed signing
contract rather than silently losing their entitlements. Embedded frameworks, dylibs,
and resource bundles are supported; every Mach-O must include `arm64` and `x86_64`.
The workflow uses the default Xcode on `macos-15` and checksum-pinned XcodeGen 2.46.0.
Callers cannot provide arbitrary build commands, signing options, or vault secret names.

See [credential operations](docs/credentials.md) for native caller preparation and
[the production release gate](docs/security.md#before-production-migration) before
using real credentials.

## Project status

The repository foundation is ready for disposable Azure and sample-application
integration testing. Native credential-interface tests use disposable local material;
they do not prove Azure access or Apple notarization. Do not migrate a production release
until the checklist in [security.md](docs/security.md) passes.
