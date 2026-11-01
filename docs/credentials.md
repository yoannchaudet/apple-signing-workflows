# Credential operations

## Initial vault schema

| Scope | Logical value | Key Vault representation |
|---|---|---|
| Shared | Developer ID PKCS#12 | Base64 of the original bytes |
| Shared | PKCS#12 password | UTF-8 text |
| Shared | Apple notarization app-specific password | UTF-8 text |
| Repository | Tauri updater private key | Base64 of the original bytes |
| Repository | Tauri updater-key password | UTF-8 text or a reserved empty marker |

Apple ID, Team ID, and signing identity are caller environment configuration rather than
vault secrets. Store the Apple ID as an environment secret instead of a variable if its
privacy matters.

## Hydration

```powershell
./scripts/manage-vault.ps1 -Action Hydrate -Repository owner/application
./scripts/manage-vault.ps1 -Action Verify -Repository owner/application -TauriProjectPath ../application
```

Passwords use hidden, confirmed prompts. Certificates and updater keys are read from
prompted file paths. Values never appear in command arguments.

The certificate and updater key are encoded exactly once. The workflow decodes the
updater key to an owner-readable temporary file because Tauri accepts a key path.

`Verify` uses the caller project's installed, pinned Tauri CLI to sign a disposable
payload. This proves that the stored updater key and password work together. Run
`npm ci` in the caller project first if its dependencies are not installed.

## Rotation

```powershell
./scripts/manage-vault.ps1 -Action Rotate -Repository owner/application -Secret apple-certificate
./scripts/manage-vault.ps1 -Action Rotate -Repository owner/application -Secret apple-notarization-password
```

Key Vault creates a new version while retaining previous versions. Certificate rotation
also rotates its export password as one maintenance operation.

Key Vault writes are not atomic. Before coordinated rotation:

1. Confirm no release workflow is running.
2. Prevent release tags until verification completes.
3. Validate all replacement material locally.
4. Rotate and run `Verify`.
5. Resume releases only after the complete set passes.

Rollback promotes a selected prior value into a new current version:

```powershell
./scripts/manage-vault.ps1 -Action Rollback -Repository owner/application -Secret apple-notarization-password
```

The script never purges or automatically disables old versions.

## Updater-key warning

Do not treat updater-key replacement as routine rotation. Existing clients trust the
public key embedded in the application. Replacing the private key without a compatible
bridge release prevents those clients from accepting future updates.
