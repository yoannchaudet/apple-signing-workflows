# Repository guidance

- Never commit credentials, signing material, or concrete Azure resource identifiers.
- Keep workflows narrow. Do not accept arbitrary commands or secret names from callers.
- Pin third-party GitHub Actions to immutable commit SHAs.
- PowerShell scripts require PowerShell 7.3 or newer and must fail explicitly.
- Secret values must not appear in command arguments, output, logs, or test fixtures.
- Azure provisioning must be idempotent and must never delete or purge resources.
- Run the repository validation commands documented in `CONTRIBUTING.md`.
