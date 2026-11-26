# Contributing

Run all checks before opening a pull request:

```powershell
Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Warning,Error -EnableExit
Invoke-ScriptAnalyzer -Path tests -Recurse -Severity Warning,Error -EnableExit
Invoke-Pester -Path tests -CI
pwsh -NoLogo -NoProfile -File tests/Test-TrackedContent.ps1
python3 -B tests/native_workflow_test.py
```

Run `actionlint` against `.github/workflows` using a locally installed binary. CI runs
the same checks.

The native workflow tests use Python's standard library. On macOS, they also generate
a disposable certificate and keychain and test the notarization credential prompt with
validation disabled. They do not contact Apple or use real signing credentials.
They also create a disposable headless DMG, mount it read-only, compare its app
contents, permissions, and symlinks with the standalone ZIP, and detach the owned
mount. Mock tests check notarization ordering, protected diagnostics, and draft-only
publication of the complete native artifact set. Optional Finder layout tests verify
artifact validation, digest binding, layout metadata in a freshly created compressed
DMG, and unchanged signed-app metadata. The `macos-15` CI job also drives Finder to
save and reopen a synthetic layout without signing credentials. Inspect the final
signed DMG on a clean Mac before the first production release.

Never use real Azure identifiers or signing values in examples or tests. Use descriptive
placeholders instead.
