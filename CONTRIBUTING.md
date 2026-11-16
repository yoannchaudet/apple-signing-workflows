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

Never use real Azure identifiers or signing values in examples or tests. Use descriptive
placeholders instead.
