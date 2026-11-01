# Contributing

Run all checks before opening a pull request:

```powershell
Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Warning,Error -EnableExit
Invoke-ScriptAnalyzer -Path tests -Recurse -Severity Warning,Error -EnableExit
Invoke-Pester -Path tests -CI
pwsh -NoLogo -NoProfile -File tests/Test-TrackedContent.ps1
```

Run `actionlint` against `.github/workflows` using a locally installed binary. CI runs
the same checks.

Never use real Azure identifiers or signing values in examples or tests. Use descriptive
placeholders instead.
