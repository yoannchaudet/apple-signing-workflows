BeforeAll {
    $script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:WorkflowPath = Join-Path $script:RepositoryRoot '.github/workflows/release-macos-tauri.yml'

    function Get-CredentialLoaderScript {
        $lines = [IO.File]::ReadAllLines($script:WorkflowPath)
        $stepIndex = [Array]::FindIndex(
            $lines,
            [Predicate[string]] { param($line) $line -match '^\s+- name: Load signing credentials$' }
        )
        if ($stepIndex -lt 0) { throw 'Credential loader step not found.' }

        $runIndex = $stepIndex
        while ($runIndex -lt $lines.Length -and $lines[$runIndex].Trim() -ne 'run: |') {
            $runIndex++
        }
        if ($runIndex -ge $lines.Length) { throw 'Credential loader run block not found.' }

        $body = [Collections.Generic.List[string]]::new()
        for ($index = $runIndex + 1; $index -lt $lines.Length; $index++) {
            if ($lines[$index] -match '^\s{6}- name: ') { break }
            if ($lines[$index].Length -ge 10) {
                $body.Add($lines[$index].Substring(10))
            }
            else {
                $body.Add('')
            }
        }
        return $body -join "`n"
    }

    function Initialize-CredentialLoaderFixture {
        $directory = Join-Path ([IO.Path]::GetTempPath()) "workflow-test-$([guid]::NewGuid().ToString('N'))"
        $bin = Join-Path $directory 'bin'
        [IO.Directory]::CreateDirectory($bin) | Out-Null
        $azPath = Join-Path $bin 'az'
        $azScript = @'
#!/usr/bin/env bash
set -euo pipefail
joined="$*"
if [[ -n "${FAIL_SECRET:-}" && "$joined" == *"$FAIL_SECRET"* ]]; then
  exit 4
fi
case "$joined" in
  *apple-developer-id-certificate*) printf '%s' 'Y2VydGlmaWNhdGU=' ;;
  *apple-developer-id-password*) printf '%s' 'certificate-password' ;;
  *apple-notarization-password*) printf '%s' 'notarization-password' ;;
  *tauri-private-key-password*) printf '%s' '__EMPTY__' ;;
  *tauri-private-key*) printf '%s' 'c3ludGhldGljLXVwZGF0ZXIta2V5' ;;
  *) exit 5 ;;
esac
'@
        [IO.File]::WriteAllText($azPath, $azScript)
        & chmod +x $azPath
        if ($LASTEXITCODE -ne 0) { throw 'Unable to make the fake az command executable.' }

        $loaderPath = Join-Path $directory 'load.sh'
        [IO.File]::WriteAllText($loaderPath, (Get-CredentialLoaderScript))
        return [pscustomobject]@{
            Directory  = $directory
            Bin        = $bin
            LoaderPath = $loaderPath
            OutputPath = Join-Path $directory 'github-output'
            RunnerTemp = Join-Path $directory 'runner'
        }
    }

    function Invoke-CredentialLoaderFixture {
        param(
            [Parameter(Mandatory)] $Fixture,
            [string] $FailSecret
        )

        [IO.Directory]::CreateDirectory($Fixture.RunnerTemp) | Out-Null
        $oldEnvironment = @{
            PATH              = $env:PATH
            VAULT_URI         = $env:VAULT_URI
            GITHUB_REPOSITORY = $env:GITHUB_REPOSITORY
            GITHUB_RUN_ID     = $env:GITHUB_RUN_ID
            GITHUB_RUN_ATTEMPT = $env:GITHUB_RUN_ATTEMPT
            GITHUB_OUTPUT     = $env:GITHUB_OUTPUT
            RUNNER_TEMP       = $env:RUNNER_TEMP
            FAIL_SECRET       = $env:FAIL_SECRET
        }
        try {
            $env:PATH = "$($Fixture.Bin)$([IO.Path]::PathSeparator)$env:PATH"
            $env:VAULT_URI = 'https://' + 'synthetic-vault' + '.vault.azure.net'
            $env:GITHUB_REPOSITORY = 'owner/application'
            $env:GITHUB_RUN_ID = '10'
            $env:GITHUB_RUN_ATTEMPT = '2'
            $env:GITHUB_OUTPUT = $Fixture.OutputPath
            $env:RUNNER_TEMP = $Fixture.RunnerTemp
            $env:FAIL_SECRET = $FailSecret

            $output = @(& /bin/bash $Fixture.LoaderPath 2>&1)
            return [pscustomobject]@{
                ExitCode = $LASTEXITCODE
                Output   = ($output | ForEach-Object { "$_" }) -join "`n"
            }
        }
        finally {
            foreach ($entry in $oldEnvironment.GetEnumerator()) {
                Set-Item -Path "env:$($entry.Key)" -Value $entry.Value
            }
        }
    }
}

Describe 'Signing credential loader' {
    It 'uses protected environment variables rather than caller-passed secrets' {
        $workflow = [IO.File]::ReadAllText($script:WorkflowPath)
        $workflow | Should -Match 'client-id: \$\{\{ vars\.AZURE_CLIENT_ID \}\}'
        $workflow | Should -Match 'tenant-id: \$\{\{ vars\.AZURE_TENANT_ID \}\}'
        $workflow | Should -Match 'VAULT_URI: \$\{\{ vars\.AZURE_KEY_VAULT_URI \}\}'
        $workflow | Should -Not -Match 'secrets\.AZURE_'
    }

    It 'masks values without corrupting step outputs' {
        $fixture = Initialize-CredentialLoaderFixture
        try {
            $result = Invoke-CredentialLoaderFixture -Fixture $fixture
            $result.ExitCode | Should -Be 0
            $result.Output | Should -Match '::add-mask::certificate-password'

            $outputs = [IO.File]::ReadAllText($fixture.OutputPath)
            $outputs | Should -Not -Match '::add-mask::'
            $outputs | Should -Match 'apple-certificate<<'
            $outputs | Should -Match 'Y2VydGlmaWNhdGU='

            $keyPath = Join-Path $fixture.RunnerTemp 'tauri-signing-10-2.key'
            [IO.File]::ReadAllText($keyPath) | Should -Be 'synthetic-updater-key'
        }
        finally {
            Remove-Item -LiteralPath $fixture.Directory -Recurse -Force
        }
    }

    It 'reports the missing secret name and fails closed' {
        $fixture = Initialize-CredentialLoaderFixture
        try {
            $result = Invoke-CredentialLoaderFixture -Fixture $fixture -FailSecret 'apple-notarization-password'
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match "::error::Unable to read required Key Vault secret 'apple-notarization-password'"
        }
        finally {
            Remove-Item -LiteralPath $fixture.Directory -Recurse -Force
        }
    }
}
