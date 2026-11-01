BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../scripts/AppleSigning.Common.psm1') -Force
}

Describe 'ConvertTo-SafeName' {
    It 'normalizes repository identifiers' {
        ConvertTo-SafeName -Value 'Owner/My_App.Name' | Should -Be 'owner-my-app-name'
    }

    It 'collapses separators' {
        ConvertTo-SafeName -Value 'Owner///Repo' | Should -Be 'owner-repo'
    }
}

Describe 'Test-KeyVaultName' {
    It 'accepts a valid generated-style name' {
        Test-KeyVaultName -Name 'apple-signing-example' | Should -BeTrue
    }

    It 'rejects uppercase, consecutive hyphens, and excessive length' {
        Test-KeyVaultName -Name 'Apple-signing' | Should -BeFalse
        Test-KeyVaultName -Name 'apple--signing' | Should -BeFalse
        Test-KeyVaultName -Name ('a' * 25) | Should -BeFalse
    }
}

Describe 'Get-RepositoryProfile' {
    It 'requires owner/name and returns a safe profile' {
        Get-RepositoryProfile -Repository 'Owner/App.Name' | Should -Be 'owner-app-name'
        { Get-RepositoryProfile -Repository 'missing-owner' } | Should -Throw
    }

    It 'rejects profiles that cannot fit safely in Key Vault secret names' {
        { Get-RepositoryProfile -Repository "owner/$('r' * 81)" } | Should -Throw
    }
}

Describe 'Signing secret catalog' {
    It 'separates shared Apple values from repository updater values' {
        $catalog = Get-SigningSecretCatalog -Repository 'Owner/Application'
        $catalog.Certificate | Should -Be 'apple-developer-id-certificate'
        $catalog.UpdaterKey | Should -Be 'repo-owner-application-tauri-private-key'
        $catalog.UpdaterPassword | Should -Be 'repo-owner-application-tauri-private-key-password'
    }
}

Describe 'Idempotent resource decisions' {
    BeforeAll {
        $script:ManagedTags = [pscustomobject]@{
            'managed-by' = 'apple-signing-workflows'
            purpose      = 'apple-signing'
        }
    }

    It 'creates a missing resource' {
        Get-ManagedResourceAction -Resource $null -ExpectedLocation westus | Should -Be 'Create'
    }

    It 'reuses a compatible managed resource' {
        $resource = [pscustomobject]@{
            name = 'synthetic'
            location = 'westus'
            tags = $script:ManagedTags
        }
        Get-ManagedResourceAction -Resource $resource -ExpectedLocation westus | Should -Be 'Reuse'
    }

    It 'treats Azure display and canonical location names as equivalent' {
        $resource = [pscustomobject]@{
            name = 'synthetic'
            location = 'westus2'
            tags = $script:ManagedTags
        }
        Get-ManagedResourceAction -Resource $resource -ExpectedLocation 'West US 2' | Should -Be 'Reuse'
    }

    It 'rejects unmanaged or wrong-location resources' {
        $unmanaged = [pscustomobject]@{
            name = 'synthetic'
            location = 'westus'
            tags = [pscustomobject]@{ purpose = 'other' }
        }
        $wrongLocation = [pscustomobject]@{
            name = 'synthetic'
            location = 'eastus'
            tags = $script:ManagedTags
        }

        { Get-ManagedResourceAction -Resource $unmanaged -ExpectedLocation westus } | Should -Throw '*ownership tags*'
        { Get-ManagedResourceAction -Resource $wrongLocation -ExpectedLocation westus } | Should -Throw '*not*westus*'
    }
}

Describe 'Federated credential compatibility' {
    It 'requires exact issuer, subject, and audience' {
        $credential = [pscustomobject]@{
            subject = 'repo:owner/application:environment:release'
            issuer = 'https://token.actions.githubusercontent.com'
            audiences = @('api://AzureADTokenExchange')
        }
        Test-FederatedCredentialTrust -FederatedIdentity $credential -Subject $credential.subject | Should -BeTrue
        Test-FederatedCredentialTrust -FederatedIdentity $credential -Subject 'repo:owner/other:environment:release' | Should -BeFalse
    }
}

Describe 'Credential validation' {
    It 'measures encoded UTF-8 bytes against the vault limit' {
        Test-SecretValueSize -Value ('a' * 10) -MaximumBytes 10 | Should -BeTrue
        Test-SecretValueSize -Value (([char]0xE9).ToString() * 6) -MaximumBytes 10 | Should -BeFalse
    }

    It 'validates a synthetic PKCS12 bundle and its password' {
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        try {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Synthetic Test',
                $rsa,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $certificate = $request.CreateSelfSigned(
                [DateTimeOffset]::UtcNow.AddMinutes(-1),
                [DateTimeOffset]::UtcNow.AddDays(1)
            )
            $bytes = $certificate.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                'synthetic-password'
            )

            Test-Pkcs12Bundle -Bytes $bytes -Password 'synthetic-password' | Should -BeTrue
            Test-Pkcs12Bundle -Bytes $bytes -Password 'wrong-password' | Should -BeFalse
        }
        finally {
            $rsa.Dispose()
        }
    }

    It 'requires exact typed confirmations' {
        Test-ExactConfirmation -Actual 'ROTATE' -Expected 'ROTATE' | Should -BeTrue
        Test-ExactConfirmation -Actual 'rotate' -Expected 'ROTATE' | Should -BeFalse
    }
}

Describe 'Secret byte helpers' {
    It 'round-trips binary data through base64' {
        $bytes = [byte[]](0, 1, 2, 10, 13, 255)
        $encoded = ConvertTo-Base64 -Bytes $bytes
        [Convert]::FromBase64String($encoded) | Should -Be $bytes
    }

    It 'creates owner-only temporary files and removes them' {
        $path = New-ProtectedTempFile -Bytes ([Text.Encoding]::UTF8.GetBytes('synthetic-value'))
        try {
            Test-Path -LiteralPath $path | Should -BeTrue
            [IO.File]::ReadAllText($path) | Should -Be 'synthetic-value'
        }
        finally {
            Remove-ProtectedTempFile -Path $path
        }
        Test-Path -LiteralPath $path | Should -BeFalse
        Test-Path -LiteralPath (Split-Path -Parent $path) | Should -BeFalse
    }
}

Describe 'Managed vault discovery' {
    It 'returns only resources carrying both ownership tags' {
        Mock Invoke-AzJson -ModuleName AppleSigning.Common {
            @(
                [pscustomobject]@{
                    name = 'managed'
                    tags = [pscustomobject]@{
                        'managed-by' = 'apple-signing-workflows'
                        purpose      = 'apple-signing'
                    }
                },
                [pscustomobject]@{
                    name = 'unrelated'
                    tags = [pscustomobject]@{ purpose = 'other' }
                }
            )
        }

        $result = @(Find-ManagedVault)
        $result | Should -HaveCount 1
        $result[0].name | Should -Be 'managed'
    }

    It 'fails explicitly when no managed vault exists' {
        Mock Find-ManagedVault -ModuleName AppleSigning.Common { @() }
        { Resolve-ManagedVault } | Should -Throw '*No managed signing vault*'
    }

    It 'uses an explicit vault name without discovery' {
        Mock Invoke-AzJson -ModuleName AppleSigning.Common {
            [pscustomobject]@{ name = 'selected' }
        }
        Mock Find-ManagedVault -ModuleName AppleSigning.Common {
            throw 'Discovery should not run.'
        }

        (Resolve-ManagedVault -VaultName selected).name | Should -Be 'selected'
        Should -Invoke Invoke-AzJson -ModuleName AppleSigning.Common -Times 1 -Exactly
    }
}

Describe 'Protected command execution' {
    It 'writes standard input without adding a newline' {
        $result = Invoke-Tool -Name sh -Arguments @('-c', 'cat') -StandardInput 'exact-input'
        $result | Should -BeExactly 'exact-input'
    }

    It 'returns stdout without mixing successful stderr warnings into values' {
        $result = Invoke-Tool -Name sh -Arguments @(
            '-c',
            'printf synthetic-value; printf warning >&2'
        )
        $result | Should -Be 'synthetic-value'
        $result | Should -Not -Match 'warning'
    }

    It 'redacts output from sensitive command failures' {
        $caught = $null
        try {
            Invoke-Tool -Name sh -Arguments @('-c', 'echo synthetic-sensitive-value >&2; exit 7') -Sensitive
        }
        catch {
            $caught = $_
        }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Not -Match 'synthetic-sensitive-value'
        $caught.Exception.Message | Should -Match 'protected input'
    }
}

Describe 'PowerShell source parsing' {
    It 'parses every script and module without errors' {
        $root = Resolve-Path (Join-Path $PSScriptRoot '..')
        $files = Get-ChildItem -Path $root -Recurse -File |
            Where-Object { $_.Extension -in @('.ps1', '.psm1') }

        foreach ($file in $files) {
            $tokens = $null
            $errors = $null
            [Management.Automation.Language.Parser]::ParseFile(
                $file.FullName,
                [ref] $tokens,
                [ref] $errors
            ) | Out-Null
            $errors | Should -BeNullOrEmpty -Because $file.FullName
        }
    }
}
