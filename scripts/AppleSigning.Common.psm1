Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ManagedByTag = 'apple-signing-workflows'
$script:PurposeTag = 'apple-signing'

function Assert-Tool {
    param([Parameter(Mandatory)][string] $Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required but was not found on PATH."
    }
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string[]] $Arguments,
        [AllowEmptyString()][string] $StandardInput,
        [switch] $Sensitive,
        [switch] $AllowEmpty
    )

    $command = Get-Command $Name -ErrorAction Stop
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $command.Source
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $hasStandardInput = $PSBoundParameters.ContainsKey('StandardInput')
    $startInfo.RedirectStandardInput = $hasStandardInput
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Unable to start $Name."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($hasStandardInput) {
            $process.StandardInput.Write($StandardInput)
            $process.StandardInput.Close()
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult().TrimEnd("`r", "`n")
        $stderr = $stderrTask.GetAwaiter().GetResult().TrimEnd("`r", "`n")
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    if ($exitCode -ne 0) {
        if ($Sensitive) {
            throw "$Name failed while processing protected input."
        }

        throw "$Name failed with exit code ${exitCode}: $stderr"
    }

    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($stdout)) {
        throw "$Name returned no output."
    }

    return $stdout
}

function Invoke-AzJson {
    param([Parameter(Mandatory)][string[]] $Arguments)

    $text = Invoke-Tool -Name az -Arguments ($Arguments + @('--output', 'json'))
    return $text | ConvertFrom-Json
}

function Get-ActiveAzureAccount {
    Assert-Tool -Name az
    return Invoke-AzJson -Arguments @('account', 'show')
}

function ConvertTo-SafeName {
    param([Parameter(Mandatory)][string] $Value)

    $safe = $Value.ToLowerInvariant() -replace '[^a-z0-9-]', '-'
    $safe = $safe -replace '-+', '-'
    return $safe.Trim('-')
}

function Test-KeyVaultName {
    param([Parameter(Mandatory)][string] $Name)

    return $Name -cmatch '^[a-z][a-z0-9-]{1,22}[a-z0-9]$' -and
        $Name -notmatch '--'
}

function Get-RandomSuffix {
    param([ValidateRange(4, 32)][int] $Length = 8)

    $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789'
    $bytes = [byte[]]::new($Length)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

function Find-ManagedVault {
    $vaults = @(Invoke-AzJson -Arguments @('keyvault', 'list'))
    return @($vaults | Where-Object { Test-ManagedResource -Resource $_ })
}

function Test-ManagedResource {
    param([Parameter(Mandatory)] $Resource)

    if (-not $Resource.tags) { return $false }
    $managedBy = $Resource.tags.PSObject.Properties['managed-by']
    $purpose = $Resource.tags.PSObject.Properties['purpose']
    return $managedBy -and $purpose -and
        $managedBy.Value -eq $script:ManagedByTag -and
        $purpose.Value -eq $script:PurposeTag
}

function Resolve-ManagedVault {
    param([string] $VaultName)

    if ($VaultName) {
        return Invoke-AzJson -Arguments @('keyvault', 'show', '--name', $VaultName)
    }

    $vaults = @(Find-ManagedVault)
    if ($vaults.Count -eq 0) {
        throw 'No managed signing vault was found in the active subscription. Run provision-azure.ps1 first.'
    }
    if ($vaults.Count -eq 1) {
        return $vaults[0]
    }

    Write-Information 'Select a managed signing vault:' -InformationAction Continue
    for ($index = 0; $index -lt $vaults.Count; $index++) {
        Write-Information "[$($index + 1)] $($vaults[$index].name) ($($vaults[$index].resourceGroup))" -InformationAction Continue
    }
    $selection = Read-Host 'Selection'
    $number = 0
    if (-not [int]::TryParse($selection, [ref] $number) -or
        $number -lt 1 -or $number -gt $vaults.Count) {
        throw 'Invalid vault selection.'
    }
    return $vaults[$number - 1]
}

function Get-RepositoryProfile {
    param([Parameter(Mandatory)][string] $Repository)

    if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw "Repository must use the owner/name form."
    }
    $repositoryProfile = ConvertTo-SafeName -Value $Repository
    if ($repositoryProfile.Length -gt 80) {
        throw 'The normalized repository name exceeds 80 characters and cannot be used safely in the vault schema.'
    }
    return $repositoryProfile
}

function Get-SigningSecretCatalog {
    param([string] $Repository)

    $catalog = [ordered]@{
        Certificate          = 'apple-developer-id-certificate'
        CertificatePassword  = 'apple-developer-id-password'
        NotarizationPassword = 'apple-notarization-password'
    }
    if ($Repository) {
        $repositoryProfile = Get-RepositoryProfile -Repository $Repository
        $catalog.UpdaterKey = "repo-$repositoryProfile-tauri-private-key"
        $catalog.UpdaterPassword = "repo-$repositoryProfile-tauri-private-key-password"
    }
    return $catalog
}

function Get-ManagedResourceAction {
    param(
        $Resource,
        [string] $ExpectedLocation
    )

    if (-not $Resource) { return 'Create' }
    if (-not (Test-ManagedResource -Resource $Resource)) {
        throw "Resource '$($Resource.name)' exists without the required ownership tags."
    }
    if ($ExpectedLocation -and
        (ConvertTo-AzureLocationName -Value $Resource.location) -ne
        (ConvertTo-AzureLocationName -Value $ExpectedLocation)) {
        throw "Resource '$($Resource.name)' exists in '$($Resource.location)', not '$ExpectedLocation'."
    }
    return 'Reuse'
}

function ConvertTo-AzureLocationName {
    param([Parameter(Mandatory)][string] $Value)

    return ($Value -replace '\s', '').ToLowerInvariant()
}

function Test-FederatedCredentialTrust {
    param(
        [Parameter(Mandatory)] $FederatedIdentity,
        [Parameter(Mandatory)][string] $Subject
    )

    return $FederatedIdentity.subject -eq $Subject -and
        $FederatedIdentity.issuer -eq 'https://token.actions.githubusercontent.com' -and
        'api://AzureADTokenExchange' -in @($FederatedIdentity.audiences)
}

function Test-SecretValueSize {
    param(
        [Parameter(Mandatory)][string] $Value,
        [ValidateRange(1, 262144)][int] $MaximumBytes = 25KB
    )

    return [Text.Encoding]::UTF8.GetByteCount($Value) -le $MaximumBytes
}

function Test-Pkcs12Bundle {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        '',
        Justification = 'X509Certificate2Collection.Import requires the decoded password.'
    )]
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][string] $Password
    )

    try {
        $certificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $certificates.Import($Bytes, $Password, $flags)
        return [bool]($certificates | Where-Object { $_.HasPrivateKey })
    }
    catch {
        return $false
    }
}

function Test-ExactConfirmation {
    param(
        [AllowEmptyString()][string] $Actual,
        [Parameter(Mandatory)][string] $Expected
    )

    return $Actual -ceq $Expected
}

function Read-ConfirmedSecureString {
    param(
        [Parameter(Mandatory)][string] $Prompt,
        [switch] $AllowEmpty
    )

    $first = Read-Host $Prompt -AsSecureString
    $second = Read-Host 'Confirm value' -AsSecureString
    $firstText = ConvertFrom-ProtectedString -Value $first
    $secondText = ConvertFrom-ProtectedString -Value $second
    try {
        if ($firstText -cne $secondText) {
            throw 'The entered values do not match.'
        }
        if (-not $AllowEmpty -and $firstText.Length -eq 0) {
            throw 'The value must not be empty.'
        }
        return $first
    }
    finally {
        $firstText = $null
        $secondText = $null
    }
}

function ConvertFrom-ProtectedString {
    param([Parameter(Mandatory)][Security.SecureString] $Value)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function New-ProtectedTempFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Internal helper writes an owner-only temporary file required by the requested operation.'
    )]
    param([Parameter(Mandatory)][byte[]] $Bytes)

    $directory = Join-Path ([IO.Path]::GetTempPath()) "apple-signing-$([guid]::NewGuid().ToString('N'))"
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    if (-not $IsWindows) {
        [IO.File]::SetUnixFileMode(
            $directory,
            [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite -bor
            [IO.UnixFileMode]::UserExecute
        )
    }

    $path = Join-Path $directory 'value'
    [IO.File]::WriteAllBytes($path, $Bytes)
    if (-not $IsWindows) {
        [IO.File]::SetUnixFileMode(
            $path,
            [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        )
    }
    return $path
}

function Remove-ProtectedTempFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Internal helper unconditionally removes sensitive temporary data.'
    )]
    param([Parameter(Mandatory)][string] $Path)

    if (Test-Path -LiteralPath $Path) {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 0) {
            [IO.File]::WriteAllBytes($Path, [byte[]]::new($length))
        }
        Remove-Item -LiteralPath $Path -Force
    }
    $directory = Split-Path -Parent $Path
    if ($directory -and (Test-Path -LiteralPath $directory)) {
        Remove-Item -LiteralPath $directory -Force
    }
}

function ConvertTo-Base64 {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    return [Convert]::ToBase64String($Bytes)
}

function Get-ManagedTagArgument {
    return @(
        "managed-by=$script:ManagedByTag",
        "purpose=$script:PurposeTag"
    )
}

Export-ModuleMember -Function @(
    'Assert-Tool',
    'Invoke-Tool',
    'Invoke-AzJson',
    'Get-ActiveAzureAccount',
    'ConvertTo-SafeName',
    'Test-KeyVaultName',
    'Get-RandomSuffix',
    'Find-ManagedVault',
    'Test-ManagedResource',
    'Resolve-ManagedVault',
    'Get-RepositoryProfile',
    'Get-SigningSecretCatalog',
    'Get-ManagedResourceAction',
    'ConvertTo-AzureLocationName',
    'Test-FederatedCredentialTrust',
    'Test-SecretValueSize',
    'Test-Pkcs12Bundle',
    'Test-ExactConfirmation',
    'Read-ConfirmedSecureString',
    'ConvertFrom-ProtectedString',
    'New-ProtectedTempFile',
    'Remove-ProtectedTempFile',
    'ConvertTo-Base64',
    'Get-ManagedTagArgument'
)
