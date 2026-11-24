<#
.SYNOPSIS
  Manage the saved tap sign-in PINs of EID Authentication on this computer.

.DESCRIPTION
  -List          the station PIN and each local account : PIN saved / none, card enrolled (never shows a PIN)
  -Clear -User   forget the PIN learnt for one account ("*" : every account).
                 The user's next sign-in with card + PIN saves it again; to offboard,
                 unenroll the card as well.
  -RemoveCard -User  unenroll the card of an account and forget its PIN (offboarding, lost card)
  -ExportCard -User -Path  copy an account's card enrollment and saved PIN to a file (-NoPin : without the PIN)
  -ImportCard -Path [-User]  enroll that card on this computer from the file (default : the account in the file)
                 The file holds the PIN : keep it admin-only, move it admin to admin, delete it after the import.
  -NewTransferKey  on the target computer : make its card transfer key and print the public part (EIDTKEY1:...)
  -ExportCard -User -ToKey <EIDTKEY1:...> [-Path]  seal the copy for that computer only (prints it without -Path).
                 A sealed copy can travel anywhere (chat, ticket, e-mail) : only the target computer opens it.
  -ImportCard -Sealed <EIDSEALED1...> | -Path <file>  a sealed copy is opened with this computer's transfer key.
                 The key is one-shot : deleted after the import, also when the import is refused (-KeepKey keeps it),
                 and refused once older than -MaxKeyAgeMinutes (30). Prints "IMPORTED account=<name> cert=<SHA-1>".
  -RemoveTransferKey  delete this computer's transfer key (succeeds when there is none)
  Every refusal exits with code 1 and one line on stderr : "EIDAUTH-ERROR: <reason>".
  -SetStation    set the fallback PIN shared by every badge (prompted, never on the command line)
  -ClearStation  remove the fallback PIN
  -Events        the audit trail (Application log, source EIDAuthentication)

  Reading the LSA secrets needs SYSTEM : -List, -Clear, -RemoveCard, -ExportCard and -ImportCard run through
  a one-shot scheduled task.

.EXAMPLE
  .\eid-autologon-pin.ps1 -List
  .\eid-autologon-pin.ps1 -Clear -User jdoe
  .\eid-autologon-pin.ps1 -Events -Last 50
  .\eid-autologon-pin.ps1 -ExportCard -User ian -Path C:\Temp\ian.eidcard    (on the computer where ian enrolled)
  .\eid-autologon-pin.ps1 -ImportCard -Path C:\Temp\ian.eidcard             (on each other computer)
  .\eid-autologon-pin.ps1 -NewTransferKey                                     (on the target : prints EIDTKEY1:...)
  .\eid-autologon-pin.ps1 -ExportCard -User ian -ToKey EIDTKEY1:...           (on the source : prints EIDSEALED1...)
  .\eid-autologon-pin.ps1 -ImportCard -Sealed EIDSEALED1...                   (on the target)
#>
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'List')][switch]$List,
    [Parameter(ParameterSetName = 'Clear', Mandatory)][switch]$Clear,
    [Parameter(ParameterSetName = 'Clear', Mandatory)]
    [Parameter(ParameterSetName = 'RemoveCard', Mandatory)]
    [Parameter(ParameterSetName = 'ExportCard', Mandatory)]
    [Parameter(ParameterSetName = 'ImportCard')][string]$User,
    [Parameter(ParameterSetName = 'RemoveCard', Mandatory)][switch]$RemoveCard,
    [Parameter(ParameterSetName = 'ExportCard', Mandatory)][switch]$ExportCard,
    [Parameter(ParameterSetName = 'ExportCard')][switch]$NoPin,
    [Parameter(ParameterSetName = 'ExportCard')][string]$ToKey,
    [Parameter(ParameterSetName = 'ImportCard', Mandatory)][switch]$ImportCard,
    [Parameter(ParameterSetName = 'ImportCard')][string]$Sealed,
    [Parameter(ParameterSetName = 'ImportCard')][switch]$KeepKey,
    [Parameter(ParameterSetName = 'ImportCard')][ValidateRange(1, 1440)][int]$MaxKeyAgeMinutes = 30,
    [Parameter(ParameterSetName = 'ExportCard')]
    [Parameter(ParameterSetName = 'ImportCard')][string]$Path,
    [Parameter(ParameterSetName = 'NewTransferKey', Mandatory)][switch]$NewTransferKey,
    [Parameter(ParameterSetName = 'RemoveTransferKey', Mandatory)][switch]$RemoveTransferKey,
    [Parameter(ParameterSetName = 'SetStation', Mandatory)][switch]$SetStation,
    [Parameter(ParameterSetName = 'ClearStation', Mandatory)][switch]$ClearStation,
    [Parameter(ParameterSetName = 'Events', Mandatory)][switch]$Events,
    [Parameter(ParameterSetName = 'Events')][int]$Last = 20
)
$ErrorActionPreference = 'Stop'
# one line and exit code 1 on any failure, so a runbook can stop cleanly
trap {
    [Console]::Error.WriteLine('EIDAUTH-ERROR: ' + ($_.Exception.Message -replace '\s+', ' ').Trim())
    exit 1
}
$Dll = "$env:WINDIR\System32\EIDAuthenticationPackage.dll"

# A fresh folder that only SYSTEM and Administrators can write, created with its ACL : SYSTEM
# writes the -List output there, so no user may pre-create it or plant a link in it.
function New-PrivateWorkDir {
    $path = Join-Path "$env:SystemRoot\Temp" ('EIDAuth-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { throw "$path already exists." }
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $sec.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $dir = [System.IO.Directory]::CreateDirectory($path, $sec)
    $owner = (Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $owner -notin 'S-1-5-18', 'S-1-5-32-544') {
        throw "$path is not a private folder (owner $owner)."
    }
    $path
}

# The card copy file holds the PIN : only SYSTEM and Administrators may read it.
function Protect-AdminOnlyFile([string]$File) {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')))
    }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $File -AclObject $acl
}

# Sealed copies : RSA-3072 OAEP-SHA256 wraps an AES-256-CBC key and an HMAC-SHA256 key (encrypt-then-MAC).
# The private key is a non-exportable machine key of the target computer (SYSTEM and Administrators).
$TransferKeyName = 'EIDAuthCardTransfer'
$TransferKeyReg = 'HKLM:\SOFTWARE\EIDAuthentication\TransferKey'
$Ksp = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider

function Get-KeyFingerprint([byte[]]$PublicBlob) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    (($sha.ComputeHash($PublicBlob) | Select-Object -First 8 | ForEach-Object { $_.ToString('X2') }) -join '')
}

function New-TransferKey {
    $p = New-Object System.Security.Cryptography.CngKeyCreationParameters
    $p.Provider = $Ksp
    $p.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey -bor [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
    $p.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $p.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Decryption
    $p.Parameters.Add((New-Object System.Security.Cryptography.CngProperty('Length', [BitConverter]::GetBytes([int]3072), [System.Security.Cryptography.CngPropertyOptions]::None)))
    $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $TransferKeyName, $p)
    try { $blob = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob) } finally { $key.Dispose() }
    # the key's birth time and fingerprint, for the lifetime check (admin-only HKLM key)
    New-Item -Path $TransferKeyReg -Force | Out-Null
    Set-ItemProperty -Path $TransferKeyReg -Name CreatedUtc -Value ([DateTime]::UtcNow.ToString('o'))
    Set-ItemProperty -Path $TransferKeyReg -Name Fingerprint -Value (Get-KeyFingerprint $blob)
    $blob
}

# deletes the transfer key and its record; nothing to delete is not an error
function Remove-TransferKey {
    $removed = $false
    if ([System.Security.Cryptography.CngKey]::Exists($TransferKeyName, $Ksp, [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
        $key = [System.Security.Cryptography.CngKey]::Open($TransferKeyName, $Ksp, [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)
        $key.Delete()
        $removed = $true
    }
    Remove-Item -Path $TransferKeyReg -Force -ErrorAction SilentlyContinue
    $removed
}

function Open-TransferKey {
    if (-not [System.Security.Cryptography.CngKey]::Exists($TransferKeyName, $Ksp, [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
        throw 'This computer has no transfer key: run -NewTransferKey here first.'
    }
    [System.Security.Cryptography.CngKey]::Open($TransferKeyName, $Ksp, [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)
}

function Protect-CardCopy([byte[]]$Plain, [string]$KeyText) {
    if ($KeyText -notmatch '^EIDTKEY1:([A-Za-z0-9+/=]+)$') { throw 'The -ToKey value is not an EIDTKEY1: key.' }
    $blob = [Convert]::FromBase64String($Matches[1])
    $pub = [System.Security.Cryptography.CngKey]::Import($blob, [System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob)
    $rsa = New-Object System.Security.Cryptography.RSACng($pub)
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
        $aes.GenerateKey(); $aes.GenerateIV()
        $macKey = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($macKey)
        $data = $aes.CreateEncryptor().TransformFinalBlock($Plain, 0, $Plain.Length)
        $mac = (New-Object System.Security.Cryptography.HMACSHA256(,$macKey)).ComputeHash([byte[]]($aes.IV + $data))
        $wrap = $rsa.Encrypt([byte[]]($aes.Key + $macKey), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        'EIDSEALED1 key=' + (Get-KeyFingerprint $blob) + ' wrap=' + [Convert]::ToBase64String($wrap) + ' iv=' + [Convert]::ToBase64String($aes.IV) +
            ' data=' + [Convert]::ToBase64String($data) + ' mac=' + [Convert]::ToBase64String($mac)
        [Array]::Clear($macKey, 0, $macKey.Length)
    } finally { $aes.Dispose(); $rsa.Dispose(); $pub.Dispose() }
}

function Unprotect-CardCopy([string]$Text) {
    $f = @{}
    foreach ($part in ($Text.Trim() -split '\s+')) { if ($part -match '^(\w+)=(.+)$') { $f[$Matches[1]] = $Matches[2] } }
    if (-not $Text.Trim().StartsWith('EIDSEALED1') -or -not ($f.wrap -and $f.iv -and $f.data -and $f.mac)) { throw 'Not a sealed card copy (EIDSEALED1).' }
    $key = Open-TransferKey
    $rsa = New-Object System.Security.Cryptography.RSACng($key)
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $fp = Get-KeyFingerprint ($key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPublicBlob))
        if ($f.key -ne $fp) { throw "This copy is sealed for another computer or an older key (key $($f.key), this computer $fp)." }
        $record = Get-ItemProperty -Path $TransferKeyReg -ErrorAction SilentlyContinue
        if (-not $record -or $record.Fingerprint -ne $fp) { throw 'The transfer key has no birth record: make a new one with -NewTransferKey.' }
        $age = [DateTime]::UtcNow - [DateTime]::Parse($record.CreatedUtc, $null, [Globalization.DateTimeStyles]::RoundtripKind)
        if ($age.TotalMinutes -gt $MaxKeyAgeMinutes -or $age.TotalMinutes -lt -5) {
            throw "The transfer key is $([int]$age.TotalMinutes) minutes old (limit $MaxKeyAgeMinutes): make a new one with -NewTransferKey."
        }
        $keys = $rsa.Decrypt([Convert]::FromBase64String($f.wrap), [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        $iv = [Convert]::FromBase64String($f.iv); $data = [Convert]::FromBase64String($f.data)
        $expected = (New-Object System.Security.Cryptography.HMACSHA256(,[byte[]]$keys[32..63])).ComputeHash([byte[]]($iv + $data))
        if ([Convert]::ToBase64String($expected) -ne $f.mac) { throw 'The sealed copy was changed or damaged (MAC mismatch).' }
        $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
        $aes.Key = [byte[]]$keys[0..31]; $aes.IV = $iv
        $aes.CreateDecryptor().TransformFinalBlock($data, 0, $data.Length)
        [Array]::Clear($keys, 0, $keys.Length)
    } finally { $aes.Dispose(); $rsa.Dispose(); $key.Dispose() }
}

# SHA-1 of the card certificate in a plain copy (EID_PRIVATE_DATA.Hash, bytes 16-35 of the credential)
function Get-CopyCertThumbprint([byte[]]$Copy) {
    $text = [Text.Encoding]::ASCII.GetString($Copy)
    $line = ($text -split "`r?`n") | Where-Object { $_ -like 'credential=*' } | Select-Object -First 1
    if (-not $line) { throw 'The copy has no credential.' }
    $data = [Convert]::FromBase64String($line.Substring(11))
    if ($data.Length -lt 36) { throw 'The copy credential is too short.' }
    (($data[16..35] | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Assert-LocalAccount([string]$Name) {
    if ($Name -notmatch '^[\w.\- ]{1,20}$') { throw "Invalid account name: $Name" }
    if (-not (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) { throw "No local account named $Name" }
}

function Invoke-AsSystem([string]$Command, [string]$Variables) {
    $task = 'EIDAuth-pin-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $Variables rundll32.exe `"$Dll`",$Command"
    Register-ScheduledTask $task -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
    try {
        Start-ScheduledTask $task
        $deadline = (Get-Date).AddSeconds(30)
        do { Start-Sleep -Milliseconds 300 } while ((Get-ScheduledTask $task).State -eq 'Running' -and (Get-Date) -lt $deadline)
    } finally {
        Unregister-ScheduledTask $task -Confirm:$false
    }
}

if (-not (Test-Path $Dll)) { throw "EID Authentication is not installed ($Dll missing)." }

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        $workDir = New-PrivateWorkDir
        try {
            $out = Join-Path $workDir 'pins.txt'
            Invoke-AsSystem 'ListAutoLogonPins' "set `"EID_AUTOLOGON_OUT=$out`"&&"
            if (-not (Test-Path -LiteralPath $out)) { throw 'No output: is this build older than ListAutoLogonPins?' }
            Get-Content -LiteralPath $out -Encoding UTF8 | ForEach-Object {
                $f = $_ -split "`t"
                [pscustomobject]@{ Account = $f[0]; Rid = $f[1]; Pin = $f[2]; Card = $f[3] }
            } | Format-Table -AutoSize
        } finally {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    'Clear' {
        if ($User -ne '*' -and $User -notmatch '^[\w.\- ]{1,20}$') { throw "Invalid account name: $User" }
        if ($User -ne '*' -and -not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) { throw "No local account named $User" }
        Invoke-AsSystem 'ClearUserAutoLogonPin' "set `"EID_AUTOLOGON_USER=$User`"&&"
        Write-Host "Cleared the saved PIN of $User (see -Events)."
    }
    'RemoveCard' {
        if ($User -notmatch '^[\w.\- ]{1,20}$') { throw "Invalid account name: $User" }
        if (-not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) { throw "No local account named $User" }
        Invoke-AsSystem 'RemoveUserCard' "set `"EID_AUTOLOGON_USER=$User`"&&"
        Write-Host "Removed the card of $User (see -Events). The next sign-in with a card enrolls it again."
    }
    'ExportCard' {
        Assert-LocalAccount $User
        if (-not $Path -and -not $ToKey) { throw 'Give -Path (plain copy) or -ToKey (sealed copy).' }
        if ($Path -and (Test-Path -LiteralPath $Path)) { throw "$Path already exists." }
        $workDir = New-PrivateWorkDir
        try {
            $out = Join-Path $workDir 'card.eidcard'
            $withPin = if ($NoPin) { '0' } else { '1' }
            Invoke-AsSystem 'ExportUserCard' "set `"EID_AUTOLOGON_USER=$User`"&&set EID_AUTOLOGON_WITHPIN=$withPin&&set `"EID_AUTOLOGON_OUT=$out`"&&"
            if (-not (Test-Path -LiteralPath $out)) { throw "No card to export for $User (not enrolled on this computer?)." }
            $hasPin = [bool](Select-String -LiteralPath $out -Pattern '^pin=' -Quiet)
            $what = "the card of $User ($(if ($hasPin) { 'with' } else { 'without' }) the saved PIN)"
            if ($ToKey) {
                $sealedText = Protect-CardCopy ([IO.File]::ReadAllBytes($out)) $ToKey
                if ($Path) {
                    [IO.File]::WriteAllText($Path, $sealedText)
                    Write-Host "Sealed $what to $Path. Only the computer that made the key can open it."
                } else {
                    Write-Host "Sealed $what. Only the computer that made the key can open it:"
                    Write-Output $sealedText
                }
            } else {
                Copy-Item -LiteralPath $out -Destination $Path
                Protect-AdminOnlyFile $Path
                Write-Host "Exported $what to $Path."
                if ($hasPin) { Write-Warning 'The file holds the PIN: keep it admin-only and delete it after the import, or use -ToKey.' }
            }
        } finally {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    'ImportCard' {
        if ($User) { Assert-LocalAccount $User }
        if (-not $Sealed -and -not $Path) { throw 'Give -Sealed <EIDSEALED1...> or -Path <file>.' }
        if ($Path -and -not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "No file $Path" }
        $workDir = New-PrivateWorkDir
        $usedKey = $false
        try {
            $in = Join-Path $workDir 'card.eidcard'
            $out = Join-Path $workDir 'result.txt'
            if (-not $Sealed -and (Get-Content -LiteralPath $Path -TotalCount 1) -like 'EIDSEALED1*') { $Sealed = [IO.File]::ReadAllText($Path) }
            if ($Sealed) {
                $usedKey = $true
                $plain = Unprotect-CardCopy $Sealed
            } else {
                $plain = [IO.File]::ReadAllBytes($Path)
            }
            try {
                $thumbprint = Get-CopyCertThumbprint $plain
                [IO.File]::WriteAllBytes($in, $plain)
            } finally { [Array]::Clear($plain, 0, $plain.Length) }
            $userVar = if ($User) { "set `"EID_AUTOLOGON_USER=$User`"&&" } else { '' }
            Invoke-AsSystem 'ImportUserCard' "$userVar set `"EID_AUTOLOGON_IN=$in`"&&set `"EID_AUTOLOGON_OUT=$out`"&&"
            if (-not (Test-Path -LiteralPath $out)) { throw 'No result: is this build older than ImportUserCard?' }
            $result = (Get-Content -LiteralPath $out -Encoding UTF8 | Select-Object -First 1)
            if ($result -notlike 'OK *') {
                $code = [Convert]::ToInt32(($result -replace '^ERROR 0x', ''), 16)
                $text = (New-Object System.ComponentModel.Win32Exception($code)).Message
                throw "Import refused: $result ($text). Check that the badge CA is trusted here and the card isn't enrolled for another account."
            }
            $account = $result.Substring(3).Trim()
            Write-Host "Imported the card for $account. Inserting it at the lock screen now signs in without typing (see -Events)."
            Write-Output "IMPORTED account=$account cert=$thumbprint"
        } finally {
            Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
            # one-shot key : a forgotten -RemoveTransferKey or a captured copy can't be used later
            if ($usedKey -and -not $KeepKey) { Remove-TransferKey | Out-Null }
        }
    }
    'NewTransferKey' {
        $blob = New-TransferKey
        Write-Host "Made the card transfer key of $env:COMPUTERNAME (fingerprint $(Get-KeyFingerprint $blob)). Give this to -ExportCard -ToKey on the source computer:"
        Write-Output ('EIDTKEY1:' + [Convert]::ToBase64String($blob))
    }
    'RemoveTransferKey' {
        if (Remove-TransferKey) { Write-Host "Deleted the card transfer key of $env:COMPUTERNAME." }
        else { Write-Host "$env:COMPUTERNAME has no card transfer key." }
    }
    'SetStation' {
        $secure = Read-Host 'Station PIN' -AsSecureString
        $env:EID_AUTOLOGON_PIN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
        try { Start-Process rundll32.exe -ArgumentList "`"$Dll`",SetAutoLogonPin" -Wait -NoNewWindow }
        finally { Remove-Item env:EID_AUTOLOGON_PIN }
        Write-Host 'Station PIN set.'
    }
    'ClearStation' {
        Start-Process rundll32.exe -ArgumentList "`"$Dll`",ClearAutoLogonPin" -Wait -NoNewWindow
        Write-Host 'Station PIN cleared.'
    }
    'Events' {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'EIDAuthentication' } -MaxEvents $Last -ErrorAction SilentlyContinue |
            Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
    }
}
