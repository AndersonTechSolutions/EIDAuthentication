<#
.SYNOPSIS
  Manage the saved tap sign-in PINs of EID Authentication on this computer.

.DESCRIPTION
  -List          the station PIN and each local account : PIN saved / none, card enrolled (never shows a PIN)
  -Clear -User   forget the PIN learnt for one account ("*" : every account).
                 The user's next sign-in with card + PIN saves it again; to offboard,
                 unenroll the card as well.
  -RemoveCard -User  unenroll the card of an account and forget its PIN (offboarding, lost card)
  -SetStation    set the fallback PIN shared by every badge (prompted, never on the command line)
  -ClearStation  remove the fallback PIN
  -Events        the audit trail (Application log, source EIDAuthentication)

  Reading the LSA secrets needs SYSTEM : -List, -Clear and -RemoveCard run through a one-shot scheduled task.

.EXAMPLE
  .\eid-autologon-pin.ps1 -List
  .\eid-autologon-pin.ps1 -Clear -User jdoe
  .\eid-autologon-pin.ps1 -Events -Last 50
#>
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'List')][switch]$List,
    [Parameter(ParameterSetName = 'Clear', Mandatory)][switch]$Clear,
    [Parameter(ParameterSetName = 'Clear', Mandatory)]
    [Parameter(ParameterSetName = 'RemoveCard', Mandatory)][string]$User,
    [Parameter(ParameterSetName = 'RemoveCard', Mandatory)][switch]$RemoveCard,
    [Parameter(ParameterSetName = 'SetStation', Mandatory)][switch]$SetStation,
    [Parameter(ParameterSetName = 'ClearStation', Mandatory)][switch]$ClearStation,
    [Parameter(ParameterSetName = 'Events', Mandatory)][switch]$Events,
    [Parameter(ParameterSetName = 'Events')][int]$Last = 20
)
$ErrorActionPreference = 'Stop'
$Dll = "$env:WINDIR\System32\EIDAuthenticationPackage.dll"
$WorkDir = "$env:ProgramData\EIDAuth"

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
New-Item -ItemType Directory -Force $WorkDir | Out-Null

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        $out = Join-Path $WorkDir 'pins.txt'
        Remove-Item $out -ErrorAction SilentlyContinue
        Invoke-AsSystem 'ListAutoLogonPins' "set EID_AUTOLOGON_OUT=$out&&"
        if (-not (Test-Path $out)) { throw 'No output: is this build older than ListAutoLogonPins?' }
        Get-Content $out -Encoding UTF8 | ForEach-Object {
            $f = $_ -split "`t"
            [pscustomobject]@{ Account = $f[0]; Rid = $f[1]; Pin = $f[2]; Card = $f[3] }
        } | Format-Table -AutoSize
        Remove-Item $out
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
