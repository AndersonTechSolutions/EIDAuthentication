# v0.3.0 "no-lsass": EID Authentication with LSA protection on

Status: implemented in v0.3.0 (spec 2026-11-22; tested on MC03-RCVNG-STTN 2026-11-23). Ian's decision: no code in lsass, so `RunAsPPL` goes back on without Microsoft LSA signing.

## Target

- Only `EIDCredentialProvider.dll` runs at sign-in. It's loaded by LogonUI.exe, which runs as SYSTEM and isn't a protected process, so it needs no Microsoft signature.
- Windows's own MSV1_0 does the logon, reached through Negotiate. It receives a normal `KERB_INTERACTIVE_UNLOCK_LOGON` (username, password, computer name).
- No EID package is registered in `Security Packages` or `Notification Packages`.
- The `EIDAuthenticationPackage.dll` file is renamed `EIDAdmin.dll`. It only hosts the rundll32 admin commands and is never loaded by lsass.
- Pre-releases are tagged `v0.3.0-nolsa.N`; the release is `v0.3.0`.

## What lsass does today, and where it goes

| Today (in lsass) | v0.3.0 |
|---|---|
| Verify the PIN; decrypt the stored password with the card's 9A key | Credential provider: CryptoAPI on the card's provider (`CRYPT_SILENT` + `PP_KEYEXCHANGE_PIN`). This is the same `CStoredCredentialManager::GetPassword` code, built into the credential provider |
| Build the token (`UserNameToToken`) and create the logon session | MSV1_0, from the password |
| Map card to account (`GetUsernameFromCertContext`, which reads the `L$_EID_<RID>` secrets) | Credential provider, same code, run as SYSTEM |
| Trust check (`IsTrustedCertificate`) | Credential provider, same code (CertGetCertificateChain + Smart Card Logon EKU) |
| Learn or forget the tap PIN | Credential provider: learn after a successful sign-in with a typed PIN; forget on `SCARD_W_WRONG_CHV` |
| `CheckPassword` at enrollment: reads the SAM through **samsrv.dll in-process**, which **only works inside lsass** | Removed. The sign-in itself proves the password: the blob is stored only after `ReportResult(STATUS_SUCCESS)` |
| Re-encrypt the password on a password change (notification package) | Stale-password flow on the tile (below) |
| Wizard enroll / remove / has-credential (`LsaCallAuthenticationPackage`) | Enrollment moves to the lock screen; removal moves to the admin tool, which runs as SYSTEM. The wizard is no longer installed |

**Storage is unchanged and reused as-is.**
- Blob: `L$_EID_<RID %08X>`, holding the `EID_PRIVATE_DATA` structure (certificate, AES-256 key wrapped to the card's RSA key, encrypted password, certificate hash).
- PINs: `L$_EID_AutoLogonPin[_<RID>]`.
- The credential provider already reads these secrets as SYSTEM inside LogonUI: tap sign-in on MC03 v0.1.0/v0.2.0 depends on it. `LsaStore/RetrievePrivateData` are LSA policy RPCs. They need no lsass-resident code and keep working with PPL on.
- Migration from v0.2.0 is therefore zero-touch: existing enrollments and saved PINs keep working.

## Tile flows

1. **Enrolled card, saved PIN (tap):** insert → decrypt → sign in. One attempt per insertion; a card left in the reader does nothing. Same as v0.2.0.
2. **Enrolled card, no saved PIN:** the tile shows the PIN field. On success the PIN is saved for this account.
3. **Card not enrolled on this station:** the tile shows *username*, *Windows password* and *PIN*.
   - Requirements: the certificate must pass the trust check, and the PIN must unlock the card (a test decrypt proves the key is there).
   - Sign in with the typed username and password. Only on `STATUS_SUCCESS`: wrap the password to the card's public key, store the blob, save the PIN, and log event 1012 "card enrolled".
   - Policy `EnrollAtLogon` (default 1) lets admins turn this off.
   - One card maps to one account. Enrolling a new card for an account replaces the old blob, and the event records that.
4. **Stale password** (for example after a JumpCloud password reset): MSV1_0 returns `STATUS_LOGON_FAILURE` or `STATUS_WRONG_PASSWORD`.
   - The blob is marked stale in memory and in the secret flags, so later taps don't retry it and add to the account-lockout counter.
   - The tile asks: "Your Windows password changed. Type it once."
   - After a successful sign-in, re-wrap the password with the public key; no PIN is needed for that. Log event 1013.
5. **Wrong PIN:** forget the saved PIN (event 1011) and show the remaining attempts. Same as v0.2.0.

All password and PIN buffers are zeroed after serialization or failure. CredProtect is used where the scenario needs it (`ProtectIfNecessaryAndCopyPassword` already exists).

Kept from v0.2.0:
- the per-employee learnt PIN;
- PIN-less insert-to-unlock;
- a card left in the reader stays locked;
- events 1000–1020, plus the new 1012 and 1013, now all written by the credential provider;
- `eid-autologon-pin.ps1`, pointed at `EIDAdmin.dll` and given `-RemoveCard -User`.

Out of scope for v0.3.0: UAC/CredUI prompts with the card (`CPUS_CREDUI`). No tile is shown there, so users type the password.

## Install and upgrade

1. Remove `EIDAuthenticationPackage` from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`, and `EIDPasswordChangeNotification` from `Notification Packages`.
2. Rename the loaded DLLs with the `.old-<stamp>` trick, then delete them at the next boot.
3. Install `EIDCredentialProvider.dll` and `EIDAdmin.dll`. Keep every `L$_EID_*` secret.
4. Do **not** touch RunAsPPL in the installer. The USB kit owns it.
5. Uninstall removes all secrets (as in `feature/audit-admin`).

## Acceptance on MC03 (after Ian's v0.2.0-audit.1 card test)

1. Install v0.3.0-nolsa.1; set `RunAsPPL=2`, `RunAsPPLBoot=2`; reboot.
2. Check:
   - `Get-Process lsass -Module` shows no `EID*`;
   - no CodeIntegrity 3033/3063/3065/3066 events for EID files;
   - `RunAsPPL` is in effect (Wininit event 12 / LSA 3.x).
3. Lock-screen tests:
   - ian taps to sign in (migrated blob, no re-enrollment);
   - tap to unlock;
   - card left in stays locked;
   - wrong PIN;
   - enroll `martin` with TEST 1 at the lock screen;
   - change ian's password, then the stale-password prompt appears and the next tap is PIN-less again.
4. Then set `RunAsPPL=1` (UEFI lock) once Secure Boot is on.

## One unverified assumption (spike first, ~1 h)

The card decrypt has run in lsass until now. It should behave the same from LogonUI (SYSTEM, session 1) with `CRYPT_SILENT` and the PIN set as a provider parameter. That's the documented Base Smart Card CSP path, but it hasn't been proven on MC03. The spike runs `EIDTest.exe` as SYSTEM to decrypt ian's blob with TEST 1. If it fails, the fallback is the CNG KSP (`NCryptDecrypt` with `NCRYPT_SILENT_FLAG` + `SmartCardPin`), about +3 h.

## Time

| Step | Hours |
|---|---|
| Spike: decrypt outside lsass | 1 |
| Credential provider: decrypt + Negotiate serialization, PIN learn/forget | 5 |
| Lock-screen enrollment tile + stale-password flow | 6 |
| `EIDAdmin.dll`, admin tool `-RemoveCard`, events 1012/1013 | 2 |
| Installer: unregister packages, upgrade, keep secrets | 2 |
| MC03 acceptance | 4 |
| **Total** | **~20 h (2.5 days)** |

## Risks

- **JumpCloud credential provider filtering:** if JumpCloud's credential provider or MFA filter is enabled it can hide other tiles. Check on MC03 before step 1.
- **Policies that refuse password logons** ("Interactive logon: Require Windows Hello for Business or smart card", `scforceoption`) must stay off. Our logon is a password logon as far as Windows is concerned.
- **Password exposure:** the decrypted password is briefly in LogonUI memory, the same as Microsoft's own password tile. lsass is protected again.
- **Credential provider crashes:** a bug now crashes LogonUI, which restarts, instead of lsass, which reboots the station.
