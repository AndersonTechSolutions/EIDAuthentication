# Plan: run with LSA protection on

Status: proposal, 2026-11-21. No code yet.

## Problem

Windows 11 24H2 turns on LSA protection: `RunAsPPL=2`, with no UEFI lock. With it on, lsass loads only DLLs that carry a Microsoft signature. Two of our DLLs load into lsass:

| DLL | Loaded as | Job |
|---|---|---|
| `EIDAuthenticationPackage.dll` | authentication package | checks the card, decrypts the stored Windows password with the card key, builds the logon token, learns the tap sign-in PIN |
| `EIDPasswordChangeNotification.dll` | notification package | when the Windows password changes, re-encrypts the stored password to the card's public key |

Our stations therefore run with `RunAsPPL=0`. As a result, any administrator (or malware running as administrator) can read lsass memory, which holds the credentials of every account signed in on the station. A crash in our package also crashes lsass, which reboots the station.

## Options

| | A. Have Microsoft sign our lsass DLLs | **B. Move the work out of lsass (recommended)** | C. Replace EIDAuthenticate |
|---|---|---|---|
| What | Partner Center LSA-plugin signing for the two DLLs | The credential provider (LogonUI, not protected) decrypts the password and hands Windows a normal username+password logon. lsass runs only Microsoft packages | JumpCloud's own credential provider, or Windows Hello for Business |
| Code | none | ~2.5–3 days | none in this repo |
| Other cost | EV code-signing certificate (~$300–500/yr), Hardware Dev Center account, a resubmission for every build, weeks of lead time | none | depends on the JumpCloud plan. Windows Hello for Business needs Entra or AD, which local JumpCloud accounts don't have |
| lsass crash risk | stays | gone | gone |
| Keeps the J3R180 badge cards | yes | yes | unknown |

**Recommendation: B.** It removes our code from lsass for good, needs no certificate or Microsoft submission, and keeps today's enrollments.

## Design for B

1. **Logon path in the credential provider.** `CEIDCredential::GetSerialization` acquires the card key with the PIN (typed or saved) and decrypts the stored password. That's the same CryptoAPI code that runs in lsass today (`CStoredCredentialManager::GetPassword`). It then serializes a `KERB_INTERACTIVE_UNLOCK_LOGON` for the Negotiate package, as Microsoft's credential provider sample does. Windows's MSV1_0 does the logon. LogonUI runs as SYSTEM, so it can read the LSA secrets. The decrypted password stays in LogonUI memory only until serialization; zero it after.
2. **Tap sign-in PIN.** Move learning and forgetting from lsass to the credential provider. On `ReportResult` success with a typed PIN, save it; on a wrong-PIN status, forget it. The secrets, events and admin commands of `feature/audit-admin` stay the same.
3. **Enrollment broker.** The wizard runs as the user, who is not an administrator, so today it asks lsass (`LsaCallAuthenticationPackage`) to store the credential. Replace that with a small SYSTEM service, `EIDAuthBroker`, on a local named pipe. It:
   - impersonates the caller and only enrolls or removes the caller's own account (administrators may act on any account);
   - checks the password with `LogonUser` before storing it;
   - stores the credential in the same secret format as today (`L$_EID_<...>`, AES-256 key wrapped to the card's RSA key).

   Because the format doesn't change, existing enrollments keep working with no re-enrollment.
4. **Password changes without a notification package.** If the stored password is stale, MSV1_0 returns `STATUS_LOGON_FAILURE`. The tile then asks once for the new Windows password, signs in with it, and has the broker re-encrypt it to the card. This matters for JumpCloud, which sets local passwords: after each JumpCloud password change, each user types the new password once. To avoid that, keep the notification package (option A for that one small DLL).
5. **Installer.**
   - Remove `EIDAuthenticationPackage` from `Security Packages` and `EIDPasswordChangeNotification` from `Notification Packages`.
   - Install and start `EIDAuthBroker`.
   - Set `RunAsPPL=2` back and keep `RunAsPPLBoot`.
   - On upgrade, keep the existing secrets.

## Steps and time

| # | Step | Time |
|---|---|---|
| 1 | Decrypt and serialize in the credential provider; Negotiate logon | 4 h |
| 2 | Move PIN learn/forget to the credential provider | 2 h |
| 3 | `EIDAuthBroker` service + named pipe + wizard client | 8 h |
| 4 | Stale-password prompt on the tile + re-encrypt | 4 h |
| 5 | Installer changes, upgrade path, RunAsPPL back on | 2 h |
| 6 | MC03 test: enroll, PIN sign-in, tap sign-in and unlock, card left in, password change, upgrade from v0.2.0, `RunAsPPL=2` confirmed with lsass protected | 4 h |

Total: about 3 working days, including CI builds and MC03 reboots.

## Risks

- **Credential provider filtering.** Some policies (for example "Require Windows Hello for Business" or JumpCloud's own credential provider settings) can hide other credential providers. Check JumpCloud's credential provider settings on MC03 before step 1.
- **Password in LogonUI memory.** The decrypted password is briefly in LogonUI memory. That's the same exposure as Microsoft's own password tile, and much smaller than today's unprotected lsass.
- **Broker attack surface.** The broker is a new privileged endpoint. Keep it to three calls (enroll, remove, has-credential) and check the caller on each one.
