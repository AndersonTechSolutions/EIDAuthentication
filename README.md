clone of https://sourceforge.net/projects/eidauthenticate/

EIDAuthenticate is the solution to perform smart card authentication on stand alone computers or to protect local accounts on domain computers. Originally made by certified security experts, EIDAuthenticate respects the spirit of the deep internal Windows security mechanisms and offers a user friendly interface.

Changes added by @andrysky to start dropping XP support

Using msbuild, the solution builds without WIX but needs the Cryptographic Provider Development Kit https://www.microsoft.com/en-us/download/details.aspx?id=30688

Build by installing Build Tools for Visual Studio https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022  

This link provides information on how to start linking VSCode and old Visual Stuido 2022 projects.
https://code.visualstudio.com/docs/cpp/config-msvc


If you would like to track how I am doing with working on this fork, check out this Discussion and leave a comment if you are interested in testing/helping out or even if you are just interested in using it when I am done.  Feedback helps to motivate me.

https://github.com/uberlinuxguy/EIDAuthentication/discussions/2

## AndersonTech changes (v0.3.0): card sign-in with LSA protection on

Kiosk mode: inserting an enrolled badge signs in to, or unlocks, a local Windows account without typing.

How it works: no EID code runs inside lsass, so LSA protection (`RunAsPPL`) stays on. The credential provider (`EIDCredentialProvider.dll`, loaded by LogonUI as SYSTEM) has the card decrypt the account's stored password, then hands Windows an ordinary password logon through Negotiate. Design: `Documentation/LSA-PROTECTION-PLAN.md`.

- Turn it on with the DWORD policy `HKLM\SOFTWARE\Policies\EIDAuthentication\AutoLogonOnCardInsert = 1`.
- Enrollment happens at the lock screen. An unenrolled card from a trusted CA gets a tile that asks once for the Windows user name, the Windows password and the card PIN. The card is saved only after that sign-in works and a decrypt proves card and PIN. Set `DisableEnrollAtLogon = 1` (same key) to turn this off.
- Per-employee PIN: the first successful PIN sign-in of a user on a computer saves that PIN for the user (LSA secret `L$_EID_AutoLogonPin_<RID>`, readable only by SYSTEM and administrators). Every later insertion signs in without typing. A PIN the user mistypes saves and forgets nothing. A saved PIN the card refuses is forgotten, so a changed card PIN can't use up the card's retries.
- After a Windows password change, the stored password is refused once. The tile then asks for the new password, saves it, and tapping works again. It never retries the old password, so it can't lock the account.
- Optional computer-wide fallback PIN (all badges share it): `-SetStation` / `-ClearStation` in the admin script.
- Only a card *inserted* while the sign-in or lock screen is shown triggers it. A card left in the reader doesn't unlock a session that was just locked.
- With a PIN saved, holding the badge is enough to sign in. Treat badges like keys.
- Revoking a card: put its certificate in the computer's `Disallowed` store (`LocalMachine\Disallowed`). From the next insertion it gets no tile and no tap sign-in. Online revocation (CRL/OCSP) is not checked, so a certificate without a CRL distribution point works.
- UAC prompts get no card tile.
- Uninstalling removes every saved PIN.

Install and upgrade:

- Silent install: `EIDInstallx64.exe /S`, then reboot. The installer writes `EIDAuthenticationPackage.dll` (admin commands only, never loaded by lsass), `EIDCredentialProvider.dll` and `EIDUninstall.exe` to System32.
- Upgrade: the installer refuses to run over an existing install ("Please uninstall first !"), and uninstalling would erase the saved PINs. Rename the existing `System32\EID*.dll` / `EIDConfigurationWizard.exe` files to `<name>.old-<stamp>` first (v0.2.0's lsass DLLs are locked until reboot), then install, reboot, and delete the `.old` files.
- Upgrading from v0.2.0 removes its lsass authentication package, its password-change notification package and the configuration wizard. Enrollments and saved PINs carry over.
- Then set `RunAsPPL` back on (2, or 1 with Secure Boot). Check after the reboot: System event Wininit 12 (lsass started as a protected process), and no CodeIntegrity 3033/3063/3065/3066 events.

Audit trail: the Application log, source `EIDAuthentication`.

| Event | Meaning |
|---|---|
| 1000 / 1001 | Tap sign-in or unlock succeeded / failed (account, card) |
| 1002 / 1003 | Sign-in or unlock with a typed PIN succeeded / failed |
| 1010 | PIN saved for an account (first PIN sign-in, or the PIN changed) |
| 1011 | Saved PIN forgotten (refused by the card, or the card was removed) |
| 1012 | Card enrolled for an account at the lock screen |
| 1013 | Stored password updated after a Windows password change |
| 1020 | An administrator set or cleared a PIN |

Copy a card to the other computers (v0.4.0): enroll once, then every other station signs in on insert with no typing.

1. On the computer where the employee enrolled: `eid-autologon-pin.ps1 -ExportCard -User ian -Path C:\Temp\ian.eidcard`. The file holds the card's stored password copy, which only that card and its PIN can open, plus the saved PIN (`-NoPin` leaves the PIN out; the employee then types it once per computer). The script makes the file readable by SYSTEM and administrators only.
2. On each other computer: `eid-autologon-pin.ps1 -ImportCard -Path C:\Temp\ian.eidcard` (the account in the file, or `-User <name>`). The import refuses a card whose certificate isn't trusted there (badge CA, EKU, Disallowed) or that is enrolled for another account.
3. Delete the file. It holds the PIN: move it admin to admin only (USB kit, admin SSH), never through Odoo or a shared folder.

Or seal the copy so it can travel any way (chat, ticket, SSH output): only the target computer can open it.

1. On the target: `-NewTransferKey` prints `EIDTKEY1:...`, the public part of a non-exportable machine key of that computer.
2. On the source: `-ExportCard -User ian -ToKey EIDTKEY1:...` prints `EIDSEALED1 ...` (RSA-3072 OAEP-SHA256 wrapping AES-256 + HMAC-SHA256).
3. On the target: `-ImportCard -Sealed "EIDSEALED1 ..."`. `-RemoveTransferKey` deletes the key afterwards.

The copied password is the one from the enrollment. After a Windows password change, each computer asks for the new password once; export and import again to spare that.

Admin script `Tools\eid-autologon-pin.ps1` (Windows PowerShell 5.1, run as administrator):
`-List` (saved PIN and enrolled card per account, never the PIN itself), `-Clear -User <name|*>`, `-RemoveCard -User <name>` (offboarding or a lost card: removes the card and the saved PIN), `-ExportCard -User <name> -Path <file> [-NoPin]`, `-ImportCard -Path <file> [-User <name>]`, `-SetStation`, `-ClearStation`, `-Events [-Last N]`.
It calls `rundll32 %WINDIR%\System32\EIDAuthenticationPackage.dll,<command>`. `ListAutoLogonPins`, `ClearUserAutoLogonPin`, `RemoveUserCard`, `ExportUserCard` and `ImportUserCard` need SYSTEM, so the script runs them through a one-shot SYSTEM scheduled task. `-List` writes its output to a fresh folder under `%SystemRoot%\Temp` that only SYSTEM and administrators can write, and deletes it afterwards.

Card readers held exclusively by another application at insertion (for example a badge service reading NDEF) are waited for instead of being missed.
