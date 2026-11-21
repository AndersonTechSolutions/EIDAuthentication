clone of https://sourceforge.net/projects/eidauthenticate/

EIDAuthenticate is the solution to perform smart card authentication on stand alone computers or to protect local accounts on domain computers. Originally made by certified security experts, EIDAuthenticate respects the spirit of the deep internal Windows security mechanisms and offers a user friendly interface.

Changes added by @andrysky to start dropping XP support

Using msbuild, the solution builds without WIX but needs the Cryptographic Provider Development Kit https://www.microsoft.com/en-us/download/details.aspx?id=30688

Build by installing Build Tools for Visual Studio https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022  

This link provides information on how to start linking VSCode and old Visual Stuido 2022 projects.
https://code.visualstudio.com/docs/cpp/config-msvc


If you would like to track how I am doing with working on this fork, check out this Discussion and leave a comment if you are interested in testing/helping out or even if you are just interested in using it when I am done.  Feedback helps to motivate me.

https://github.com/uberlinuxguy/EIDAuthentication/discussions/2

## AndersonTech changes: auto logon on card insertion

Kiosk mode: inserting an enrolled badge logs on (or unlocks) without typing the PIN.

- Enable with the DWORD policy `HKLM\SOFTWARE\Policies\EIDAuthentication\AutoLogonOnCardInsert = 1`.
- Per-employee PIN (default): the first successful PIN logon of a user on a computer stores that PIN for the user (LSA secret `L$_EID_AutoLogonPin_<RID>`, readable only by SYSTEM and administrators). The enrollment wizard's test logon counts. Every later insertion logs on without typing. A wrong PIN forgets it; removing the user's EID credential removes it.
- Optional computer-wide fallback PIN (all badges share it):
  `set EID_AUTOLOGON_PIN=<pin>` then `rundll32 EIDAuthenticationPackage.dll,SetAutoLogonPin`.
  Remove it with `rundll32 EIDAuthenticationPackage.dll,ClearAutoLogonPin`.
- Only a card *inserted* while the logon/lock screen is shown triggers it; a card left in the reader does not unlock a session that was just locked.
- One attempt per insertion, so a wrong stored PIN costs one PIN try, not the whole retry counter.
- With a PIN stored, possession of the badge is enough to log on. Treat badges like keys.
- Uninstalling removes every stored PIN.

Audit trail: the Application log, source `EIDAuthentication`.

| Event | Meaning |
|---|---|
| 1000 / 1001 | Tap sign-in or unlock succeeded / failed (account, card) |
| 1002 / 1003 | Sign-in or unlock with a typed PIN succeeded / failed |
| 1010 | PIN saved for an account (first PIN sign-in, or the PIN changed) |
| 1011 | Saved PIN forgotten (refused by the card, or the card was unenrolled) |
| 1020 | An administrator set or cleared a PIN |

Admin script `Tools\eid-autologon-pin.ps1` (run as administrator):
`-List` (which accounts have a saved PIN, never the PIN itself), `-Clear -User <name|*>`, `-SetStation`, `-ClearStation`, `-Events [-Last N]`.
The rundll32 commands behind it are `ListAutoLogonPins` (output file in `EID_AUTOLOGON_OUT`) and `ClearUserAutoLogonPin` (account in `EID_AUTOLOGON_USER`); both need SYSTEM.

Card readers held exclusively by another application at insertion (for example a badge service reading NDEF) are now waited for instead of being missed.
