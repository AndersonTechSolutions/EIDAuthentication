# MISTAKES.md

## Enforced Rules (check every task)
- **EID-01** — Sources, .vcxproj, .def and .nsi are CRLF (no .gitattributes). Edit through a read→replace(\r\n→\n)→edit→replace(\n→\r\n) helper, never sed/heredoc in place; before commit check `git diff --stat` shows only real line counts and `od -c | tail -c 4` on any file whose last line was touched (a stray `Uninstall\r` in the .def broke the link once). (hits: 9)

## Patterns (promote at 3 hits)

## Observations (first sightings)
- 2026-11-23: `Installerx64.nsi` `.onInit` aborts ("Please uninstall first !") whenever `System32\EIDAuthenticationPackage.dll` exists, and uninstalling first wipes every learnt PIN (DllUnRegister) → an in-place upgrade must rename the old System32 EID files to `.old-<stamp>` (the lsass ones are locked until reboot) before running `/S` → keep that rename step in any upgrade script, or teach `.onInit` to upgrade. (hits: 1)
- 2026-11-22: `CStoredCredentialManager::StorePrivateData/RetrievePrivateData` silently fell back to `%TEMP%\EIDCredential<rid>.txt` when not running inside lsass (`EIDIsComponentInLSAContext`) → any code moved out of lsass would have written credentials to a temp file → v0.3.0 removed the fallback; grep for `EIDIsComponentInLSAContext` before moving more lsass code. (hits: 1)
- 2026-11-22: `CheckPINandGetRemainingAttemptsIfPossible` returns success without checking for PIV cards (`Identity Device (NIST SP 800-73 [PIV])`) and non-minidriver CSPs → it proves nothing for our J3R180 badges → prove card + PIN by a decrypt (`CStoredCredentialManager::GetPassword`). (hits: 1)
- 2026-11-20: `CContainerHolderFactory.cpp` is a template body `#include`d by its header and ExcludedFromBuild in the vcxproj → compile errors in it surface in every includer, not in the file → edit it like a header. (hits: 1)
- 2026-11-21: README.md and MISTAKES.md are LF, unlike the sources → the CRLF helper turned them into whole-file diffs → check `git show HEAD:<file> | grep -c $'\r'` before choosing the helper; edit LF files as plain text. (hits: 1)
- 2026-11-20: No local MSVC on the DevVM → the only compiler check is the `windows-build.yaml` run on `feature/**` pushes → push, then wait for CI before handing binaries to MC03. (hits: 1)
- 2026-11-20: The EID tile's SFI_USERNAME / `CContainer::GetUserName()` is the certificate display name (e.g. `ATS PIV TEST 1 (03326320)`), not the Windows account → `GetRidFromUsername()` on it returns 0 → use `CContainer::GetRid()` (cert → stored-credential RID, same mapping as lsass). (hits: 1)
