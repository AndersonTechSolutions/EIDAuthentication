# MISTAKES.md

## Enforced Rules (check every task)
- **EID-01** — Sources, .vcxproj, .def and .nsi are CRLF (no .gitattributes). Edit through a read→replace(\r\n→\n)→edit→replace(\n→\r\n) helper, never sed/heredoc in place; before commit check `git diff --stat` shows only real line counts and `od -c | tail -c 4` on any file whose last line was touched (a stray `Uninstall\r` in the .def broke the link once). (hits: 5)

## Patterns (promote at 3 hits)

## Observations (first sightings)
- 2026-11-20: `CContainerHolderFactory.cpp` is a template body `#include`d by its header and ExcludedFromBuild in the vcxproj → compile errors in it surface in every includer, not in the file → edit it like a header. (hits: 1)
- 2026-11-21: README.md and MISTAKES.md are LF, unlike the sources → the CRLF helper turned them into whole-file diffs → check `git show HEAD:<file> | grep -c $'\r'` before choosing the helper; edit LF files as plain text. (hits: 1)
- 2026-11-20: No local MSVC on the DevVM → the only compiler check is the `windows-build.yaml` run on `feature/**` pushes → push, then wait for CI before handing binaries to MC03. (hits: 1)
- 2026-11-20: The EID tile's SFI_USERNAME / `CContainer::GetUserName()` is the certificate display name (e.g. `ATS PIV TEST 1 (03326320)`), not the Windows account → `GetRidFromUsername()` on it returns 0 → use `CContainer::GetRid()` (cert → stored-credential RID, same mapping as lsass). (hits: 1)
