# MISTAKES.md

## Enforced Rules (check every task)
- **EID-01** — Sources, .vcxproj, .def and .nsi are CRLF (no .gitattributes). Edit through a read→replace(\r\n→\n)→edit→replace(\n→\r\n) helper, never sed/heredoc in place; before commit check `git diff --stat` shows only real line counts and `od -c | tail -c 4` on any file whose last line was touched (a stray `Uninstall\r` in the .def broke the link once). (hits: 3)

## Patterns (promote at 3 hits)

## Observations (first sightings)
- 2026-11-20: `CContainerHolderFactory.cpp` is a template body `#include`d by its header and ExcludedFromBuild in the vcxproj → compile errors in it surface in every includer, not in the file → edit it like a header. (hits: 1)
- 2026-11-20: No local MSVC on the DevVM → the only compiler check is the `windows-build.yaml` run on `feature/**` pushes → push, then wait for CI before handing binaries to MC03. (hits: 1)
