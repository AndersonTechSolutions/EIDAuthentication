# MISTAKES.md

## Enforced Rules (check every task)

## Patterns (promote at 3 hits)

## Observations (first sightings)
- 2026-11-20: Sources, .vcxproj, .def and .nsi are CRLF with no .gitattributes → LF edits produce whole-file diffs → convert to LF to edit, restore CRLF (`sed -i 's/$/\r/'`) before commit, and check `git diff --stat` shows only real line counts. (hits: 1)
- 2026-11-20: `CContainerHolderFactory.cpp` is a template body `#include`d by its header and ExcludedFromBuild in the vcxproj → compile errors in it surface in every includer, not in the file → edit it like a header. (hits: 1)
- 2026-11-20: No local MSVC on the DevVM → the only compiler check is the `windows-build.yaml` run on `feature/**` pushes → push, then wait for CI before handing binaries to MC03. (hits: 1)
