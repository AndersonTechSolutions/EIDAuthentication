# MISTAKES.md

## Enforced Rules (check every task)

## Patterns (promote at 3 hits)
- Sources, .vcxproj, .def and .nsi are CRLF with no .gitattributes → LF edits produce whole-file diffs, and a hand-trimmed final newline left `Uninstall\r` in the .def (LNK2001 unresolved `Uninstall`) → convert to LF to edit, restore CRLF before commit, check `git diff --stat` line counts, and `od -c | tail` any file whose last line was touched. (hits: 2)

## Observations (first sightings)
- 2026-11-20: `CContainerHolderFactory.cpp` is a template body `#include`d by its header and ExcludedFromBuild in the vcxproj → compile errors in it surface in every includer, not in the file → edit it like a header. (hits: 1)
- 2026-11-20: No local MSVC on the DevVM → the only compiler check is the `windows-build.yaml` run on `feature/**` pushes → push, then wait for CI before handing binaries to MC03. (hits: 1)
