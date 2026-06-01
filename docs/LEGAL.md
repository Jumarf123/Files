# Legal Notes

## Project License

`Files` is distributed under `GPL-3.0-or-later`.

Reasoning:

- the local analysis set mixes MIT, Apache-2.0, and GPL-family reference projects;
- the prompt explicitly required a conservative, compatibility-safe approach;
- the application domain overlaps with deleted-file heuristics commonly associated with GPL recovery tooling.

The current implementation is modular and mostly clean-room in code, but the repository-level license remains GPL-compatible to avoid ambiguous downstream compliance.

## Included Legal Files

- [LICENSE](../LICENSE)
- [legal/EULA.md](../legal/EULA.md)
- [legal/THIRD_PARTY_NOTICES.md](../legal/THIRD_PARTY_NOTICES.md)
- `legal/licenses/*`

## Local Reference Repository Notes

### Digler

The prompt referenced `source/digler-main/LICENSE`, but that file was not present in the local checkout during implementation.

Practical consequence:

- Digler was treated as a workflow and architecture reference only;
- no bundled Digler code or sidecar is declared in the current release;
- the absence of the local license file is documented rather than silently ignored.

### TestDisk / PhotoRec

Referenced for recovery heuristics and deleted-file/carving behavior, but not currently bundled as runtime sidecars or linked code.

### Autopsy

Referenced for forensic workflow and case/reporting ideas, not bundled as runtime code.

## EULA Compatibility

The included user agreement deliberately avoids adding restrictions that would conflict with GPL rights. It focuses on:

- lawful-use guidance
- malware and recovery warnings
- warranty disclaimer
- limitation of liability

## Future Compliance Tasks

If future releases add:

- bundled helper binaries
- external forensic sidecars
- copied validators or parsers from third-party projects

then `THIRD_PARTY_NOTICES.md`, `legal/licenses/`, and installer packaging metadata must be updated in the same release.

Current packaging note:

- the repository embeds a Windows application manifest for elevation;
- no code-signing pipeline or certificate material is part of the current project state.
