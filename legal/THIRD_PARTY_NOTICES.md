# Third-Party Notices

Last updated: March 10, 2026

## Licensing Strategy

`Files` is licensed as `GPL-3.0-or-later`.

This conservative licensing choice was made because the project was designed with reference to mixed-license forensic recovery materials and because the prompt explicitly required legal caution around `TestDisk/PhotoRec`, `Autopsy`, and `Digler`.

The shipped codebase is modular and primarily clean-room in implementation, but the top-level project license remains GPL-compatible to reduce future compliance risk.

## Local Reference Projects Reviewed

### `source/testdisk-7.3-WIP`

- Role: behavior and heuristic reference for signature-based recovery and deleted-file recovery edge cases.
- Local license evidence: `source/testdisk-7.3-WIP/COPYING`
- Effective license treatment in this repository: GPL-compatible reference material
- Bundled as runtime code: No
- Bundled as sidecar binary: No

### `source/autopsy-release-4.22.1`

- Role: workflow, evidence presentation, case management, and forensic reporting reference.
- Local license evidence used for notice copy: `source/autopsy-release-4.22.1/thirdparty/LICENSE-2.0.txt`
- Effective license treatment in this repository: Apache-2.0 reference material
- Bundled as runtime code: No
- Bundled as sidecar binary: No

### `source/digler-main`

- Role: extensible scanner architecture and recovery workflow reference.
- Prompt referenced a local `source/digler-main/LICENSE`, but that file is not present in the checked-out repository on disk as of March 10, 2026.
- Effective treatment in this repository: reference-only, not bundled, no direct code copy assumed.
- Bundled as runtime code: No
- Bundled as sidecar binary: No

## Shipped Open Source Components

The application is built from Rust crates and npm packages resolved through:

- `src-tauri/Cargo.lock`
- `app/package-lock.json`

These dependencies are distributed under their own licenses. The primary categories include:

- Tauri runtime and plugins
- Tokio, Serde, Time, UUID, Tracing
- React, Vite, Tailwind CSS, TanStack Query/Table
- Radix UI primitives and Lucide icons

Refer to package metadata in the lockfiles and package registries for dependency-level licensing.

## Included License Copies

The following texts are stored under `legal/licenses/`:

- `GPL-3.0-or-later.txt`
- `GPL-2.0-or-later.txt`
- `Apache-2.0.txt`
- `MIT.txt`

The MIT text is included as the standard MIT form for reference convenience. Because the local Digler checkout does not include the `LICENSE` file referenced by the prompt, it is not treated as bundled project code in the current release.

## Sidecars

Current release status:

- bundled sidecar binaries: none
- external forensic executables invoked by default: none

If future releases add helper binaries such as PhotoRec/TestDisk sidecars, this document must be updated to identify:

- binary name;
- upstream project and version;
- whether the helper is invoked automatically or manually;
- source availability and packaging path;
- applicable notices and license texts.
