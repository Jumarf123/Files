# Testing

## Validated Commands

Frontend:

```powershell
cd app
npm run build
npm run lint
npm run test
npm run test:visual
```

Rust workspace:

```powershell
cd src-tauri
cargo check
cargo test --workspace
```

Release pipeline:

```powershell
pwsh -File resources\installer\release.ps1
```

The release script validates the frontend and Rust workspace, builds the production frontend, runs `npm run tauri:build`, smoke-checks the packaged runtime, copies NSIS/MSI artifacts into `results/`, and writes `Files_<version>_x64-SHA256SUMS.txt`.

Repeatable deleted-file audit:

```powershell
cd src-tauri
cargo run -p rss-scan-audit --release -- --source-id volume:R --output-dir ..\tmp\scan-audit
```

## Current Automated Coverage

### Rust

Implemented unit tests currently verify:

- artifact kind inference from extensions and signatures
- scan duration calculation
- HTML report content generation
- DFXML-like export content generation
- NTFS browser exposure of metadata/system entries through the MFT-backed provider

### Frontend

Implemented component test currently verifies:

- deleted artifact rows render in the results table under virtualization
- clicking a row forwards the inspected artifact to the parent handler

Visual interaction coverage verifies:

- tree scrolling and pagination
- file-list scrolling and pagination
- splitter drag
- zoom hotkeys, mouse wheel zoom, and zoom persistence

## Manual Verification Performed

The project was manually validated for:

- Tauri command wiring compatibility with frontend DTOs
- browser mock fallback for frontend-only runs
- deleted-only workbench rendering
- report export flow wiring
- recovery destination separation in UI workflow
- fresh release launch without a new console window
- embedded associated icon on the built executable
- embedded Windows manifest requesting `requireAdministrator`
- NSIS/MSI bundle generation and release artifact copying
- disposable NTFS deleted-file audit via `scan_audit`
- desktop runtime screenshot capture for the packaged application window

## Performance Notes

`Fast` and `Deep` are modeled as target SLAs for common Windows SSD/NVMe systems:

- `Fast`: about 2-3 minutes
- `Deep`: about 8-10 minutes

These are not hard guarantees. Real performance depends on source size, filesystem state, overwrite activity, fragmentation, and storage hardware.

## Remaining Recommended Validation

- FAT32 deleted entry fixture
- larger-volume benchmark runs
- installer smoke test on a clean Windows VM
- offline WebView2 verification on a machine without runtime preinstalled
