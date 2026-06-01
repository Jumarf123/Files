# Architecture

## Goals

`Files` is structured as a Windows-first forensic workbench with clear separation between scanning, filesystem parsing, recovery, reporting, and UI orchestration.

Core design constraints:

- deleted-only result model
- read-only source access
- separate recovery destination
- fast metadata-first triage
- extendable deep-mode carving
- low-coupling between forensic pipeline and frontend shell

## Workspace Layout

### `src-tauri/crates/rss-core`

Domain model:

- scan sources and options
- progress and status objects
- deleted artifact record schema
- recovery plan contracts
- snapshot and report-facing DTOs

### `src-tauri/crates/rss-windows`

Windows-specific access layer:

- logical volume discovery
- physical disk probing
- raw read handles
- volume bitmap retrieval
- privilege-sensitive device access helpers
- MFT-backed NTFS browser index for live tree/list views

### `src-tauri/crates/rss-ntfs`

NTFS-focused deleted-entry pipeline:

- deleted MFT record enumeration
- recoverability assessment with bitmap support
- preview extraction for high-value formats

### `src-tauri/crates/rss-fat`

Limited FAT32 deleted directory entry support:

- deleted entry discovery
- contiguous cluster heuristics
- basic recovery plan creation

### `src-tauri/crates/rss-carver`

Deep-mode carving:

- unallocated extent scan
- high-priority signatures
- light structural validation

### `src-tauri/crates/rss-recovery`

Recovery engine:

- restore from raw runs or resident payloads
- sidecar metadata emission
- SHA-256 and BLAKE3 hashing
- recovery status reporting

### `src-tauri/crates/rss-report`

Evidence export:

- JSON
- CSV
- HTML
- DFXML-like XML

### `src-tauri/crates/rss-case`

Local persistence:

- snapshot history
- recent cases for UI reopening

### `src-tauri/crates/rss-security`

Privilege inspection:

- elevation state
- safety signals for the operator

### `src-tauri/crates/rss-ui-bridge`

Bridge/orchestration layer:

- source listing
- background scan sessions
- append-only scan batching and reconnectable snapshots
- lazy artifact details, preview, and signature commands
- recovery and report export commands
- case persistence wiring

## Frontend Structure

### `app/src/app`

- query provider
- main workbench composition

### `app/src/features/dashboard`

- browser mock backend for design-time and non-Tauri builds

### `app/src/features/results`

- virtualized deleted artifact grid
- artifact inspector, archive preview, and signature panel

### `app/src/shared`

- Tauri bridge
- formatting helpers
- typed DTO mirrors
- reusable UI primitives

## Data Flow

1. UI loads bootstrap and scan sources.
2. Operator selects a source and starts `Fast` or `Deep`.
3. `rss-ui-bridge` creates a background scan session.
4. `rss-fs` orchestrates filesystem-specific deleted-entry discovery.
5. `rss-ui-bridge` emits `scan-progress` and `scan-results-batch` events while keeping a reconnectable snapshot.
6. `rss-carver` optionally expands results in deep mode.
7. UI appends streamed summaries and requests artifact details, preview, and signature data lazily for the selected row.
8. Recovery writes outputs only to a separate destination.
9. Reports and snapshots are saved for later review.

## Deleted-Only Semantics

Every result carries:

- `origin_type`
- `confidence`
- `recoverability`

The main results table is intentionally limited to:

- filesystem deleted entries
- orphaned deleted records
- carved unallocated artifacts
- partial fragments with honest labeling

## Fast vs Deep

### Fast

- metadata-first
- prioritizes deleted filesystem records
- checks all deleted entries first and avoids broad preview extraction when type is already trustworthy
- uses a reduced carve budget and limited preview probes to keep UI and disk pressure lower

### Deep

- starts from fast pipeline
- extends into selective carving
- performs deeper validation of PE/JAR/MSI/ISO and archive signatures
- trades latency for wider deleted artifact coverage

## Runtime Notes

- the desktop target is Windows x64 only
- the installer pipeline is NSIS primary plus MSI secondary
- embedded manifest requests `requireAdministrator`, and startup aborts if elevation is still unavailable
- `source/` contains local reference material only and is not part of the shipped runtime
