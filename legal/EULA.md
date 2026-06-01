# Files User Agreement

Effective date: March 10, 2026

`Files` is a Windows-first forensic triage and deleted-file recovery tool intended for lawful investigation, incident response, administrative support, and evidence-oriented recovery workflows.

## 1. Scope

This agreement applies to the use of the `Files` application, installer packages, reports, and recovered outputs.

The software itself is distributed under `GPL-3.0-or-later`. This agreement does not restrict any rights granted by that license. If any provision here conflicts with the GPL, the GPL controls.

## 2. Permitted Use

Use `Files` only when you have lawful authority, consent, or another valid legal basis to inspect the source device or storage media.

You are responsible for compliance with:

- workplace and customer policies;
- local, regional, and national laws;
- evidence handling and disclosure requirements;
- privacy and data protection obligations.

## 3. Safety Warnings

Recovered files may contain malware, exploit code, credential material, or other dangerous content.

You must assume that:

- recovered executables and scripts are unsafe to run;
- recovered archives may contain malicious payloads;
- opening restored files on the same machine may trigger security risk;
- writing recovered output to the source volume can reduce future recoverability.

Recommended practice:

- restore to a different destination volume;
- inspect hashes, metadata, and previews before opening content;
- use an isolated virtual machine or sandbox for deeper analysis.

## 4. No Recovery Guarantee

`Files` is designed to maximize reliable deleted-file recovery for selected artifact classes, especially executables, archives, and adjacent forensic traces. It does not and cannot guarantee `100%` recovery in all cases.

Recovery quality depends on:

- filesystem type and integrity;
- overwrite activity after deletion;
- fragmentation level;
- storage controller behavior;
- TRIM, garbage collection, compression, deduplication, encryption, or vendor-specific features;
- media damage or imaging quality.

Results marked as `Partial`, `Poor`, or `Unknown` must be treated accordingly.

## 5. Warranty Disclaimer

To the maximum extent permitted by law, the software is provided `as is`, without warranty of any kind, express or implied, including merchantability, fitness for a particular purpose, non-infringement, or uninterrupted operation.

## 6. Limitation of Liability

To the maximum extent permitted by law, the authors and contributors are not liable for:

- loss of data;
- business interruption;
- evidentiary misuse;
- security incidents caused by recovered files;
- regulatory or contractual violations arising from improper use;
- indirect, incidental, special, or consequential damages.

## 7. Source Preservation Guidance

For best forensic results:

- do not recover files back onto the source volume;
- avoid unnecessary writes to the source device after deletion is discovered;
- prefer imaging or triage on stable read-only paths when feasible;
- preserve generated report bundles and sidecar metadata with recovered files.

## 8. Open Source Rights

Nothing in this agreement limits your rights under `GPL-3.0-or-later`, including rights to run, study, modify, and redistribute the covered software under the terms of that license.
