use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use rss_core::{
    ArtifactKind, ArtifactRecord, Confidence, OriginType, PreviewFact, Recoverability,
    RecoveryPlan, ScanSource, infer_artifact_kind,
};
use rss_windows::{RawReader, VolumeBitmap};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const CHUNK_SIZE: u64 = 4 << 20;
const CARVE_PROGRESS_BYTES: u64 = 64 << 20;
const CARVE_PROGRESS_INTERVAL: Duration = Duration::from_millis(700);
const MAX_SCAN_BUDGET: u64 = 3 * 1024 * 1024 * 1024;
const PRIORITY_EXTENT_SLICE: u64 = 256 * 1024;
const PRIORITY_HEAD_SLICE: u64 = 192 * 1024;

struct Signature {
    kind: ArtifactKind,
    bytes: &'static [u8],
}

#[derive(Clone, Copy)]
struct ScanSegment {
    offset: u64,
    length: u64,
    extent_end: u64,
}

const SIGNATURES: &[Signature] = &[
    Signature {
        kind: ArtifactKind::Pe,
        bytes: b"MZ",
    },
    Signature {
        kind: ArtifactKind::Zip,
        bytes: b"PK\x03\x04",
    },
    Signature {
        kind: ArtifactKind::Rar,
        bytes: b"Rar!\x1A\x07",
    },
    Signature {
        kind: ArtifactKind::SevenZip,
        bytes: b"7z\xBC\xAF\x27\x1C",
    },
    Signature {
        kind: ArtifactKind::Cab,
        bytes: b"MSCF",
    },
    Signature {
        kind: ArtifactKind::Pdf,
        bytes: b"%PDF-",
    },
    Signature {
        kind: ArtifactKind::Png,
        bytes: b"\x89PNG\r\n\x1A\n",
    },
    Signature {
        kind: ArtifactKind::Jpg,
        bytes: b"\xFF\xD8\xFF",
    },
    Signature {
        kind: ArtifactKind::Gif,
        bytes: b"GIF87a",
    },
    Signature {
        kind: ArtifactKind::Gif,
        bytes: b"GIF89a",
    },
    Signature {
        kind: ArtifactKind::Sqlite,
        bytes: b"SQLite format 3\0",
    },
    Signature {
        kind: ArtifactKind::Gzip,
        bytes: b"\x1F\x8B\x08",
    },
    Signature {
        kind: ArtifactKind::Bzip2,
        bytes: b"BZh",
    },
    Signature {
        kind: ArtifactKind::Xz,
        bytes: b"\xFD7zXZ\x00",
    },
    Signature {
        kind: ArtifactKind::OleCompound,
        bytes: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
    },
];

pub fn carve_high_priority<F>(
    scan_id: &str,
    source: &ScanSource,
    bitmap: &VolumeBitmap,
    budget_override: Option<u64>,
    warnings: &mut Vec<String>,
    mut on_progress: F,
) -> Result<Vec<ArtifactRecord>>
where
    F: FnMut(u64, u64, &[ArtifactRecord]) -> bool,
{
    let budget = budget_override
        .unwrap_or(MAX_SCAN_BUDGET)
        .min(MAX_SCAN_BUDGET);
    let patterns: Vec<&[u8]> = SIGNATURES.iter().map(|sig| sig.bytes).collect();
    let ac = AhoCorasick::new(patterns).context("Failed to compile carve signatures")?;
    let mut scanned = 0u64;
    let mut seen_offsets = HashSet::new();
    let mut results = Vec::new();
    let mut last_progress_scanned = 0u64;
    let mut last_progress_at = Instant::now();
    let boundary_overlap = source.cluster_size.unwrap_or(4096).clamp(4096, CHUNK_SIZE);
    let mut raw_reader = match RawReader::open(&source.device_path) {
        Ok(reader) => reader,
        Err(err) => {
            push_unique_warning(
                warnings,
                format!(
                    "High-priority carve pass was skipped because the raw device could not be opened: {}",
                    err
                ),
            );
            return Ok(Vec::new());
        }
    };

    let scan_segments = build_scan_segments(&bitmap.extents);
    let mut ordered_extents = bitmap.extents.clone();
    ordered_extents.sort_by_key(|extent| extent.offset);

    'extent_loop: for segment in scan_segments {
        let scan_len = segment.length.min(budget.saturating_sub(scanned));
        if scan_len == 0 {
            break;
        }

        let mut local_offset = 0u64;
        while local_offset < scan_len {
            let remaining = scan_len - local_offset;
            let chunk_len = remaining.min(CHUNK_SIZE);
            let overlap = if remaining > chunk_len {
                let available_tail = remaining - chunk_len;
                if available_tail >= boundary_overlap {
                    boundary_overlap
                } else {
                    0
                }
            } else {
                0
            };
            let read_len = chunk_len.saturating_add(overlap) as usize;
            let absolute_offset = segment.offset + local_offset;
            let bytes = match raw_reader.read_at(absolute_offset, read_len) {
                Ok(bytes) => bytes,
                Err(err) => {
                    push_unique_warning(
                        warnings,
                        format!(
                            "Skipped unreadable carve chunk at {absolute_offset:#x} on {}: {}",
                            source.display_name, err
                        ),
                    );
                    scanned = scanned.saturating_add(chunk_len);
                    if should_emit_carve_progress(
                        scanned,
                        budget,
                        false,
                        &mut last_progress_scanned,
                        &mut last_progress_at,
                    ) && !on_progress(scanned, budget, &results)
                    {
                        return Ok(results);
                    }
                    local_offset = local_offset.saturating_add(CHUNK_SIZE);
                    if scanned >= budget {
                        break 'extent_loop;
                    }
                    continue;
                }
            };

            let mut emitted_new_result = false;
            for matched in ac.find_iter(&bytes) {
                if matched.start() as u64 >= chunk_len {
                    continue;
                }
                let pattern_index = matched.pattern().as_usize();
                let sig = &SIGNATURES[pattern_index];
                let hit_offset = absolute_offset + matched.start() as u64;
                let candidate_bytes = &bytes[matched.start()..];
                if !quick_signature_plausible(sig.kind, candidate_bytes) {
                    continue;
                }
                if !seen_offsets.insert(hit_offset) {
                    continue;
                }

                if let Some(record) = carve_candidate(
                    scan_id,
                    source,
                    &mut raw_reader,
                    sig.kind,
                    hit_offset,
                    segment.extent_end,
                    &ordered_extents,
                    warnings,
                )? {
                    results.push(record);
                    emitted_new_result = true;
                }
            }

            scanned = scanned.saturating_add(chunk_len);
            if should_emit_carve_progress(
                scanned,
                budget,
                emitted_new_result,
                &mut last_progress_scanned,
                &mut last_progress_at,
            ) && !on_progress(scanned, budget, &results)
            {
                return Ok(results);
            }
            local_offset = local_offset.saturating_add(CHUNK_SIZE);

            if scanned >= budget {
                break 'extent_loop;
            }
        }
    }

    let _ = on_progress(scanned, budget, &results);
    results.sort_by_key(|artifact| std::cmp::Reverse(artifact.priority_score));
    Ok(results)
}

fn build_scan_segments(extents: &[rss_core::ByteRun]) -> Vec<ScanSegment> {
    let mut prioritized = extents
        .iter()
        .filter(|extent| !extent.sparse && extent.length > 0)
        .cloned()
        .collect::<Vec<_>>();
    prioritized.sort_by_key(|extent| extent.offset);

    let mut head_segments = Vec::with_capacity(prioritized.len());
    let mut tail_segments = Vec::with_capacity(prioritized.len());
    let mut remainder_segments = Vec::new();

    for extent in prioritized {
        let extent_end = extent.offset.saturating_add(extent.length);
        if extent.length <= PRIORITY_EXTENT_SLICE {
            head_segments.push(ScanSegment {
                offset: extent.offset,
                length: extent.length,
                extent_end,
            });
            continue;
        }

        let head_len = PRIORITY_HEAD_SLICE.min(extent.length);
        let tail_len = PRIORITY_EXTENT_SLICE
            .saturating_sub(head_len)
            .min(extent.length.saturating_sub(head_len));
        head_segments.push(ScanSegment {
            offset: extent.offset,
            length: head_len,
            extent_end,
        });

        if tail_len > 0 {
            tail_segments.push(ScanSegment {
                offset: extent_end.saturating_sub(tail_len),
                length: tail_len,
                extent_end,
            });
        }

        let middle_start = extent.offset.saturating_add(head_len);
        let middle_end = extent_end.saturating_sub(tail_len);
        if middle_end > middle_start {
            remainder_segments.push(ScanSegment {
                offset: middle_start,
                length: middle_end - middle_start,
                extent_end,
            });
        }
    }

    remainder_segments.sort_by_key(|segment| segment.offset);
    let mut segments =
        Vec::with_capacity(head_segments.len() + tail_segments.len() + remainder_segments.len());
    segments.extend(head_segments);
    segments.extend(tail_segments);
    segments.extend(remainder_segments);
    segments
}

fn should_emit_carve_progress(
    scanned: u64,
    budget: u64,
    new_result: bool,
    last_scanned: &mut u64,
    last_at: &mut Instant,
) -> bool {
    if scanned >= budget || new_result {
        *last_scanned = scanned;
        *last_at = Instant::now();
        return true;
    }

    if scanned.saturating_sub(*last_scanned) >= CARVE_PROGRESS_BYTES
        && last_at.elapsed() >= CARVE_PROGRESS_INTERVAL
    {
        *last_scanned = scanned;
        *last_at = Instant::now();
        return true;
    }

    false
}

fn quick_signature_plausible(kind: ArtifactKind, bytes: &[u8]) -> bool {
    match kind {
        ArtifactKind::Pe => {
            if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
                return false;
            }
            let e_lfanew =
                u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap_or_default()) as usize;
            if e_lfanew < 0x40 || e_lfanew > 1024 * 1024 {
                return false;
            }
            if bytes.len() >= e_lfanew + 4 {
                &bytes[e_lfanew..e_lfanew + 4] == b"PE\0\0"
            } else {
                true
            }
        }
        ArtifactKind::Zip => {
            if bytes.len() < 30 || &bytes[..4] != b"PK\x03\x04" {
                return false;
            }
            let method = u16::from_le_bytes([bytes[8], bytes[9]]);
            let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
            matches!(method, 0 | 1 | 6 | 8 | 9 | 12 | 14 | 93 | 95 | 98 | 99)
                && name_len > 0
                && 30usize.saturating_add(name_len).saturating_add(extra_len) <= bytes.len()
        }
        ArtifactKind::Gzip => {
            bytes.len() >= 10
                && bytes[0] == 0x1f
                && bytes[1] == 0x8b
                && bytes[2] == 0x08
                && bytes[3] & 0b1110_0000 == 0
        }
        ArtifactKind::Bzip2 => {
            bytes.len() >= 4 && &bytes[..3] == b"BZh" && (b'1'..=b'9').contains(&bytes[3])
        }
        ArtifactKind::Xz => bytes.len() >= 6 && &bytes[..6] == b"\xFD7zXZ\x00",
        ArtifactKind::Png => bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1A\n",
        ArtifactKind::Gif => {
            bytes.len() >= 10
                && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a")
                && u16::from_le_bytes([bytes[6], bytes[7]]) > 0
                && u16::from_le_bytes([bytes[8], bytes[9]]) > 0
        }
        ArtifactKind::Jpg => {
            bytes.len() >= 4 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff
        }
        ArtifactKind::Rar => bytes.len() >= 7 && &bytes[..6] == b"Rar!\x1A\x07",
        ArtifactKind::SevenZip => bytes.len() >= 6 && &bytes[..6] == b"7z\xBC\xAF\x27\x1C",
        ArtifactKind::Cab => bytes.len() >= 8 && &bytes[..4] == b"MSCF",
        ArtifactKind::Pdf => bytes.len() >= 8 && &bytes[..5] == b"%PDF-",
        ArtifactKind::Sqlite => bytes.len() >= 16 && &bytes[..16] == b"SQLite format 3\0",
        ArtifactKind::OleCompound => {
            bytes.len() >= 8 && &bytes[..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
        }
        _ => true,
    }
}

fn carve_candidate(
    scan_id: &str,
    source: &ScanSource,
    raw_reader: &mut RawReader,
    signature_kind: ArtifactKind,
    offset: u64,
    scan_end: u64,
    ordered_extents: &[rss_core::ByteRun],
    warnings: &mut Vec<String>,
) -> Result<Option<ArtifactRecord>> {
    let probe_len = match signature_kind {
        ArtifactKind::Pe => 512 * 1024,
        ArtifactKind::Zip => 4 * 1024 * 1024,
        ArtifactKind::Rar => 4 * 1024 * 1024,
        ArtifactKind::SevenZip | ArtifactKind::Cab => 256 * 1024,
        _ => 2 * 1024 * 1024,
    };
    let available_in_extent = scan_end.saturating_sub(offset);
    if available_in_extent
        < SIGNATURES
            .iter()
            .find(|signature| signature.kind == signature_kind)
            .map(|signature| signature.bytes.len() as u64)
            .unwrap_or(1)
    {
        return Ok(None);
    }
    let read_len = probe_len.min(available_in_extent) as usize;
    let probe = match raw_reader.read_at(offset, read_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            push_unique_warning(
                warnings,
                format!(
                    "Skipped carved candidate at {offset:#x} on {} because a validation read failed: {}",
                    source.display_name, err
                ),
            );
            return Ok(None);
        }
    };
    if probe.is_empty() {
        return Ok(None);
    }

    let (estimated_len, derived_kind, confidence, exact) = match signature_kind {
        ArtifactKind::Pe => {
            let Some(size) = estimate_pe_size(&probe) else {
                return Ok(None);
            };
            let kind = infer_artifact_kind("carved.bin", Some(&probe));
            (size, kind, Confidence::High, true)
        }
        ArtifactKind::Zip => {
            let Some((size, kind)) = estimate_zip_size(&probe) else {
                return Ok(None);
            };
            (size, kind, Confidence::High, true)
        }
        ArtifactKind::SevenZip => {
            let Some(size) = estimate_7z_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::SevenZip, Confidence::High, true)
        }
        ArtifactKind::Cab => {
            let Some(size) = estimate_cab_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::Cab, Confidence::High, true)
        }
        ArtifactKind::Pdf => {
            let Some(size) = estimate_pdf_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::Pdf, Confidence::High, true)
        }
        ArtifactKind::Png => {
            let Some(size) = estimate_png_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::Png, Confidence::High, true)
        }
        ArtifactKind::Jpg => {
            let Some(size) = estimate_jpeg_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::Jpg, Confidence::High, true)
        }
        ArtifactKind::Gif => {
            let Some(size) = estimate_gif_size(&probe) else {
                return Ok(None);
            };
            (size, ArtifactKind::Gif, Confidence::High, true)
        }
        ArtifactKind::Sqlite => (
            probe.len() as u64,
            ArtifactKind::Sqlite,
            Confidence::Medium,
            false,
        ),
        ArtifactKind::Rar => {
            let (size, exact) = estimate_rar_size(&probe).unwrap_or((probe.len() as u64, false));
            (
                size,
                ArtifactKind::Rar,
                if exact {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                exact,
            )
        }
        ArtifactKind::Gzip => (
            probe.len() as u64,
            ArtifactKind::Gzip,
            Confidence::Medium,
            false,
        ),
        ArtifactKind::Bzip2 => (
            probe.len() as u64,
            ArtifactKind::Bzip2,
            Confidence::Medium,
            false,
        ),
        ArtifactKind::Xz => (
            probe.len() as u64,
            ArtifactKind::Xz,
            Confidence::Medium,
            false,
        ),
        ArtifactKind::OleCompound => (
            probe.len() as u64,
            infer_artifact_kind("carved.bin", Some(&probe)),
            Confidence::Medium,
            false,
        ),
        _ => return Ok(None),
    };

    if estimated_len < 128 {
        return Ok(None);
    }

    let fallback_available = scan_end.saturating_sub(offset);
    let mut runs = build_carve_runs(offset, estimated_len, ordered_extents);
    let stitched_len = runs.iter().map(|run| run.length).sum::<u64>();
    if runs.is_empty() {
        runs.push(rss_core::ByteRun {
            offset,
            length: estimated_len.min(fallback_available),
            sparse: false,
        });
    }
    let actual_len = stitched_len
        .max(runs[0].length)
        .min(estimated_len.max(runs[0].length));
    let partial = actual_len < estimated_len || !exact;
    let extension = extension_for_kind(derived_kind);
    let name = format!("carved_{offset:016X}.{extension}");

    let mut record = ArtifactRecord::new(scan_id, &source.id, name);
    record.kind = derived_kind;
    record.family = derived_kind.family();
    record.priority_score = derived_kind.priority_score();
    record.origin_type = if partial {
        OriginType::PartialFragment
    } else {
        OriginType::UnallocatedCarved
    };
    record.deleted_entry = false;
    record.confidence = confidence;
    record.recoverability = if partial {
        Recoverability::Partial
    } else {
        Recoverability::Good
    };
    record.placement_kind = rss_core::PlacementKind::UnknownParent;
    record.path_confidence = rss_core::PathConfidence::Unknown;
    record.name_source = rss_core::NameSourceKind::Generated;
    record.content_source = if partial {
        rss_core::ContentSourceKind::FragmentCandidate
    } else {
        rss_core::ContentSourceKind::ContiguousCarve
    };
    record.artifact_class = if partial {
        rss_core::ArtifactClass::FragmentCandidate
    } else {
        rss_core::ArtifactClass::CarvedHit
    };
    record.preview_ready = true;
    record.is_fragment = partial;
    record.fragment_id = partial.then(|| format!("frag-{offset:016X}-{actual_len:X}"));
    record.size = actual_len;
    record.raw_offset = Some(offset);
    record.raw_length = Some(actual_len);
    record.preview = vec![
        PreviewFact {
            label: "Carve Offset".to_string(),
            value: format!("{offset:#x}"),
        },
        PreviewFact {
            label: "Estimated Size".to_string(),
            value: format!("{estimated_len} bytes"),
        },
    ];
    if partial {
        record.notes.push(
            "Carved object is truncated or validator could not determine a trustworthy end marker."
                .to_string(),
        );
    }
    record.recovery_plan = RecoveryPlan::RawRuns {
        source_path: source.device_path.clone(),
        runs,
        logical_size: actual_len,
    };

    Ok(Some(record))
}

fn build_carve_runs(
    start_offset: u64,
    logical_size: u64,
    ordered_extents: &[rss_core::ByteRun],
) -> Vec<rss_core::ByteRun> {
    const MAX_FRAGMENT_GAP: u64 = 64 * 1024;

    let start_index = ordered_extents.partition_point(|extent| extent.offset <= start_offset);
    if start_index == 0 {
        return Vec::new();
    }
    let start_index = start_index - 1;
    let Some(start_extent) = ordered_extents.get(start_index) else {
        return Vec::new();
    };
    if start_extent.sparse
        || start_offset >= start_extent.offset.saturating_add(start_extent.length)
    {
        return Vec::new();
    }

    let mut runs = Vec::new();
    let mut remaining = logical_size;
    let mut expected_next = start_offset;

    for extent in &ordered_extents[start_index..] {
        if extent.sparse {
            continue;
        }

        let extent_end = extent.offset.saturating_add(extent.length);
        if expected_next < extent.offset {
            let gap = extent.offset - expected_next;
            if gap > MAX_FRAGMENT_GAP || runs.is_empty() {
                break;
            }
        }
        if expected_next >= extent_end {
            continue;
        }

        let run_offset = expected_next.max(extent.offset);
        let available = extent_end.saturating_sub(run_offset);
        if available == 0 {
            continue;
        }

        let length = available.min(remaining);
        runs.push(rss_core::ByteRun {
            offset: run_offset,
            length,
            sparse: false,
        });
        remaining = remaining.saturating_sub(length);
        expected_next = run_offset.saturating_add(length);

        if remaining == 0 {
            break;
        }
    }

    runs
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.iter().any(|existing| existing == &warning) {
        return;
    }
    warnings.push(warning);
}

fn estimate_pe_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.len() < e_lfanew + 24 || &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let number_of_sections =
        u16::from_le_bytes(bytes[e_lfanew + 6..e_lfanew + 8].try_into().ok()?) as usize;
    let optional_size =
        u16::from_le_bytes(bytes[e_lfanew + 20..e_lfanew + 22].try_into().ok()?) as usize;
    let sections_offset = e_lfanew + 24 + optional_size;
    let mut max_size = sections_offset as u64;

    for index in 0..number_of_sections {
        let start = sections_offset + index * 40;
        if bytes.len() < start + 40 {
            return None;
        }
        let raw_size = u32::from_le_bytes(bytes[start + 16..start + 20].try_into().ok()?) as u64;
        let raw_ptr = u32::from_le_bytes(bytes[start + 20..start + 24].try_into().ok()?) as u64;
        max_size = max_size.max(raw_ptr.saturating_add(raw_size));
    }

    Some(max_size.min(128 * 1024 * 1024))
}

fn estimate_zip_size(bytes: &[u8]) -> Option<(u64, ArtifactKind)> {
    if bytes.len() < 32 || &bytes[..4] != b"PK\x03\x04" {
        return None;
    }
    let eocd = bytes
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")?;
    if bytes.len() < eocd + 22 {
        return None;
    }
    let comment_len = u16::from_le_bytes(bytes[eocd + 20..eocd + 22].try_into().ok()?) as usize;
    let end = eocd + 22 + comment_len;
    if end > bytes.len() {
        return None;
    }

    let kind = if bytes
        .windows(20)
        .any(|window| window == b"META-INF/MANIFEST.MF")
    {
        ArtifactKind::Jar
    } else if bytes
        .windows(19)
        .any(|window| window == b"AndroidManifest.xml")
    {
        ArtifactKind::Apk
    } else {
        ArtifactKind::Zip
    };

    Some((end as u64, kind))
}

fn estimate_7z_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 32 || &bytes[..6] != b"7z\xBC\xAF\x27\x1C" {
        return None;
    }
    let next_header_offset = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
    let next_header_size = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
    Some(32 + next_header_offset + next_header_size)
}

fn estimate_cab_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 16 || &bytes[..4] != b"MSCF" {
        return None;
    }
    Some(u32::from_le_bytes(bytes[8..12].try_into().ok()?) as u64)
}

fn estimate_rar_size(bytes: &[u8]) -> Option<(u64, bool)> {
    if bytes.len() >= 8 && &bytes[..8] == b"Rar!\x1A\x07\x01\x00" {
        const RAR5_FOOTER: &[u8] = &[0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00];
        let footer = bytes
            .windows(RAR5_FOOTER.len())
            .rposition(|window| window == RAR5_FOOTER)?;
        return Some(((footer + RAR5_FOOTER.len()) as u64, true));
    }
    if bytes.len() >= 7 && &bytes[..7] == b"Rar!\x1A\x07\x00" {
        const RAR4_FOOTER: &[u8] = &[0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00];
        if let Some(footer) = bytes
            .windows(RAR4_FOOTER.len())
            .rposition(|window| window == RAR4_FOOTER)
        {
            return Some(((footer + RAR4_FOOTER.len()) as u64, true));
        }
    }
    None
}

fn estimate_pdf_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 || &bytes[..5] != b"%PDF-" {
        return None;
    }

    let eof = bytes.windows(5).rposition(|window| window == b"%%EOF")?;
    let mut end = eof + 5;
    while end < bytes.len() && matches!(bytes[end], b'\r' | b'\n' | b' ' | b'\t' | 0x1A) {
        end += 1;
    }
    Some(end as u64)
}

fn estimate_png_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1A\n" {
        return None;
    }

    let mut cursor = 8usize;
    let mut saw_ihdr = false;
    while cursor + 12 <= bytes.len() {
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().ok()?) as usize;
        let chunk_type = &bytes[cursor + 4..cursor + 8];
        if !chunk_type.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        let chunk_end = cursor.checked_add(12)?.checked_add(length)?;
        if chunk_end > bytes.len() {
            return None;
        }

        if chunk_type == b"IHDR" {
            if length != 13 {
                return None;
            }
            let width = u32::from_be_bytes(bytes[cursor + 8..cursor + 12].try_into().ok()?);
            let height = u32::from_be_bytes(bytes[cursor + 12..cursor + 16].try_into().ok()?);
            if width == 0 || height == 0 {
                return None;
            }
            saw_ihdr = true;
        }

        cursor = chunk_end;
        if chunk_type == b"IEND" {
            return saw_ihdr.then_some(cursor as u64);
        }
    }

    None
}

fn estimate_jpeg_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 || bytes[2] != 0xFF {
        return None;
    }

    let mut cursor = 2usize;
    let mut saw_structure = false;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] != 0xFF {
            return None;
        }

        while cursor < bytes.len() && bytes[cursor] == 0xFF {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            return None;
        }

        let marker = bytes[cursor];
        cursor += 1;
        match marker {
            0xD8 => continue,
            0xD9 => return saw_structure.then_some(cursor as u64),
            0xDA => {
                return saw_structure
                    .then(|| scan_jpeg_scan_data(bytes, cursor))
                    .flatten()
                    .map(|end| end as u64);
            }
            0x01 | 0xD0..=0xD7 => {
                saw_structure = true;
            }
            _ => {
                if cursor + 2 > bytes.len() {
                    return None;
                }
                let segment_length =
                    u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                if segment_length < 2 {
                    return None;
                }
                cursor = cursor.checked_add(segment_length)?;
                if cursor > bytes.len() {
                    return None;
                }
                saw_structure = true;
            }
        }
    }

    None
}

fn scan_jpeg_scan_data(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    while cursor + 1 < bytes.len() {
        if bytes[cursor] != 0xFF {
            cursor += 1;
            continue;
        }

        match bytes[cursor + 1] {
            0x00 => cursor += 2,
            0xD0..=0xD7 => cursor += 2,
            0xD9 => return Some(cursor + 2),
            _ => cursor += 1,
        }
    }

    None
}

fn estimate_gif_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 13 || !matches!(&bytes[..6], b"GIF87a" | b"GIF89a") {
        return None;
    }

    let mut cursor = 13usize;
    let packed = bytes[10];
    if packed & 0x80 != 0 {
        let table_entries = 1usize << ((packed & 0x07) + 1);
        cursor = cursor.checked_add(3 * table_entries)?;
    }

    while cursor < bytes.len() {
        match bytes[cursor] {
            0x21 => {
                cursor += 1;
                if cursor >= bytes.len() {
                    return None;
                }
                cursor += 1;
                skip_gif_sub_blocks(bytes, &mut cursor)?;
            }
            0x2C => {
                cursor += 1;
                if cursor + 9 > bytes.len() {
                    return None;
                }
                let packed = bytes[cursor + 8];
                cursor += 9;
                if packed & 0x80 != 0 {
                    let table_entries = 1usize << ((packed & 0x07) + 1);
                    cursor = cursor.checked_add(3 * table_entries)?;
                }
                if cursor >= bytes.len() {
                    return None;
                }
                cursor += 1;
                skip_gif_sub_blocks(bytes, &mut cursor)?;
            }
            0x3B => return Some((cursor + 1) as u64),
            _ => return None,
        }
    }

    None
}

fn skip_gif_sub_blocks(bytes: &[u8], cursor: &mut usize) -> Option<()> {
    while *cursor < bytes.len() {
        let block_len = bytes[*cursor] as usize;
        *cursor += 1;
        if block_len == 0 {
            return Some(());
        }
        *cursor = cursor.checked_add(block_len)?;
        if *cursor > bytes.len() {
            return None;
        }
    }

    None
}

fn extension_for_kind(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Exe | ArtifactKind::Pe => "exe",
        ArtifactKind::Dll => "dll",
        ArtifactKind::Sys => "sys",
        ArtifactKind::Msi => "msi",
        ArtifactKind::Jar => "jar",
        ArtifactKind::Zip => "zip",
        ArtifactKind::Apk => "apk",
        ArtifactKind::Rar => "rar",
        ArtifactKind::SevenZip => "7z",
        ArtifactKind::Cab => "cab",
        ArtifactKind::Gzip => "gz",
        ArtifactKind::Bzip2 => "bz2",
        ArtifactKind::Xz => "xz",
        ArtifactKind::Iso => "iso",
        ArtifactKind::Pdf => "pdf",
        ArtifactKind::Png => "png",
        ArtifactKind::Jpg => "jpg",
        ArtifactKind::Gif => "gif",
        ArtifactKind::Sqlite => "sqlite3",
        ArtifactKind::OleCompound => "ole",
        _ => "bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_scan_segments_spreads_budget_across_multiple_extents_first() {
        let extents = vec![
            rss_core::ByteRun {
                offset: 0x0000,
                length: 4 * PRIORITY_EXTENT_SLICE,
                sparse: false,
            },
            rss_core::ByteRun {
                offset: 0x8000_0000,
                length: 2 * PRIORITY_EXTENT_SLICE,
                sparse: false,
            },
        ];

        let segments = build_scan_segments(&extents);

        assert!(segments.len() >= 4);
        assert_eq!(segments[0].offset, 0x0000);
        assert_eq!(segments[0].length, PRIORITY_HEAD_SLICE);
        assert_eq!(segments[1].offset, 0x8000_0000);
        assert_eq!(segments[1].length, PRIORITY_HEAD_SLICE);
        assert_eq!(
            segments[2].offset,
            (4 * PRIORITY_EXTENT_SLICE) - (PRIORITY_EXTENT_SLICE - PRIORITY_HEAD_SLICE)
        );
        assert_eq!(
            segments[3].offset,
            (2 * PRIORITY_EXTENT_SLICE) + 0x8000_0000
                - (PRIORITY_EXTENT_SLICE - PRIORITY_HEAD_SLICE)
        );
    }

    #[test]
    fn build_carve_runs_starts_from_containing_extent() {
        let extents = vec![
            rss_core::ByteRun {
                offset: 0x1000,
                length: 0x1000,
                sparse: false,
            },
            rss_core::ByteRun {
                offset: 0x4000,
                length: 0x2000,
                sparse: false,
            },
            rss_core::ByteRun {
                offset: 0x6000,
                length: 0x1000,
                sparse: false,
            },
        ];

        let runs = build_carve_runs(0x4800, 0x1800, &extents);

        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].offset, 0x4800);
        assert_eq!(runs[0].length, 0x1800);
        assert!(!runs[0].sparse);
    }

    #[test]
    fn estimate_pdf_size_uses_eof_marker() {
        let bytes = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n";
        assert_eq!(estimate_pdf_size(bytes), Some(bytes.len() as u64));
    }

    #[test]
    fn estimate_png_size_walks_chunks_until_iend() {
        let bytes = [
            b"\x89PNG\r\n\x1A\n".as_slice(),
            b"\x00\x00\x00\x0DIHDR",
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00IEND",
            b"\xAE\x42\x60\x82",
        ]
        .concat();
        assert_eq!(estimate_png_size(&bytes), Some(bytes.len() as u64));
    }

    #[test]
    fn estimate_gif_size_finds_trailer() {
        let bytes = [
            b"GIF89a".as_slice(),
            b"\x01\x00\x01\x00\x80\x00\x00",
            b"\x00\x00\x00\xFF\xFF\xFF",
            b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00",
            b"\x02\x02\x4C\x01\x00",
            b"\x3B",
        ]
        .concat();
        assert_eq!(estimate_gif_size(&bytes), Some(bytes.len() as u64));
    }

    #[test]
    fn estimate_rar4_size_uses_footer_when_present() {
        let mut bytes = b"Rar!\x1A\x07\x00header".to_vec();
        bytes.extend_from_slice(&[0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00]);
        assert_eq!(estimate_rar_size(&bytes), Some((bytes.len() as u64, true)));
    }

    #[test]
    fn estimate_rar5_size_uses_footer_when_present() {
        let mut bytes = b"Rar!\x1A\x07\x01\x00payload".to_vec();
        bytes.extend_from_slice(&[0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00]);
        assert_eq!(estimate_rar_size(&bytes), Some((bytes.len() as u64, true)));
    }

    #[test]
    fn estimate_jpeg_size_finds_eoi() {
        let bytes = [
            b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00".as_slice(),
            b"\xFF\xDB\x00\x04\x00\x00",
            b"\xFF\xC0\x00\x11\x08\x00\x01\x00\x01\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00",
            b"\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00",
            b"\x00\x11\x22\x33\x44",
            b"\xFF\xD9",
        ]
        .concat();
        assert_eq!(estimate_jpeg_size(&bytes), Some(bytes.len() as u64));
    }
}
