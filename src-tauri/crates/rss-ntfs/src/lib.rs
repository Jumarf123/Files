use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ntfs_reader::{
    api::ntfs_to_unix_time,
    api::{FIRST_NORMAL_RECORD, NtfsAttributeType, NtfsFileName, NtfsFileNamespace, ROOT_RECORD},
    attribute::DataRun,
    file_info::{FileInfo, VecCache},
    mft::Mft,
    volume::Volume,
};
use rss_core::{
    ArtifactClass, ArtifactFamily, ArtifactKind, ArtifactRecord, Confidence, ContentSourceKind,
    DeletedTimeConfidence, DeletedTimeSource, FileSystemKind, NameSourceKind, PathConfidence,
    PathEvidence, PathEvidenceSource, PlacementKind, PreviewFact, RawEvidenceMode, Recoverability,
    RecoveryPlan, ScanMode, ScanSource, infer_artifact_kind, infer_artifact_kind_from_bytes,
    now_iso,
};
use rss_windows::{RawReader, VolumeBitmap};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

mod evidence;

const FAST_PROGRESS_RECORD_INTERVAL: u64 = 262_144;
const DEEP_PROGRESS_RECORD_INTERVAL: u64 = 16_384;
const FAST_RESULT_BATCH_SIZE: usize = 16_384;
const DEEP_RESULT_BATCH_SIZE: usize = 256;
const FAST_EMIT_INTERVAL: Duration = Duration::from_millis(900);
const DEEP_EMIT_INTERVAL: Duration = Duration::from_millis(300);
const FAST_PREVIEW_BYTES: usize = 2048;
const DEEP_PREVIEW_BYTES: usize = 32 * 1024;
const FAST_ISO_PREVIEW_BYTES: usize = 4 * 1024;
const DEEP_ISO_PREVIEW_BYTES: usize = 40 * 1024;

enum NtfsDataStream {
    Resident(Vec<u8>),
    NonResident {
        logical_size: u64,
        runs: Vec<DataRun>,
    },
}

#[derive(Debug, Clone)]
struct FileNameCandidate {
    name: String,
    original_path: Option<String>,
    probable_path: Option<String>,
    parent_reference: u64,
    namespace: u8,
    placement_kind: PlacementKind,
    path_confidence: PathConfidence,
    path_evidence: Vec<PathEvidence>,
    created_at: Option<String>,
    modified_at: Option<String>,
    last_metadata_change_at: Option<String>,
}

struct PathResolution {
    path: std::path::PathBuf,
    placement_kind: PlacementKind,
    confidence: PathConfidence,
    evidence_source: PathEvidenceSource,
    note: &'static str,
}

struct NtfsInspectContext<'a> {
    source: &'a ScanSource,
    mode: ScanMode,
    bitmap: Option<&'a VolumeBitmap>,
    mft: &'a Mft,
    cache: &'a mut VecCache,
    path_cache: &'a mut HashMap<u64, std::path::PathBuf>,
    preview_reader: &'a mut Option<RawReader>,
    preview_reader_open_failed: &'a mut bool,
    warnings: &'a mut Vec<String>,
}

pub fn scan_deleted_entries<F, R>(
    scan_id: &str,
    source: &ScanSource,
    mode: ScanMode,
    bitmap: Option<&VolumeBitmap>,
    raw_evidence: &rss_core::RawEvidenceConfig,
    mut on_progress: F,
    mut on_raw_progress: R,
    warnings: &mut Vec<String>,
) -> Result<Vec<ArtifactRecord>>
where
    F: FnMut(u64, u64, usize, &[ArtifactRecord]) -> bool,
    R: FnMut(&str, f32) -> bool,
{
    if source.filesystem != FileSystemKind::Ntfs {
        return Err(anyhow!("{} is not an NTFS source", source.display_name));
    }

    let volume = Volume::new(&source.device_path)
        .with_context(|| format!("Failed to open NTFS volume {}", source.device_path))?;
    let mft = Mft::new(volume).context("Failed to read NTFS MFT")?;
    let mut cache = VecCache::default();
    let mut path_cache = HashMap::new();
    let mut results = Vec::new();
    let mut preview_reader: Option<RawReader> = None;
    let mut preview_reader_open_failed = false;
    let mut last_emitted_result_count = 0usize;
    let mut last_emit_at = Instant::now();

    for record_number in FIRST_NORMAL_RECORD..mft.max_record {
        let Some(file) = mft.get_record(record_number) else {
            if should_emit_progress(
                mode,
                record_number,
                mft.max_record,
                results.len(),
                last_emitted_result_count,
                last_emit_at,
            ) {
                let batch = &results[last_emitted_result_count..];
                if !on_progress(record_number + 1, mft.max_record, results.len(), batch) {
                    return Ok(results);
                }
                last_emitted_result_count = results.len();
                last_emit_at = Instant::now();
            }
            continue;
        };

        // Deleted NTFS entries often survive in MFT slots whose bitmap bit is already
        // cleared. Walking every valid file record avoids missing those freed records.
        if file.is_used() || file.is_directory() {
            if should_emit_progress(
                mode,
                record_number,
                mft.max_record,
                results.len(),
                last_emitted_result_count,
                last_emit_at,
            ) {
                let batch = &results[last_emitted_result_count..];
                if !on_progress(record_number + 1, mft.max_record, results.len(), batch) {
                    return Ok(results);
                }
                last_emitted_result_count = results.len();
                last_emit_at = Instant::now();
            }
            continue;
        }

        let inspected_record = inspect_deleted_record(
            scan_id,
            &mut NtfsInspectContext {
                source,
                mode,
                bitmap,
                mft: &mft,
                cache: &mut cache,
                path_cache: &mut path_cache,
                preview_reader: &mut preview_reader,
                preview_reader_open_failed: &mut preview_reader_open_failed,
                warnings,
            },
            &file,
            record_number,
        );

        let Some(record) = inspected_record else {
            if should_emit_progress(
                mode,
                record_number,
                mft.max_record,
                results.len(),
                last_emitted_result_count,
                last_emit_at,
            ) {
                let batch = &results[last_emitted_result_count..];
                if !on_progress(record_number + 1, mft.max_record, results.len(), batch) {
                    return Ok(results);
                }
                last_emitted_result_count = results.len();
                last_emit_at = Instant::now();
            }
            continue;
        };
        results.push(record);

        if should_emit_progress(
            mode,
            record_number,
            mft.max_record,
            results.len(),
            last_emitted_result_count,
            last_emit_at,
        ) {
            let batch = &results[last_emitted_result_count..];
            if !on_progress(record_number + 1, mft.max_record, results.len(), batch) {
                return Ok(results);
            }
            last_emitted_result_count = results.len();
            last_emit_at = Instant::now();
        }
    }

    if last_emitted_result_count < results.len() {
        let batch = &results[last_emitted_result_count..];
        if !on_progress(mft.max_record, mft.max_record, results.len(), batch) {
            return Ok(results);
        }
    }

    apply_recycle_bin_metadata(&mut results);
    if raw_evidence.mode != RawEvidenceMode::ManualDeep
        && (raw_evidence.i30_enabled || raw_evidence.usn_enabled)
    {
        if !on_raw_progress(
            "Refining deleted paths from NTFS $I30 and USN Journal evidence",
            0.0,
        ) {
            sort_results(mode, &mut results);
            return Ok(results);
        }
        evidence::apply_raw_evidence(scan_id, source, &mft, &mut results, warnings, raw_evidence);
        if !on_raw_progress("NTFS raw evidence refinement complete", 1.0) {
            sort_results(mode, &mut results);
            return Ok(results);
        }
    }
    sort_results(mode, &mut results);
    Ok(results)
}

pub fn refine_raw_evidence<P, C>(
    scan_id: &str,
    source: &ScanSource,
    results: &mut Vec<ArtifactRecord>,
    warnings: &mut Vec<String>,
    config: &rss_core::RawEvidenceConfig,
    on_progress: P,
    should_cancel: C,
) -> Result<bool>
where
    P: FnMut(&str, f32, u64, Option<u64>) -> bool,
    C: FnMut() -> bool,
{
    if source.filesystem != FileSystemKind::Ntfs {
        return Err(anyhow!("{} is not an NTFS source", source.display_name));
    }
    if !config.i30_enabled && !config.usn_enabled {
        return Ok(true);
    }

    let volume = Volume::new(&source.device_path)
        .with_context(|| format!("Failed to open NTFS volume {}", source.device_path))?;
    let mft = Mft::new(volume).context("Failed to read NTFS MFT")?;
    let completed = evidence::apply_raw_evidence_with_progress(
        scan_id,
        source,
        &mft,
        results,
        warnings,
        config,
        on_progress,
        should_cancel,
    );
    sort_results(ScanMode::Deep, results);
    Ok(completed)
}

pub fn inspect_deleted_records(
    scan_id: &str,
    source: &ScanSource,
    mode: ScanMode,
    bitmap: Option<&VolumeBitmap>,
    warnings: &mut Vec<String>,
    record_numbers: &[u64],
) -> Result<Vec<ArtifactRecord>> {
    if source.filesystem != FileSystemKind::Ntfs {
        return Err(anyhow!("{} is not an NTFS source", source.display_name));
    }

    let volume = Volume::new(&source.device_path)
        .with_context(|| format!("Failed to open NTFS volume {}", source.device_path))?;
    let mft = Mft::new(volume).context("Failed to read NTFS MFT")?;
    let mut cache = VecCache::default();
    let mut path_cache = HashMap::new();
    let mut preview_reader: Option<RawReader> = None;
    let mut preview_reader_open_failed = false;
    let mut results = Vec::new();

    for &record_number in record_numbers {
        let Some(file) = mft.get_record(record_number) else {
            continue;
        };
        if file.is_used() || file.is_directory() {
            continue;
        }
        if let Some(record) = inspect_deleted_record(
            scan_id,
            &mut NtfsInspectContext {
                source,
                mode,
                bitmap,
                mft: &mft,
                cache: &mut cache,
                path_cache: &mut path_cache,
                preview_reader: &mut preview_reader,
                preview_reader_open_failed: &mut preview_reader_open_failed,
                warnings,
            },
            &file,
            record_number,
        ) {
            results.push(record);
        }
    }

    apply_recycle_bin_metadata(&mut results);
    sort_results(mode, &mut results);
    Ok(results)
}

fn inspect_deleted_record(
    scan_id: &str,
    ctx: &mut NtfsInspectContext<'_>,
    file: &ntfs_reader::file::NtfsFile<'_>,
    record_number: u64,
) -> Option<ArtifactRecord> {
    let slot_marked_present = ctx.mft.record_exists(record_number);
    let fallback_name = format!("deleted_record_{record_number}");
    let cheap_candidates = collect_file_name_candidates(ctx, file, &fallback_name, None, false);
    let mut selected_name = select_best_name_candidate(&cheap_candidates, ArtifactKind::Unknown)
        .cloned()
        .unwrap_or_else(|| FileNameCandidate {
            name: fallback_name.clone(),
            original_path: None,
            probable_path: None,
            parent_reference: 0,
            namespace: NtfsFileNamespace::Win32 as u8,
            placement_kind: PlacementKind::UnknownParent,
            path_confidence: PathConfidence::Unknown,
            path_evidence: Vec::new(),
            created_at: None,
            modified_at: None,
            last_metadata_change_at: None,
        });
    let mut original_path = selected_name.original_path.clone();
    let mut resolved_name = selected_name.name.clone();
    let mut name_source = classify_name_source(&selected_name, &fallback_name);

    let mut record = ArtifactRecord::new(scan_id, &ctx.source.id, &resolved_name);
    record.deleted_entry = true;
    record.filesystem_record = Some(record_number);
    record.size = ntfs_primary_logical_size(file);
    record.original_path = original_path;
    record.probable_path = selected_name.probable_path.clone();
    record.extension = extension(&resolved_name);
    record.kind = infer_artifact_kind(&resolved_name, None);
    record.family = record.kind.family();
    record.priority_score = record.kind.priority_score();
    record.name_source = name_source;
    record.path_evidence = selected_name.path_evidence.clone();
    record.created_at = selected_name.created_at.clone();
    record.modified_at = selected_name.modified_at.clone();
    record.last_metadata_change_at = selected_name.last_metadata_change_at.clone();
    if selected_name.parent_reference != 0 {
        record.parent_reference = Some(selected_name.parent_reference);
    }

    if record.original_path.is_some() {
        record.confidence = Confidence::High;
        record.placement_kind = selected_name.placement_kind;
        record.path_confidence = selected_name.path_confidence;
    } else {
        record.placement_kind = selected_name.placement_kind;
        record.path_confidence = selected_name.path_confidence;
    }
    if !slot_marked_present {
        record.notes.push(
            "Recovered from a freed MFT slot; metadata may be stale or partially overwritten."
                .to_string(),
        );
    }

    let data_stream = match best_ntfs_data_stream(file, ctx.mft) {
        Ok(data_stream) => data_stream,
        Err(error) => {
            push_unique_warning(
                ctx.warnings,
                format!(
                    "NTFS data stream parsing for record {} on {} was skipped: {}",
                    record_number, ctx.source.display_name, error
                ),
            );
            None
        }
    };
    if let Some(data_stream) = data_stream.as_ref() {
        record.size = match data_stream {
            NtfsDataStream::Resident(bytes) => bytes.len() as u64,
            NtfsDataStream::NonResident { logical_size, .. } => *logical_size,
        };
    }

    let recovery_plan = if let Some(data_stream) = data_stream.as_ref() {
        match data_stream {
            NtfsDataStream::Resident(bytes) => {
                record.recoverability = Recoverability::Good;
                record.content_source = ContentSourceKind::ResidentData;
                RecoveryPlan::ResidentBase64 {
                    base64: BASE64.encode(bytes),
                    logical_size: record.size,
                }
            }
            NtfsDataStream::NonResident { logical_size, runs } => {
                if let Some(first) = runs.iter().find_map(|run| match run {
                    DataRun::Data { lcn, length } => Some((*lcn, *length)),
                    DataRun::Sparse { .. } => None,
                }) {
                    record.raw_offset = Some(first.0);
                    record.raw_length = Some(first.1);
                }
                let converted_runs = convert_runs(runs.to_vec());
                record.recoverability = assess_recoverability(ctx.bitmap, &converted_runs);
                record.content_source = ContentSourceKind::RawRuns;
                if record.recoverability != Recoverability::Good {
                    record.notes.push(
                        "One or more NTFS data runs are currently allocated or sparse.".to_string(),
                    );
                }
                RecoveryPlan::RawRuns {
                    source_path: ctx.source.device_path.clone(),
                    runs: converted_runs,
                    logical_size: *logical_size,
                }
            }
        }
    } else {
        record.confidence = Confidence::Low;
        record.recoverability = Recoverability::Poor;
        record
            .notes
            .push("Deleted record has no readable $DATA attribute.".to_string());
        RecoveryPlan::Unrecoverable {
            reason: "Deleted record has no readable $DATA attribute".to_string(),
        }
    };

    let should_enrich = ctx.mode == ScanMode::Deep || should_enrich_deleted_record(&record);
    let mut preview_bytes = Vec::new();
    if should_enrich {
        let file_info = FileInfo::with_cache(ctx.mft, file, ctx.cache);
        let fallback_original_path = normalize_path(
            &ctx.source.device_path,
            ctx.source.mount_point.as_deref(),
            &file_info.path,
        );
        let name_candidates = collect_file_name_candidates(
            ctx,
            file,
            &resolved_name,
            fallback_original_path.as_deref(),
            true,
        );
        if let Some(better_candidate) =
            select_best_name_candidate(&name_candidates, record.kind).cloned()
        {
            selected_name = better_candidate.clone();
            original_path = selected_name.original_path.clone();
            resolved_name = selected_name.name.clone();
            name_source = classify_name_source(&selected_name, &fallback_name);
            record.name = resolved_name.clone();
            record.original_path = original_path.clone();
            record.probable_path = selected_name.probable_path.clone();
            record.extension = extension(&resolved_name);
            record.name_source = name_source;
            record.placement_kind = selected_name.placement_kind;
            record.path_confidence = selected_name.path_confidence;
            record.path_evidence = selected_name.path_evidence.clone();
            record.created_at = selected_name
                .created_at
                .clone()
                .or_else(|| record.created_at.clone());
            record.modified_at = selected_name
                .modified_at
                .clone()
                .or_else(|| record.modified_at.clone());
            record.last_metadata_change_at = selected_name
                .last_metadata_change_at
                .clone()
                .or_else(|| record.last_metadata_change_at.clone());
            record.parent_reference =
                (selected_name.parent_reference != 0).then_some(selected_name.parent_reference);
        }

        record.created_at = file_info
            .created
            .and_then(format_time)
            .or_else(|| record.created_at.clone());
        record.modified_at = file_info
            .modified
            .and_then(format_time)
            .or_else(|| record.modified_at.clone());

        if should_capture_preview(ctx.mode, &record, data_stream.as_ref()) {
            let target_len = preview_probe_length(ctx.mode, record.kind);
            match data_stream.as_ref() {
                Some(NtfsDataStream::Resident(bytes)) => {
                    preview_bytes = bytes.iter().copied().take(target_len).collect();
                }
                Some(NtfsDataStream::NonResident { runs, .. }) => {
                    let reader = if ctx.preview_reader.is_some() {
                        ctx.preview_reader.as_mut()
                    } else if !*ctx.preview_reader_open_failed {
                        match RawReader::open(&ctx.source.device_path) {
                            Ok(reader) => {
                                *ctx.preview_reader = Some(reader);
                                ctx.preview_reader.as_mut()
                            }
                            Err(err) => {
                                *ctx.preview_reader_open_failed = true;
                                push_unique_warning(
                                    ctx.warnings,
                                    format!(
                                        "Preview reads on {} were skipped because the raw device could not be opened: {}",
                                        ctx.source.display_name, err
                                    ),
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    if let Some(reader) = reader {
                        match read_preview_bytes(reader, runs, target_len) {
                            Ok(bytes) => {
                                preview_bytes = bytes;
                            }
                            Err(err) => {
                                push_unique_warning(
                                    ctx.warnings,
                                    format!(
                                        "Preview reads on {} were skipped after an I/O error: {}",
                                        ctx.source.display_name, err
                                    ),
                                );
                            }
                        }
                    }
                }
                None => {}
            }
        }

        if !preview_bytes.is_empty() || matches!(record.kind, rss_core::ArtifactKind::Unknown) {
            let signature_kind = if preview_bytes.is_empty() {
                ArtifactKind::Unknown
            } else {
                infer_artifact_kind_from_bytes(&preview_bytes)
            };
            let preview_kind = if signature_kind != rss_core::ArtifactKind::Unknown {
                infer_artifact_kind(&record.name, Some(&preview_bytes))
            } else {
                ArtifactKind::Unknown
            };
            if preview_kind != rss_core::ArtifactKind::Unknown
                || record.kind == rss_core::ArtifactKind::Unknown
            {
                record.kind = preview_kind;
                record.family = preview_kind.family();
                record.priority_score = preview_kind.priority_score();
            } else if !preview_bytes.is_empty() {
                record.notes.push(
                    "Preview bytes did not preserve a stronger signature than the surviving filename metadata."
                        .to_string(),
                );
                if ctx.mode == ScanMode::Deep
                    && matches!(
                        record.family,
                        ArtifactFamily::Executable
                            | ArtifactFamily::Archive
                            | ArtifactFamily::Database
                            | ArtifactFamily::Container
                    )
                {
                    record.confidence = Confidence::Medium.max(record.confidence);
                    record.notes.push(
                        "Deep validation did not confirm the filename-derived type from the available header bytes."
                            .to_string(),
                    );
                }
            }
            if ctx.mode == ScanMode::Deep && !preview_bytes.is_empty() {
                record.preview = preview_facts(&preview_bytes);
            }
        }
        if record.original_path.is_none() {
            record.notes.push(
                "Original path could not be reconstructed from surviving $FILE_NAME metadata."
                    .to_string(),
            );
            if record.probable_path.is_some() {
                record.notes.push(
                    "A probable path was reconstructed from MFT record numbers, but one or more parent sequence values no longer match."
                        .to_string(),
                );
            }
        } else {
            record.confidence = Confidence::High;
            record.placement_kind = PlacementKind::OriginalPath;
            record.path_confidence = PathConfidence::Exact;
        }
        record.preview_ready = !preview_bytes.is_empty();
    } else {
        record.preview_ready = false;
    }

    if record.original_path.is_some() {
        if matches!(record.path_confidence, PathConfidence::Unknown) {
            record.placement_kind = PlacementKind::OriginalPath;
            record.path_confidence = PathConfidence::Exact;
        }
    } else if record.probable_path.is_none() {
        record.placement_kind = PlacementKind::UnknownParent;
        record.path_confidence = PathConfidence::Unknown;
    }
    apply_generated_name_confidence(&mut record);

    if record.extension.is_none()
        && let Some(default_extension) = default_extension_for_kind(record.kind)
    {
        record.extension = Some(default_extension.to_string());
    }
    if record.deleted_at.is_none() && record.last_metadata_change_at.is_some() {
        record.deleted_time_source = Some(DeletedTimeSource::MftMetadata);
        record.deleted_time_confidence = DeletedTimeConfidence::Estimated;
    }

    record.artifact_class = classify_ntfs_record(&record);

    if ctx.mode == ScanMode::Fast && !keep_fast_record(&record) {
        return None;
    }
    record.recovery_plan = recovery_plan;
    Some(record)
}

fn collect_file_name_candidates(
    ctx: &mut NtfsInspectContext<'_>,
    file: &ntfs_reader::file::NtfsFile<'_>,
    fallback_name: &str,
    fallback_original_path: Option<&str>,
    resolve_paths: bool,
) -> Vec<FileNameCandidate> {
    let mut candidates = Vec::new();
    let mut seen = std::collections::HashSet::new();

    file.attributes(|attribute| {
        if attribute.header.type_id != NtfsAttributeType::FileName as u32 {
            return;
        }
        let Some(name_attr) = attribute.as_name() else {
            return;
        };
        if name_attr.is_reparse_point() {
            return;
        }

        let name = name_attr.to_string();
        if name.is_empty() {
            return;
        }

        let mut original_path = None;
        let mut probable_path = None;
        let mut placement_kind = PlacementKind::UnknownParent;
        let mut path_confidence = PathConfidence::Unknown;
        let mut path_evidence = Vec::new();
        if resolve_paths
            && let Some(resolution) =
                reconstruct_file_name_candidate_path(ctx.mft, ctx.path_cache, file, &name_attr)
            && let Some(normalized_path) = normalize_path(
                &ctx.source.device_path,
                ctx.source.mount_point.as_deref(),
                &resolution.path,
            )
        {
            placement_kind = resolution.placement_kind;
            path_confidence = resolution.confidence;
            if matches!(
                resolution.confidence,
                PathConfidence::Exact | PathConfidence::Reconstructed
            ) {
                original_path = Some(normalized_path.clone());
            } else {
                probable_path = Some(normalized_path.clone());
            }
            path_evidence.push(PathEvidence {
                source: resolution.evidence_source,
                path: Some(normalized_path),
                confidence: resolution.confidence,
                note: resolution.note.to_string(),
            });
        }
        let (created_at, modified_at, last_metadata_change_at) = file_name_timestamps(&name_attr);

        let key = (name.clone(), original_path.clone(), probable_path.clone());
        if seen.insert(key) {
            candidates.push(FileNameCandidate {
                name,
                original_path,
                probable_path,
                parent_reference: name_attr.parent(),
                namespace: name_attr.header.namespace,
                placement_kind,
                path_confidence,
                path_evidence,
                created_at,
                modified_at,
                last_metadata_change_at,
            });
        }
    });

    if candidates.is_empty() {
        candidates.push(FileNameCandidate {
            name: fallback_name.to_string(),
            original_path: fallback_original_path.map(str::to_string),
            probable_path: None,
            parent_reference: 0,
            namespace: NtfsFileNamespace::Win32 as u8,
            placement_kind: if fallback_original_path.is_some() {
                PlacementKind::OriginalPath
            } else {
                PlacementKind::UnknownParent
            },
            path_confidence: if fallback_original_path.is_some() {
                PathConfidence::Reconstructed
            } else {
                PathConfidence::Unknown
            },
            path_evidence: Vec::new(),
            created_at: None,
            modified_at: None,
            last_metadata_change_at: None,
        });
    }

    candidates
}

fn should_enrich_deleted_record(record: &ArtifactRecord) -> bool {
    record.original_path.is_none()
        || matches!(
            record.family,
            ArtifactFamily::Executable
                | ArtifactFamily::Archive
                | ArtifactFamily::Container
                | ArtifactFamily::Database
                | ArtifactFamily::Document
                | ArtifactFamily::Image
                | ArtifactFamily::Script
                | ArtifactFamily::Config
                | ArtifactFamily::Text
        )
        || matches!(
            record.kind,
            ArtifactKind::Unknown | ArtifactKind::Bin | ArtifactKind::Dat
        )
        || matches!(
            record.recoverability,
            Recoverability::Good | Recoverability::Partial
        )
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.iter().any(|existing| existing == &warning) {
        return;
    }
    warnings.push(warning);
}

fn reconstruct_file_name_candidate_path(
    mft: &Mft,
    cache: &mut HashMap<u64, std::path::PathBuf>,
    file: &ntfs_reader::file::NtfsFile<'_>,
    candidate: &NtfsFileName,
) -> Option<PathResolution> {
    let mut next_parent_reference = ntfs_file_name_parent_reference(candidate);
    let mut components = Vec::new();
    let mut cached_path = None;
    let mut saw_sequence_mismatch = false;
    let mut saw_deleted_directory = false;
    let mut seen_records = std::collections::HashSet::new();

    loop {
        let next_parent = ntfs_reference_record_number(next_parent_reference);
        if next_parent == ROOT_RECORD {
            break;
        }
        if !seen_records.insert(next_parent) {
            return None;
        }

        if !saw_sequence_mismatch && let Some(parent_path) = cache.get(&next_parent_reference) {
            cached_path = Some(parent_path.to_path_buf());
            break;
        }

        let parent = mft.get_record(next_parent)?;
        if parent.reference_number() != next_parent_reference {
            saw_sequence_mismatch = true;
        }
        if !parent.is_used() {
            saw_deleted_directory = true;
        }
        let parent_name = parent.get_best_file_name(mft)?;
        let parent_component = parent_name.to_string();
        if parent_component.is_empty() {
            return None;
        }
        components.push((
            parent.reference_number(),
            std::path::PathBuf::from(parent_component),
        ));
        next_parent_reference = ntfs_file_name_parent_reference(&parent_name);
    }

    let mut path = cached_path.unwrap_or_else(|| mft.volume.path.clone());
    for (reference, component) in components.iter().rev() {
        path.push(component);
        if !saw_sequence_mismatch {
            cache.insert(*reference, path.clone());
        }
    }
    path.push(candidate.to_string());
    if !saw_sequence_mismatch {
        cache.insert(file.reference_number(), path.clone());
    }
    let (placement_kind, confidence, evidence_source, note) = if saw_sequence_mismatch {
        (
            PlacementKind::BrokenParentChain,
            PathConfidence::Partial,
            PathEvidenceSource::MftSequenceMismatch,
            "Parent MFT record number was still present, but the sequence value changed; path is probable, not exact.",
        )
    } else if saw_deleted_directory {
        (
            PlacementKind::OriginalPath,
            PathConfidence::Reconstructed,
            PathEvidenceSource::MftDeletedDirectory,
            "Path was reconstructed through one or more deleted directory MFT records.",
        )
    } else {
        (
            PlacementKind::OriginalPath,
            PathConfidence::Exact,
            PathEvidenceSource::MftExact,
            "Parent MFT references matched through the directory chain.",
        )
    };
    Some(PathResolution {
        path,
        placement_kind,
        confidence,
        evidence_source,
        note,
    })
}

fn ntfs_file_name_parent_reference(candidate: &NtfsFileName) -> u64 {
    unsafe { std::ptr::addr_of!(candidate.header.parent_directory_reference).read_unaligned() }
}

fn ntfs_reference_record_number(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

fn file_name_timestamps(
    candidate: &NtfsFileName,
) -> (Option<String>, Option<String>, Option<String>) {
    let raw = unsafe { std::ptr::addr_of!(candidate.header.crap_0).read_unaligned() };
    (
        format_ntfs_filetime(read_le_u64(&raw[0..8])),
        format_ntfs_filetime(read_le_u64(&raw[8..16])),
        format_ntfs_filetime(read_le_u64(&raw[16..24])),
    )
}

fn read_le_u64(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(value)
}

fn format_ntfs_filetime(value: u64) -> Option<String> {
    if value == 0 {
        return None;
    }
    format_time(ntfs_to_unix_time(value))
}

fn select_best_name_candidate(
    candidates: &[FileNameCandidate],
    preview_kind: ArtifactKind,
) -> Option<&FileNameCandidate> {
    candidates
        .iter()
        .max_by_key(|candidate| score_file_name_candidate(candidate, preview_kind))
}

fn score_file_name_candidate(
    candidate: &FileNameCandidate,
    preview_kind: ArtifactKind,
) -> (u8, u8, u8, u8, usize) {
    let candidate_kind = infer_artifact_kind(&candidate.name, None);
    let kind_match = candidate_matches_preview_kind(candidate_kind, preview_kind) as u8;
    let specificity_rank = match candidate_kind {
        ArtifactKind::Unknown | ArtifactKind::Bin | ArtifactKind::Dat => {
            extension(&candidate.name).is_some() as u8
        }
        _ => 2,
    };
    let namespace_rank = match candidate.namespace {
        value if value == NtfsFileNamespace::Win32AndDos as u8 => 3,
        value if value == NtfsFileNamespace::Win32 as u8 => 2,
        value if value == NtfsFileNamespace::Posix as u8 => 1,
        _ => 0,
    };
    let path_rank = if candidate.original_path.is_some() {
        2
    } else if candidate.probable_path.is_some() {
        1
    } else {
        0
    };
    (
        kind_match,
        specificity_rank,
        path_rank,
        namespace_rank,
        candidate.name.len(),
    )
}

fn candidate_matches_preview_kind(
    candidate_kind: ArtifactKind,
    preview_kind: ArtifactKind,
) -> bool {
    if preview_kind == ArtifactKind::Unknown {
        return false;
    }
    if candidate_kind == preview_kind {
        return true;
    }

    matches!(preview_kind, ArtifactKind::Pe)
        && matches!(
            candidate_kind,
            ArtifactKind::Exe
                | ArtifactKind::Dll
                | ArtifactKind::Sys
                | ArtifactKind::Scr
                | ArtifactKind::Ocx
                | ArtifactKind::Cpl
                | ArtifactKind::Pe
        )
}

fn classify_name_source(candidate: &FileNameCandidate, fallback_name: &str) -> NameSourceKind {
    if candidate.name.starts_with("deleted_record_") {
        return NameSourceKind::Generated;
    }
    if candidate.name != fallback_name {
        return match candidate.namespace {
            value if value == NtfsFileNamespace::Dos as u8 => NameSourceKind::DosName,
            _ => NameSourceKind::Reconstructed,
        };
    }
    match candidate.namespace {
        value if value == NtfsFileNamespace::Dos as u8 => NameSourceKind::DosName,
        _ => NameSourceKind::LongName,
    }
}

fn keep_fast_record(record: &ArtifactRecord) -> bool {
    if record.deleted_entry && record.filesystem_record.is_some() {
        return true;
    }

    let path_resolved = record.original_path.is_some();
    let has_extension = record
        .extension
        .as_deref()
        .is_some_and(|extension| !extension.is_empty());
    let specific_kind = !matches!(
        record.kind,
        rss_core::ArtifactKind::Unknown | rss_core::ArtifactKind::Bin | rss_core::ArtifactKind::Dat
    );
    let recoverable = matches!(
        record.recoverability,
        Recoverability::Good | Recoverability::Partial
    );
    let autogenerated_name = record.name.starts_with("deleted_record_");
    let named_record = !autogenerated_name || path_resolved;
    let executable_name = record
        .extension
        .as_deref()
        .is_some_and(is_fast_executable_extension);
    let high_priority_family = matches!(
        record.family,
        rss_core::ArtifactFamily::Executable
            | rss_core::ArtifactFamily::Archive
            | rss_core::ArtifactFamily::Script
            | rss_core::ArtifactFamily::Image
            | rss_core::ArtifactFamily::Database
            | rss_core::ArtifactFamily::Document
            | rss_core::ArtifactFamily::Container
            | rss_core::ArtifactFamily::Config
            | rss_core::ArtifactFamily::Text
    );
    let metadata_quality =
        record.size > 0 && record.confidence != Confidence::Low && (path_resolved || has_extension);
    let useful_named_candidate = named_record
        && (path_resolved || has_extension || executable_name)
        && (record.size > 0 || executable_name);
    let named_metadata_candidate = named_record
        && (path_resolved || has_extension || executable_name)
        && record.filesystem_record.is_some();

    if autogenerated_name && !path_resolved && !specific_kind && !recoverable {
        return false;
    }

    useful_named_candidate
        || named_metadata_candidate
        || recoverable
        || high_priority_family
        || specific_kind
        || metadata_quality
}

fn should_emit_progress(
    mode: ScanMode,
    record_number: u64,
    max_record: u64,
    result_count: usize,
    last_emitted_result_count: usize,
    last_emit_at: Instant,
) -> bool {
    let new_results = result_count.saturating_sub(last_emitted_result_count);
    new_results >= result_batch_size(mode)
        || last_emit_at.elapsed() >= emit_interval(mode)
        || (record_number + 1).is_multiple_of(progress_record_interval(mode))
        || record_number + 1 == max_record
}

fn emit_interval(mode: ScanMode) -> Duration {
    match mode {
        ScanMode::Fast => FAST_EMIT_INTERVAL,
        ScanMode::Deep => DEEP_EMIT_INTERVAL,
    }
}

fn progress_record_interval(mode: ScanMode) -> u64 {
    match mode {
        ScanMode::Fast => FAST_PROGRESS_RECORD_INTERVAL,
        ScanMode::Deep => DEEP_PROGRESS_RECORD_INTERVAL,
    }
}

fn result_batch_size(mode: ScanMode) -> usize {
    match mode {
        ScanMode::Fast => FAST_RESULT_BATCH_SIZE,
        ScanMode::Deep => DEEP_RESULT_BATCH_SIZE,
    }
}

fn sort_results(_mode: ScanMode, results: &mut [ArtifactRecord]) {
    results.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then(left.confidence.cmp(&right.confidence))
            .then(path_confidence_rank(left).cmp(&path_confidence_rank(right)))
            .then(name_source_rank(left).cmp(&name_source_rank(right)))
            .then(right.created_at.is_some().cmp(&left.created_at.is_some()))
            .then(right.modified_at.is_some().cmp(&left.modified_at.is_some()))
            .then(left.recoverability.cmp(&right.recoverability))
            .then(left.name.cmp(&right.name))
    });
}

fn path_confidence_rank(record: &ArtifactRecord) -> u8 {
    match record.path_confidence {
        PathConfidence::Exact => 0,
        PathConfidence::Reconstructed => 1,
        PathConfidence::Partial => 2,
        PathConfidence::Unknown => 3,
    }
}

fn name_source_rank(record: &ArtifactRecord) -> u8 {
    match record.name_source {
        NameSourceKind::LongName => 0,
        NameSourceKind::Reconstructed => 1,
        NameSourceKind::DosName => 2,
        NameSourceKind::Generated => 3,
    }
}

fn apply_generated_name_confidence(record: &mut ArtifactRecord) {
    if matches!(record.name_source, NameSourceKind::Generated) {
        record.confidence = if record.original_path.is_some() {
            Confidence::Medium
        } else {
            Confidence::Low
        };
    }
}

fn should_capture_preview(
    mode: ScanMode,
    record: &ArtifactRecord,
    data_stream: Option<&NtfsDataStream>,
) -> bool {
    let Some(data_stream) = data_stream else {
        return false;
    };
    if record.size == 0 {
        return false;
    }

    match mode {
        ScanMode::Deep => true,
        ScanMode::Fast => {
            if matches!(data_stream, NtfsDataStream::Resident(_)) {
                // Resident payloads already live inside the MFT record we are parsing, so
                // probing them improves filename/content fidelity without extra raw-disk I/O.
                return true;
            }
            let small_nonresident_high_value = matches!(
                data_stream,
                NtfsDataStream::NonResident { logical_size, .. }
                    if *logical_size > 0
                        && *logical_size <= 256 * 1024
                        && matches!(
                            record.family,
                            ArtifactFamily::Archive
                                | ArtifactFamily::Script
                                | ArtifactFamily::Document
                                | ArtifactFamily::Database
                                | ArtifactFamily::Image
                                | ArtifactFamily::Config
                                | ArtifactFamily::Text
                                | ArtifactFamily::Container
                        )
            );
            let generic_kind = matches!(
                record.kind,
                rss_core::ArtifactKind::Unknown
                    | rss_core::ArtifactKind::Bin
                    | rss_core::ArtifactKind::Dat
            );
            let missing_extension = record.extension.as_deref().is_none_or(|extension| {
                extension.eq_ignore_ascii_case("bin") || extension.eq_ignore_ascii_case("dat")
            });
            generic_kind
                || missing_extension
                || record.original_path.is_none()
                || record.name.starts_with("deleted_record_")
                || matches!(record.family, ArtifactFamily::Executable)
                || small_nonresident_high_value
                || record
                    .extension
                    .as_deref()
                    .is_some_and(is_fast_executable_extension)
        }
    }
}

fn preview_probe_length(mode: ScanMode, kind: rss_core::ArtifactKind) -> usize {
    match (mode, kind) {
        (ScanMode::Fast, rss_core::ArtifactKind::Iso) => FAST_ISO_PREVIEW_BYTES,
        (
            ScanMode::Fast,
            rss_core::ArtifactKind::Exe
            | rss_core::ArtifactKind::Dll
            | rss_core::ArtifactKind::Sys
            | rss_core::ArtifactKind::Scr
            | rss_core::ArtifactKind::Ocx
            | rss_core::ArtifactKind::Cpl
            | rss_core::ArtifactKind::Pe,
        ) => 4 * 1024,
        (
            ScanMode::Fast,
            rss_core::ArtifactKind::Zip
            | rss_core::ArtifactKind::Jar
            | rss_core::ArtifactKind::Apk
            | rss_core::ArtifactKind::Rar
            | rss_core::ArtifactKind::SevenZip
            | rss_core::ArtifactKind::Cab
            | rss_core::ArtifactKind::Tar
            | rss_core::ArtifactKind::Gzip
            | rss_core::ArtifactKind::Bzip2
            | rss_core::ArtifactKind::Xz
            | rss_core::ArtifactKind::Pdf
            | rss_core::ArtifactKind::Sqlite
            | rss_core::ArtifactKind::Msi
            | rss_core::ArtifactKind::OleCompound,
        ) => 4 * 1024,
        (
            ScanMode::Fast,
            rss_core::ArtifactKind::Png | rss_core::ArtifactKind::Jpg | rss_core::ArtifactKind::Gif,
        ) => 2 * 1024,
        (
            ScanMode::Fast,
            rss_core::ArtifactKind::Bat
            | rss_core::ArtifactKind::Cmd
            | rss_core::ArtifactKind::Ps1
            | rss_core::ArtifactKind::Vbs
            | rss_core::ArtifactKind::Js
            | rss_core::ArtifactKind::Ini
            | rss_core::ArtifactKind::Cfg
            | rss_core::ArtifactKind::Json
            | rss_core::ArtifactKind::Yml
            | rss_core::ArtifactKind::Yaml
            | rss_core::ArtifactKind::Txt
            | rss_core::ArtifactKind::Log,
        ) => 8 * 1024,
        (ScanMode::Deep, rss_core::ArtifactKind::Iso) => DEEP_ISO_PREVIEW_BYTES,
        (ScanMode::Fast, _) => FAST_PREVIEW_BYTES,
        (ScanMode::Deep, _) => DEEP_PREVIEW_BYTES,
    }
}

fn classify_ntfs_record(record: &ArtifactRecord) -> ArtifactClass {
    if record.is_fragment || record.origin_type == rss_core::OriginType::PartialFragment {
        return ArtifactClass::FragmentCandidate;
    }
    if matches!(
        record.recoverability,
        Recoverability::Good | Recoverability::Partial
    ) {
        return ArtifactClass::Recoverable;
    }
    if record.preview_ready
        || !matches!(
            record.kind,
            ArtifactKind::Unknown | ArtifactKind::Bin | ArtifactKind::Dat
        )
    {
        return ArtifactClass::ValidatedHit;
    }
    ArtifactClass::NamedMetadataCandidate
}

#[derive(Debug, Clone)]
struct RecycleBinMetadata {
    original_path: String,
    deleted_at: Option<String>,
}

fn apply_recycle_bin_metadata(results: &mut [ArtifactRecord]) {
    let mut by_payload_name: HashMap<String, RecycleBinMetadata> = HashMap::new();

    for record in results.iter_mut() {
        let Some(payload_name) = recycle_payload_name_for_info_record(&record.name) else {
            continue;
        };
        let Some(bytes) = resident_recovery_bytes(record) else {
            continue;
        };
        let Some(metadata) = parse_recycle_bin_info(&bytes) else {
            continue;
        };
        apply_recycle_metadata(record, &metadata);
        by_payload_name.insert(payload_name, metadata);
    }

    for record in results.iter_mut() {
        let key = record.name.to_ascii_lowercase();
        if let Some(metadata) = by_payload_name.get(&key) {
            apply_recycle_metadata(record, metadata);
        }
    }
}

fn resident_recovery_bytes(record: &ArtifactRecord) -> Option<Vec<u8>> {
    let RecoveryPlan::ResidentBase64 { base64, .. } = &record.recovery_plan else {
        return None;
    };
    BASE64.decode(base64).ok()
}

fn recycle_payload_name_for_info_record(name: &str) -> Option<String> {
    let suffix = name
        .strip_prefix("$I")
        .or_else(|| name.strip_prefix("$i"))?;
    if suffix.is_empty() {
        return None;
    }
    Some(format!("$r{suffix}").to_ascii_lowercase())
}

fn parse_recycle_bin_info(bytes: &[u8]) -> Option<RecycleBinMetadata> {
    if bytes.len() < 24 {
        return None;
    }
    let version = read_le_u64(&bytes[0..8]);
    let deleted_at = format_ntfs_filetime(read_le_u64(&bytes[16..24]));
    let path_bytes = if version >= 2 && bytes.len() >= 28 {
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&bytes[24..28]);
        let path_chars = u32::from_le_bytes(length_bytes) as usize;
        let byte_len = path_chars.saturating_mul(2);
        let end = 28usize.saturating_add(byte_len).min(bytes.len());
        &bytes[28..end]
    } else {
        &bytes[24..]
    };
    let original_path = utf16_null_terminated(path_bytes)?;
    if original_path.is_empty() {
        return None;
    }
    Some(RecycleBinMetadata {
        original_path,
        deleted_at,
    })
}

fn utf16_null_terminated(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            break;
        }
        units.push(value);
    }
    String::from_utf16(&units).ok()
}

fn apply_recycle_metadata(record: &mut ArtifactRecord, metadata: &RecycleBinMetadata) {
    if record.original_path.is_none() {
        record.original_path = Some(metadata.original_path.clone());
        record.probable_path = None;
        record.placement_kind = PlacementKind::OriginalPath;
        record.path_confidence = PathConfidence::Exact;
        record.confidence = Confidence::High;
    }
    if let Some(deleted_at) = metadata.deleted_at.clone() {
        record.deleted_at = Some(deleted_at);
        record.deleted_time_source = Some(DeletedTimeSource::RecycleBin);
        record.deleted_time_confidence = DeletedTimeConfidence::Exact;
    }
    record.path_evidence.push(PathEvidence {
        source: PathEvidenceSource::RecycleBin,
        path: record.original_path.clone(),
        confidence: PathConfidence::Exact,
        note: "$Recycle.Bin $I metadata preserved the original path and deletion timestamp."
            .to_string(),
    });
}

fn is_fast_executable_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "dll" | "exe" | "sys" | "ocx" | "scr" | "cpl" | "mui" | "cat"
    )
}

fn normalize_path(
    device_path: &str,
    mount_point: Option<&str>,
    raw_path: &std::path::Path,
) -> Option<String> {
    let raw = raw_path.to_string_lossy().to_string();
    if raw.is_empty() {
        return None;
    }
    if let Some(root) = mount_point {
        return Some(raw.replacen(device_path, root.trim_end_matches('\\'), 1));
    }
    Some(raw)
}

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty())
}

#[cfg_attr(not(test), allow(dead_code))]
fn file_name_from_path(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn ntfs_primary_logical_size(file: &ntfs_reader::file::NtfsFile<'_>) -> u64 {
    let mut unnamed_size = None;
    let mut named_max = 0u64;

    file.attributes(|attribute| {
        if attribute.header.type_id != NtfsAttributeType::Data as u32 {
            return;
        }

        let size = if attribute.header.is_non_resident != 0 {
            attribute
                .nonresident_header()
                .map(|header| header.data_size)
                .unwrap_or(0)
        } else {
            attribute
                .resident_header()
                .map(|header| header.value_length as u64)
                .unwrap_or(0)
        };

        if attribute.header.name_length == 0 {
            unnamed_size = Some(unnamed_size.unwrap_or(0).max(size));
        } else {
            named_max = named_max.max(size);
        }
    });

    unnamed_size.unwrap_or(named_max)
}

fn format_time(value: time::OffsetDateTime) -> Option<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn convert_runs(runs: Vec<DataRun>) -> Vec<rss_core::ByteRun> {
    runs.into_iter()
        .map(|run| match run {
            DataRun::Data { lcn, length } => rss_core::ByteRun {
                offset: lcn,
                length,
                sparse: false,
            },
            DataRun::Sparse { length } => rss_core::ByteRun {
                offset: 0,
                length,
                sparse: true,
            },
        })
        .collect()
}

fn assess_recoverability(
    bitmap: Option<&VolumeBitmap>,
    runs: &[rss_core::ByteRun],
) -> Recoverability {
    let Some(bitmap) = bitmap else {
        return Recoverability::Unknown;
    };

    if runs.is_empty() {
        return Recoverability::Poor;
    }

    let mut any_allocated = false;
    let mut any_data = false;

    for run in runs {
        if run.sparse {
            continue;
        }
        any_data = true;
        if !bitmap.covers_range(run.offset, run.length) {
            any_allocated = true;
            break;
        }
    }

    if !any_data || any_allocated {
        Recoverability::Partial
    } else {
        Recoverability::Good
    }
}

pub fn refresh_recoverability(bitmap: &VolumeBitmap, results: &mut [ArtifactRecord]) {
    for artifact in results {
        if let RecoveryPlan::RawRuns { runs, .. } = &artifact.recovery_plan {
            artifact.recoverability = assess_recoverability(Some(bitmap), runs);
        }
    }
}

fn read_preview_bytes(
    raw_reader: &mut RawReader,
    runs: &[DataRun],
    target_len: usize,
) -> Result<Vec<u8>> {
    let mut preview = Vec::new();
    let mut remaining = target_len as u64;

    for run in runs {
        if remaining == 0 {
            break;
        }

        match run {
            DataRun::Data { lcn, length } => {
                let chunk = usize::try_from((*length).min(remaining)).unwrap_or(target_len);
                let bytes = raw_reader.read_at(*lcn, chunk)?;
                preview.extend_from_slice(&bytes);
                remaining = remaining.saturating_sub(bytes.len() as u64);
            }
            DataRun::Sparse { length } => {
                let chunk = usize::try_from((*length).min(remaining)).unwrap_or(target_len);
                preview.resize(preview.len() + chunk, 0);
                remaining = remaining.saturating_sub(chunk as u64);
            }
        }
    }

    Ok(preview)
}

fn best_ntfs_data_stream(
    file: &ntfs_reader::file::NtfsFile<'_>,
    mft: &Mft,
) -> Result<Option<NtfsDataStream>> {
    let mut unnamed: Option<(u64, NtfsDataStream)> = None;
    let mut named: Option<(u64, NtfsDataStream)> = None;

    file.attributes(|attribute| {
        if attribute.header.type_id != NtfsAttributeType::Data as u32 {
            return;
        }

        let candidate = if attribute.header.is_non_resident != 0 {
            attribute
                .get_nonresident_data_runs(&mft.volume)
                .ok()
                .map(|(logical_size, runs)| {
                    (
                        logical_size,
                        NtfsDataStream::NonResident { logical_size, runs },
                    )
                })
        } else {
            attribute
                .as_resident_data()
                .map(|bytes| (bytes.len() as u64, NtfsDataStream::Resident(bytes.to_vec())))
        };

        let Some(candidate) = candidate else {
            return;
        };

        if attribute.header.name_length == 0 {
            let replace = unnamed
                .as_ref()
                .map(|(size, _)| candidate.0 > *size)
                .unwrap_or(true);
            if replace {
                unnamed = Some(candidate);
            }
        } else {
            let replace = named
                .as_ref()
                .map(|(size, _)| candidate.0 > *size)
                .unwrap_or(true);
            if replace {
                named = Some(candidate);
            }
        }
    });

    Ok(unnamed.or(named).map(|(_, data)| data))
}

fn default_extension_for_kind(kind: rss_core::ArtifactKind) -> Option<&'static str> {
    match kind {
        rss_core::ArtifactKind::Exe | rss_core::ArtifactKind::Pe => Some("exe"),
        rss_core::ArtifactKind::Dll => Some("dll"),
        rss_core::ArtifactKind::Sys => Some("sys"),
        rss_core::ArtifactKind::Msi => Some("msi"),
        rss_core::ArtifactKind::Jar => Some("jar"),
        rss_core::ArtifactKind::Zip => Some("zip"),
        rss_core::ArtifactKind::Rar => Some("rar"),
        rss_core::ArtifactKind::SevenZip => Some("7z"),
        rss_core::ArtifactKind::Cab => Some("cab"),
        rss_core::ArtifactKind::Iso => Some("iso"),
        rss_core::ArtifactKind::Apk => Some("apk"),
        rss_core::ArtifactKind::Pdf => Some("pdf"),
        rss_core::ArtifactKind::Png => Some("png"),
        rss_core::ArtifactKind::Jpg => Some("jpg"),
        rss_core::ArtifactKind::Gif => Some("gif"),
        rss_core::ArtifactKind::Sqlite => Some("sqlite3"),
        rss_core::ArtifactKind::Bat => Some("bat"),
        rss_core::ArtifactKind::Cmd => Some("cmd"),
        rss_core::ArtifactKind::Ps1 => Some("ps1"),
        rss_core::ArtifactKind::Vbs => Some("vbs"),
        rss_core::ArtifactKind::Js => Some("js"),
        rss_core::ArtifactKind::Ini => Some("ini"),
        rss_core::ArtifactKind::Cfg => Some("cfg"),
        rss_core::ArtifactKind::Json => Some("json"),
        rss_core::ArtifactKind::Yml => Some("yml"),
        rss_core::ArtifactKind::Yaml => Some("yaml"),
        rss_core::ArtifactKind::Txt => Some("txt"),
        rss_core::ArtifactKind::Log => Some("log"),
        _ => None,
    }
}

fn preview_facts(bytes: &[u8]) -> Vec<PreviewFact> {
    let mut facts = Vec::new();
    match infer_artifact_kind("preview.bin", Some(bytes)) {
        rss_core::ArtifactKind::Exe
        | rss_core::ArtifactKind::Dll
        | rss_core::ArtifactKind::Sys
        | rss_core::ArtifactKind::Pe => {
            facts.push(PreviewFact {
                label: "Signature".to_string(),
                value: "MZ / PE image".to_string(),
            });
            if let Some((machine, timestamp, sections)) = parse_pe_preview(bytes) {
                facts.push(PreviewFact {
                    label: "Machine".to_string(),
                    value: machine,
                });
                facts.push(PreviewFact {
                    label: "Compile Time".to_string(),
                    value: timestamp,
                });
                facts.push(PreviewFact {
                    label: "Sections".to_string(),
                    value: sections.to_string(),
                });
            }
        }
        rss_core::ArtifactKind::Jar => {
            facts.push(PreviewFact {
                label: "Signature".to_string(),
                value: "ZIP local header".to_string(),
            });
            facts.push(PreviewFact {
                label: "Subtype".to_string(),
                value: "JAR".to_string(),
            });
        }
        rss_core::ArtifactKind::Apk => {
            facts.push(PreviewFact {
                label: "Signature".to_string(),
                value: "ZIP local header".to_string(),
            });
            facts.push(PreviewFact {
                label: "Subtype".to_string(),
                value: "APK".to_string(),
            });
        }
        rss_core::ArtifactKind::Zip => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "ZIP local header".to_string(),
        }),
        rss_core::ArtifactKind::Rar => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "RAR archive".to_string(),
        }),
        rss_core::ArtifactKind::SevenZip => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "7-Zip archive".to_string(),
        }),
        rss_core::ArtifactKind::Cab => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "Microsoft Cabinet".to_string(),
        }),
        rss_core::ArtifactKind::Pdf => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "PDF document".to_string(),
        }),
        rss_core::ArtifactKind::Png => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "PNG image".to_string(),
        }),
        rss_core::ArtifactKind::Jpg => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "JPEG image".to_string(),
        }),
        rss_core::ArtifactKind::Gif => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "GIF image".to_string(),
        }),
        rss_core::ArtifactKind::Sqlite => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "SQLite database".to_string(),
        }),
        rss_core::ArtifactKind::Msi => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "OLE Compound / MSI database".to_string(),
        }),
        rss_core::ArtifactKind::OleCompound => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "OLE Compound".to_string(),
        }),
        rss_core::ArtifactKind::Iso => facts.push(PreviewFact {
            label: "Signature".to_string(),
            value: "ISO 9660 primary volume descriptor".to_string(),
        }),
        _ => {}
    }

    facts.push(PreviewFact {
        label: "Preview Captured".to_string(),
        value: now_iso(),
    });
    facts
}

fn parse_pe_preview(bytes: &[u8]) -> Option<(String, String, u16)> {
    if bytes.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.len() < e_lfanew + 24 {
        return None;
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes(bytes[e_lfanew + 4..e_lfanew + 6].try_into().ok()?);
    let sections = u16::from_le_bytes(bytes[e_lfanew + 6..e_lfanew + 8].try_into().ok()?);
    let timestamp_raw = u32::from_le_bytes(bytes[e_lfanew + 8..e_lfanew + 12].try_into().ok()?);
    let timestamp = time::OffsetDateTime::from_unix_timestamp(timestamp_raw as i64)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()?;
    let machine = match machine {
        0x014c => "x86",
        0x8664 => "x64",
        0x01c4 => "ARM",
        0xaa64 => "ARM64",
        _ => "unknown",
    }
    .to_string();
    Some((machine, timestamp, sections))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{ArtifactFamily, ArtifactKind, ByteRun, OriginType};

    fn test_record(name: &str) -> ArtifactRecord {
        let mut record = ArtifactRecord::new("scan-1", "source-1", name);
        record.origin_type = OriginType::FilesystemDeletedEntry;
        record
    }

    fn candidate(name: &str, namespace: u8) -> FileNameCandidate {
        FileNameCandidate {
            name: name.to_string(),
            original_path: Some(format!("C:\\Audit\\{name}")),
            probable_path: None,
            parent_reference: 42,
            namespace,
            placement_kind: PlacementKind::OriginalPath,
            path_confidence: PathConfidence::Exact,
            path_evidence: Vec::new(),
            created_at: None,
            modified_at: None,
            last_metadata_change_at: None,
        }
    }

    #[test]
    fn fast_mode_keeps_low_confidence_mft_records_for_recall() {
        let mut record = test_record("deleted_record_42");
        record.kind = ArtifactKind::Unknown;
        record.family = ArtifactFamily::Unknown;
        record.recoverability = Recoverability::Poor;
        record.confidence = Confidence::Low;
        record.size = 0;
        record.filesystem_record = Some(42);

        assert!(keep_fast_record(&record));
    }

    #[test]
    fn generated_pathless_records_stay_low_confidence() {
        let mut record = test_record("deleted_record_42");
        record.name_source = NameSourceKind::Generated;
        record.original_path = None;
        record.confidence = Confidence::Medium;

        apply_generated_name_confidence(&mut record);

        assert_eq!(record.confidence, Confidence::Low);
    }

    #[test]
    fn fast_mode_keeps_recoverable_named_records() {
        let mut record = test_record("report.txt");
        record.extension = Some("txt".to_string());
        record.original_path = Some("C:\\Users\\Public\\report.txt".to_string());
        record.kind = ArtifactKind::Txt;
        record.family = ArtifactFamily::Text;
        record.recoverability = Recoverability::Good;
        record.confidence = Confidence::High;
        record.size = 512;

        assert!(keep_fast_record(&record));
    }

    #[test]
    fn fast_mode_keeps_high_priority_pathless_records() {
        let mut record = test_record("deleted_record_77");
        record.kind = ArtifactKind::Zip;
        record.family = ArtifactFamily::Archive;
        record.recoverability = Recoverability::Partial;
        record.confidence = Confidence::Medium;
        record.size = 4096;

        assert!(keep_fast_record(&record));
    }

    #[test]
    fn fast_mode_keeps_named_executable_candidates_even_with_weak_size() {
        let mut record = test_record("vec.dll");
        record.extension = Some("dll".to_string());
        record.kind = ArtifactKind::Dll;
        record.family = ArtifactFamily::Executable;
        record.confidence = Confidence::Low;
        record.recoverability = Recoverability::Unknown;
        record.size = 0;
        record.filesystem_record = Some(1_337);

        assert!(keep_fast_record(&record));
    }

    #[test]
    fn prefers_name_candidate_that_matches_preview_kind() {
        let candidates = vec![
            candidate("metrics.interim", NtfsFileNamespace::Win32 as u8),
            candidate("launcher.exe", NtfsFileNamespace::Win32AndDos as u8),
        ];

        let selected = select_best_name_candidate(&candidates, ArtifactKind::Exe)
            .expect("candidate should be selected");

        assert_eq!(selected.name, "launcher.exe");
    }

    #[test]
    fn falls_back_to_namespace_quality_when_preview_kind_is_unknown() {
        let candidates = vec![
            candidate("audit.txt", NtfsFileNamespace::Posix as u8),
            candidate("audit-final.txt", NtfsFileNamespace::Win32AndDos as u8),
        ];

        let selected = select_best_name_candidate(&candidates, ArtifactKind::Unknown)
            .expect("candidate should be selected");

        assert_eq!(selected.name, "audit-final.txt");
    }

    #[test]
    fn prefers_specific_extension_when_preview_kind_is_unknown() {
        let candidates = vec![
            candidate(".metadata-v2", NtfsFileNamespace::Win32AndDos as u8),
            candidate("installer.msi", NtfsFileNamespace::Win32 as u8),
        ];

        let selected = select_best_name_candidate(&candidates, ArtifactKind::Unknown)
            .expect("candidate should be selected");

        assert_eq!(selected.name, "installer.msi");
    }

    #[test]
    fn prefers_candidate_with_original_path_when_quality_is_otherwise_close() {
        let candidates = vec![
            FileNameCandidate {
                name: "payload.bin".to_string(),
                original_path: None,
                probable_path: None,
                parent_reference: 42,
                namespace: NtfsFileNamespace::Win32AndDos as u8,
                placement_kind: PlacementKind::UnknownParent,
                path_confidence: PathConfidence::Unknown,
                path_evidence: Vec::new(),
                created_at: None,
                modified_at: None,
                last_metadata_change_at: None,
            },
            FileNameCandidate {
                name: "payload.bin".to_string(),
                original_path: Some("C:\\Recovered\\payload.bin".to_string()),
                probable_path: None,
                parent_reference: 42,
                namespace: NtfsFileNamespace::Win32 as u8,
                placement_kind: PlacementKind::OriginalPath,
                path_confidence: PathConfidence::Exact,
                path_evidence: Vec::new(),
                created_at: None,
                modified_at: None,
                last_metadata_change_at: None,
            },
        ];

        let selected = select_best_name_candidate(&candidates, ArtifactKind::Unknown)
            .expect("candidate should be selected");

        assert_eq!(
            selected.original_path.as_deref(),
            Some("C:\\Recovered\\payload.bin")
        );
    }

    #[test]
    fn parses_recycle_bin_info_path_and_deleted_time() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&1234u64.to_le_bytes());
        bytes.extend_from_slice(&133_801_632_000_000_000u64.to_le_bytes());
        let path = "C:\\Users\\jumarf\\Downloads\\bundle.jar";
        let utf16 = path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        for unit in utf16 {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let parsed = parse_recycle_bin_info(&bytes).expect("recycle metadata");

        assert_eq!(parsed.original_path, path);
        assert!(parsed.deleted_at.is_some());
    }

    #[test]
    fn fast_preview_keeps_named_resident_records_probeable() {
        let mut record = test_record("report.txt");
        record.extension = Some("txt".to_string());
        record.original_path = Some("C:\\Users\\Public\\report.txt".to_string());
        record.kind = ArtifactKind::Txt;
        record.family = ArtifactFamily::Text;
        record.size = 1024;

        assert!(should_capture_preview(
            ScanMode::Fast,
            &record,
            Some(&NtfsDataStream::Resident(vec![0u8; 32]))
        ));
    }

    #[test]
    fn fast_preview_keeps_small_named_text_records_probeable() {
        let mut record = test_record("report.txt");
        record.extension = Some("txt".to_string());
        record.original_path = Some("C:\\Users\\Public\\report.txt".to_string());
        record.kind = ArtifactKind::Txt;
        record.family = ArtifactFamily::Text;
        record.size = 4096;

        assert!(should_capture_preview(
            ScanMode::Fast,
            &record,
            Some(&NtfsDataStream::NonResident {
                logical_size: 4096,
                runs: vec![DataRun::Sparse { length: 4096 }],
            })
        ));
    }

    #[test]
    fn fast_preview_keeps_small_nonresident_archives_probeable() {
        let mut record = test_record("bundle.zip");
        record.extension = Some("zip".to_string());
        record.original_path = Some("C:\\Users\\Public\\bundle.zip".to_string());
        record.kind = ArtifactKind::Zip;
        record.family = ArtifactFamily::Archive;
        record.size = 64 * 1024;

        assert!(should_capture_preview(
            ScanMode::Fast,
            &record,
            Some(&NtfsDataStream::NonResident {
                logical_size: 64 * 1024,
                runs: vec![DataRun::Sparse { length: 64 * 1024 }],
            })
        ));
    }

    #[test]
    fn fast_preview_keeps_pathless_autogenerated_records_probeable() {
        let mut record = test_record("deleted_record_91");
        record.kind = ArtifactKind::Unknown;
        record.family = ArtifactFamily::Unknown;
        record.size = 1024;

        assert!(should_capture_preview(
            ScanMode::Fast,
            &record,
            Some(&NtfsDataStream::Resident(vec![0u8; 32]))
        ));
    }

    #[test]
    fn recoverability_is_good_when_bitmap_covers_all_runs() {
        let bitmap = VolumeBitmap {
            cluster_size: 4096,
            extents: vec![ByteRun {
                offset: 0x1000,
                length: 0x3000,
                sparse: false,
            }],
        };
        let runs = vec![ByteRun {
            offset: 0x1000,
            length: 0x2000,
            sparse: false,
        }];

        assert_eq!(
            assess_recoverability(Some(&bitmap), &runs),
            Recoverability::Good
        );
    }

    #[test]
    fn recoverability_is_partial_when_bitmap_does_not_cover_run() {
        let bitmap = VolumeBitmap {
            cluster_size: 4096,
            extents: vec![ByteRun {
                offset: 0x1000,
                length: 0x1000,
                sparse: false,
            }],
        };
        let runs = vec![ByteRun {
            offset: 0x1000,
            length: 0x3000,
            sparse: false,
        }];

        assert_eq!(
            assess_recoverability(Some(&bitmap), &runs),
            Recoverability::Partial
        );
    }

    #[test]
    fn infers_default_extension_for_detected_kind() {
        assert_eq!(default_extension_for_kind(ArtifactKind::Dll), Some("dll"));
        assert_eq!(default_extension_for_kind(ArtifactKind::Pdf), Some("pdf"));
        assert_eq!(default_extension_for_kind(ArtifactKind::Json), Some("json"));
        assert_eq!(default_extension_for_kind(ArtifactKind::Unknown), None);
    }

    #[test]
    fn reconstructs_file_name_from_original_path() {
        assert_eq!(
            file_name_from_path("C:\\Users\\Public\\vec.dll"),
            Some("vec.dll".to_string())
        );
        assert_eq!(
            file_name_from_path("\\Device\\HarddiskVolume3\\Windows\\Temp\\triage.ps1"),
            Some("triage.ps1".to_string())
        );
    }
}
