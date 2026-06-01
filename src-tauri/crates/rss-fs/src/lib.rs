use anyhow::Result;
use rss_carver::carve_high_priority;
use rss_core::{
    ArtifactClass, ArtifactFamily, ArtifactRecord, Confidence, FileSystemKind, OriginType,
    RawEvidenceConfig, RawEvidenceState, ScanCounters, ScanMode, ScanOptions, ScanPhase,
    ScanProgress, ScanSource, ScanStatus, now_iso,
};
use rss_fat::scan_deleted_entries as scan_fat_deleted_entries;
use rss_ntfs::{
    refresh_recoverability as refresh_ntfs_recoverability,
    scan_deleted_entries as scan_ntfs_deleted_entries,
};
use rss_security::enter_background_mode_current_thread;
use rss_windows::read_volume_bitmap;
use std::collections::HashSet;
use std::time::Instant;

const FAST_MODE_CARVE_BUDGET: u64 = 512 * 1024 * 1024;
const NTFS_METADATA_RECORD_BYTES: u64 = 1024;
const FAT_DIRECTORY_ENTRY_BYTES: u64 = 32;

#[derive(Debug, Clone)]
pub struct ScanExecution {
    pub progress: ScanProgress,
    pub results: Vec<ArtifactRecord>,
    pub warnings: Vec<String>,
    pub counters: ScanCounters,
}

pub fn refine_ntfs_raw_evidence<P, C>(
    scan_id: &str,
    source: &ScanSource,
    results: &mut Vec<ArtifactRecord>,
    warnings: &mut Vec<String>,
    config: &RawEvidenceConfig,
    on_progress: P,
    should_cancel: C,
) -> Result<bool>
where
    P: FnMut(&str, f32, u64, Option<u64>) -> bool,
    C: FnMut() -> bool,
{
    rss_ntfs::refine_raw_evidence(
        scan_id,
        source,
        results,
        warnings,
        config,
        on_progress,
        should_cancel,
    )
}

pub fn run_scan<F, G, H>(
    scan_id: &str,
    source: &ScanSource,
    options: &ScanOptions,
    mut on_progress: F,
    mut on_results: G,
    mut should_cancel: H,
) -> Result<ScanExecution>
where
    F: FnMut(ScanProgress),
    G: FnMut(&[ArtifactRecord]),
    H: FnMut() -> bool,
{
    let started_at = now_iso();
    let overall_started = Instant::now();
    let mut stage_started = Instant::now();
    let mut stage_timing_ms = std::collections::BTreeMap::new();
    let mut warnings = Vec::new();
    let mut progress = ScanProgress {
        scan_id: scan_id.to_string(),
        status: ScanStatus::Running,
        phase: ScanPhase::Preparing,
        stage: "preparing".to_string(),
        progress_percent: 0.0,
        files_examined: 0,
        artifacts_found: 0,
        records_scanned: 0,
        candidates_surfaced: 0,
        validated_hits: 0,
        named_hits: 0,
        carved_hits: 0,
        fragment_hits: 0,
        verified_hits: 0,
        recoverable_hits: 0,
        bytes_scanned: 0,
        records_per_second: 0.0,
        eta_seconds: None,
        target_sla_seconds: if options.mode == ScanMode::Fast {
            120
        } else {
            600
        },
        raw_evidence_state: RawEvidenceState::NotStarted,
        message: format!("Preparing scan for {}", source.display_name),
        stage_timing_ms: std::collections::BTreeMap::new(),
        started_at: started_at.clone(),
        last_progress_at: now_iso(),
        updated_at: now_iso(),
    };
    on_progress(progress.clone());
    note_stage_completion(&mut stage_timing_ms, "preparing", &mut stage_started);
    progress.phase = ScanPhase::DiscoveringMetadata;
    progress.stage = "loading_bitmap".to_string();
    progress.progress_percent = 5.0;
    progress.message = "Loading volume metadata and allocation bitmap".to_string();
    progress.stage_timing_ms = stage_timing_ms.clone();
    progress.updated_at = now_iso();
    progress.last_progress_at = progress.updated_at.clone();
    on_progress(progress.clone());

    if should_cancel() {
        return Ok(cancelled_execution(progress, Vec::new(), warnings));
    }

    let mut bitmap = if source.filesystem == FileSystemKind::Ntfs {
        match read_volume_bitmap(source) {
            Ok(bitmap) => Some(bitmap),
            Err(err) => {
                warnings.push(format!(
                    "Allocation bitmap could not be loaded: {err}. Recoverability will be less precise."
                ));
                None
            }
        }
    } else {
        None
    };

    progress.phase = ScanPhase::ScanningDeletedEntries;
    note_stage_completion(&mut stage_timing_ms, "loading_bitmap", &mut stage_started);
    progress.stage = "enumerating_deleted_entries".to_string();
    progress.message = "Enumerating deleted filesystem entries".to_string();
    progress.stage_timing_ms = stage_timing_ms.clone();
    progress.updated_at = now_iso();
    progress.last_progress_at = progress.updated_at.clone();
    on_progress(progress.clone());

    let mut cancelled = false;
    let mut metadata_files_examined = 0u64;
    let mut metadata_bytes_scanned = 0u64;
    let mut carve_bytes_scanned = 0u64;
    let mut metadata_visible_results = 0u64;
    let mut metadata_validated_hits = 0u64;
    let mut metadata_named_hits = 0u64;
    let mut metadata_carved_hits = 0u64;
    let mut metadata_fragment_hits = 0u64;
    let mut recoverable_hits = 0u64;
    let mut results = match source.filesystem {
        FileSystemKind::Ntfs => match scan_ntfs_deleted_entries(
            scan_id,
            source,
            options.mode,
            bitmap.as_ref(),
            &options.raw_evidence,
            |done, total, total_results, new_results| {
                let visible_batch =
                    filtered_results_batch(new_results, options.include_low_confidence);
                metadata_files_examined = metadata_files_examined.max(done);
                metadata_bytes_scanned =
                    metadata_files_examined.saturating_mul(NTFS_METADATA_RECORD_BYTES);
                metadata_visible_results =
                    metadata_visible_results.saturating_add(visible_batch.len() as u64);
                metadata_validated_hits =
                    metadata_validated_hits.saturating_add(count_validated_hits(&visible_batch));
                metadata_named_hits =
                    metadata_named_hits.saturating_add(count_named_hits(&visible_batch));
                metadata_carved_hits =
                    metadata_carved_hits.saturating_add(count_carved_hits(&visible_batch));
                metadata_fragment_hits =
                    metadata_fragment_hits.saturating_add(count_fragment_hits(&visible_batch));
                recoverable_hits += visible_batch
                    .iter()
                    .filter(|artifact| {
                        matches!(
                            artifact.recoverability,
                            rss_core::Recoverability::Good | rss_core::Recoverability::Partial
                        )
                    })
                    .count() as u64;
                progress.progress_percent = 5.0 + ((done as f32 / total.max(1) as f32) * 70.0);
                progress.files_examined = metadata_files_examined;
                progress.records_scanned = done;
                progress.candidates_surfaced = metadata_visible_results;
                progress.validated_hits = metadata_validated_hits;
                progress.named_hits = metadata_named_hits;
                progress.carved_hits = metadata_carved_hits;
                progress.fragment_hits = metadata_fragment_hits;
                progress.verified_hits = progress.validated_hits;
                progress.recoverable_hits = recoverable_hits;
                progress.artifacts_found = progress.validated_hits;
                progress.bytes_scanned = metadata_bytes_scanned.saturating_add(carve_bytes_scanned);
                progress.records_per_second =
                    records_per_second(done, stage_started.elapsed().as_secs_f64());
                progress.stage_timing_ms = stage_timing_ms.clone();
                progress.message = format!(
                    "NTFS MFT pass: {} candidates, {} validated, {} named from {} records ({} raw, {:.0} rec/s)",
                    metadata_visible_results,
                    progress.validated_hits,
                    progress.named_hits,
                    done,
                    total_results,
                    progress.records_per_second
                );
                progress.updated_at = now_iso();
                progress.last_progress_at = progress.updated_at.clone();
                if !visible_batch.is_empty() {
                    on_results(&visible_batch);
                }
                on_progress(progress.clone());
                if should_cancel() {
                    cancelled = true;
                    return false;
                }
                true
            },
            |_, _| true,
            &mut warnings,
        ) {
            Ok(results) => results,
            Err(err) => {
                warnings.push(format!(
                    "NTFS deleted-entry scan could not start: {err}. Continuing with carving and other available sources."
                ));
                Vec::new()
            }
        },
        FileSystemKind::Fat32 => {
            let mut last_fat_processed_result_count = 0usize;
            match scan_fat_deleted_entries(scan_id, source, options.mode, |partial_results| {
                let new_results = &partial_results[last_fat_processed_result_count..];
                let visible_new_results =
                    filtered_results_batch(new_results, options.include_low_confidence);
                last_fat_processed_result_count = partial_results.len();
                metadata_files_examined = metadata_files_examined.max(partial_results.len() as u64);
                metadata_bytes_scanned =
                    metadata_files_examined.saturating_mul(FAT_DIRECTORY_ENTRY_BYTES);
                metadata_visible_results =
                    metadata_visible_results.saturating_add(visible_new_results.len() as u64);
                metadata_validated_hits = metadata_validated_hits
                    .saturating_add(count_validated_hits(&visible_new_results));
                metadata_named_hits =
                    metadata_named_hits.saturating_add(count_named_hits(&visible_new_results));
                metadata_carved_hits =
                    metadata_carved_hits.saturating_add(count_carved_hits(&visible_new_results));
                metadata_fragment_hits = metadata_fragment_hits
                    .saturating_add(count_fragment_hits(&visible_new_results));
                progress.progress_percent = 75.0;
                progress.files_examined = metadata_files_examined;
                progress.records_scanned = metadata_files_examined;
                progress.candidates_surfaced = metadata_visible_results;
                progress.validated_hits = metadata_validated_hits;
                progress.named_hits = metadata_named_hits;
                progress.carved_hits = metadata_carved_hits;
                progress.fragment_hits = metadata_fragment_hits;
                progress.verified_hits = progress.validated_hits;
                recoverable_hits += count_recoverable_hits(&visible_new_results);
                progress.recoverable_hits = recoverable_hits;
                progress.artifacts_found = progress.validated_hits;
                progress.bytes_scanned = metadata_bytes_scanned.saturating_add(carve_bytes_scanned);
                progress.records_per_second = records_per_second(
                    metadata_files_examined,
                    stage_started.elapsed().as_secs_f64(),
                );
                progress.stage_timing_ms = stage_timing_ms.clone();
                progress.message = format!(
                    "FAT directory pass: {} candidates, {} validated, {} named ({:.0} entries/s)",
                    metadata_visible_results,
                    progress.validated_hits,
                    progress.named_hits,
                    progress.records_per_second
                );
                progress.updated_at = now_iso();
                progress.last_progress_at = progress.updated_at.clone();
                if !visible_new_results.is_empty() {
                    on_results(&visible_new_results);
                }
                on_progress(progress.clone());
                if should_cancel() {
                    cancelled = true;
                    return false;
                }
                true
            }) {
                Ok(results) => results,
                Err(err) => {
                    warnings.push(format!(
                        "FAT deleted-entry scan could not start: {err}. Continuing with carving and other available sources."
                    ));
                    Vec::new()
                }
            }
        }
        FileSystemKind::ExFat => {
            warnings.push(
                "exFAT metadata recovery is not yet implemented; only carved artifacts will be available in Deep mode."
                    .to_string(),
            );
            Vec::new()
        }
        FileSystemKind::Unknown => {
            warnings.push(
                "Unknown filesystem: deleted-entry parsing skipped, falling back to carving only."
                    .to_string(),
            );
            Vec::new()
        }
    };
    filter_scan_results(&mut results, options.include_low_confidence);

    progress.files_examined = metadata_files_examined.max(progress.files_examined);
    progress.bytes_scanned = metadata_bytes_scanned
        .saturating_add(carve_bytes_scanned)
        .max(progress.bytes_scanned);

    if cancelled {
        sort_results(&mut results);
        return Ok(cancelled_execution(progress, results, warnings));
    }

    let should_carve = options.mode == ScanMode::Deep || should_run_fast_carve(source, options);

    if should_carve {
        if bitmap.is_none() {
            let _background_guard = enter_background_mode_current_thread().ok();
            match read_volume_bitmap(source) {
                Ok(loaded_bitmap) => {
                    if source.filesystem == FileSystemKind::Ntfs {
                        refresh_ntfs_recoverability(&loaded_bitmap, &mut results);
                    }
                    bitmap = Some(loaded_bitmap);
                }
                Err(err) => warnings.push(format!(
                    "Allocation bitmap could not be loaded before carve pass: {err}. Recoverability will remain approximate."
                )),
            }
        }

        if let Some(bitmap) = bitmap.as_ref() {
            progress.phase = ScanPhase::CarvingHighPriority;
            note_stage_completion(
                &mut stage_timing_ms,
                "enumerating_deleted_entries",
                &mut stage_started,
            );
            progress.stage = "carving_high_priority".to_string();
            progress.message = if options.mode == ScanMode::Deep {
                "Scanning high-priority signatures in unallocated space".to_string()
            } else {
                "Fast-mode carve: checking unallocated space for recoverable signatures".to_string()
            };
            progress.records_per_second = 0.0;
            progress.stage_timing_ms = stage_timing_ms.clone();
            progress.updated_at = now_iso();
            progress.last_progress_at = progress.updated_at.clone();
            on_progress(progress.clone());

            let carve_budget = if options.mode == ScanMode::Fast {
                Some(adaptive_fast_carve_budget(
                    options.carve_budget_bytes.unwrap_or(FAST_MODE_CARVE_BUDGET),
                    metadata_visible_results,
                    metadata_named_hits,
                    recoverable_hits,
                ))
            } else {
                options.carve_budget_bytes
            };
            let mut last_carve_processed_result_count = 0usize;
            let mut carved_visible_results = 0u64;
            let mut carved_validated_hits = 0u64;
            let mut carved_named_hits = 0u64;
            let mut carved_recoverable_hits = 0u64;
            let mut carved_fragment_hits = 0u64;

            match carve_high_priority(
                scan_id,
                source,
                bitmap,
                carve_budget,
                &mut warnings,
                |done, budget, partial_results| {
                    let new_results = &partial_results[last_carve_processed_result_count..];
                    let visible_new_results =
                        filtered_results_batch(new_results, options.include_low_confidence);
                    last_carve_processed_result_count = partial_results.len();
                    carved_visible_results =
                        carved_visible_results.saturating_add(visible_new_results.len() as u64);
                    carved_validated_hits = carved_validated_hits
                        .saturating_add(count_validated_hits(&visible_new_results));
                    carved_named_hits =
                        carved_named_hits.saturating_add(count_named_hits(&visible_new_results));
                    carved_recoverable_hits = carved_recoverable_hits
                        .saturating_add(count_recoverable_hits(&visible_new_results));
                    carved_fragment_hits = carved_fragment_hits
                        .saturating_add(count_fragment_hits(&visible_new_results));
                    progress.progress_percent =
                        75.0 + ((done as f32 / budget.max(1) as f32) * 20.0);
                    carve_bytes_scanned = done;
                    progress.bytes_scanned =
                        metadata_bytes_scanned.saturating_add(carve_bytes_scanned);
                    progress.candidates_surfaced = results
                        .len()
                        .saturating_add(carved_visible_results as usize)
                        as u64;
                    progress.validated_hits =
                        metadata_validated_hits.saturating_add(carved_validated_hits);
                    progress.named_hits = metadata_named_hits.saturating_add(carved_named_hits);
                    progress.carved_hits =
                        metadata_carved_hits.saturating_add(carved_visible_results);
                    progress.fragment_hits =
                        metadata_fragment_hits.saturating_add(carved_fragment_hits);
                    progress.verified_hits = progress.validated_hits;
                    progress.recoverable_hits =
                        recoverable_hits.saturating_add(carved_recoverable_hits);
                    progress.artifacts_found = progress.validated_hits;
                    progress.stage_timing_ms = stage_timing_ms.clone();
                    progress.message = format!(
                        "Carve pass: {} bytes scanned, {} carved, {} validated total",
                        done, carved_visible_results, progress.validated_hits
                    );
                    progress.updated_at = now_iso();
                    progress.last_progress_at = progress.updated_at.clone();
                    if !visible_new_results.is_empty() {
                        on_results(&visible_new_results);
                    }
                    on_progress(progress.clone());
                    if should_cancel() {
                        cancelled = true;
                        return false;
                    }
                    true
                },
            ) {
                Ok(carved) => {
                    merge_results(&mut results, carved);
                    filter_scan_results(&mut results, options.include_low_confidence);
                }
                Err(err) => warnings.push(format!(
                    "High-priority carve pass failed: {err}. Continuing with metadata results only."
                )),
            }
        } else {
            warnings.push(
                "High-priority carve pass skipped because the allocation bitmap is unavailable."
                    .to_string(),
            );
        }
    }

    sort_results(&mut results);
    if cancelled || should_cancel() {
        return Ok(cancelled_execution(progress, results, warnings));
    }
    let counters = collect_counters(&results);

    progress.phase = ScanPhase::Finalizing;
    note_stage_completion(
        &mut stage_timing_ms,
        if should_carve {
            "carving_high_priority"
        } else {
            "enumerating_deleted_entries"
        },
        &mut stage_started,
    );
    progress.stage = "finalizing".to_string();
    progress.progress_percent = 100.0;
    progress.status = if warnings.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::CompletedWithWarnings
    };
    progress.files_examined = metadata_files_examined.max(progress.files_examined);
    progress.candidates_surfaced = results.len() as u64;
    progress.validated_hits = count_validated_hits(&results);
    progress.named_hits = count_named_hits(&results);
    progress.carved_hits = count_carved_hits(&results);
    progress.fragment_hits = count_fragment_hits(&results);
    progress.verified_hits = progress.validated_hits;
    progress.recoverable_hits = results
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.recoverability,
                rss_core::Recoverability::Good | rss_core::Recoverability::Partial
            )
        })
        .count() as u64;
    progress.artifacts_found = progress.validated_hits;
    progress.bytes_scanned = metadata_bytes_scanned
        .saturating_add(carve_bytes_scanned)
        .max(progress.bytes_scanned);
    progress.eta_seconds = Some(0);
    stage_timing_ms.insert(
        "finalizing".to_string(),
        overall_started.elapsed().as_millis() as u64
            - stage_timing_ms.values().copied().sum::<u64>(),
    );
    progress.stage_timing_ms = stage_timing_ms;
    progress.message = format!(
        "Scan complete: {} validated, {} named, {} recoverable deleted files ready",
        progress.validated_hits, progress.named_hits, progress.recoverable_hits
    );
    progress.updated_at = now_iso();
    progress.last_progress_at = progress.updated_at.clone();
    on_progress(progress.clone());

    Ok(ScanExecution {
        progress,
        results,
        warnings,
        counters,
    })
}

fn sort_results(results: &mut [ArtifactRecord]) {
    results.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then(left.confidence.cmp(&right.confidence))
            .then(left.recoverability.cmp(&right.recoverability))
            .then(left.name.cmp(&right.name))
    });
}

fn records_per_second(processed: u64, elapsed_seconds: f64) -> f32 {
    if processed == 0 || elapsed_seconds <= 0.0 {
        return 0.0;
    }
    (processed as f64 / elapsed_seconds.max(0.001)) as f32
}

fn cancelled_execution(
    mut progress: ScanProgress,
    mut results: Vec<ArtifactRecord>,
    warnings: Vec<String>,
) -> ScanExecution {
    sort_results(&mut results);
    let counters = collect_counters(&results);
    progress.status = ScanStatus::Cancelled;
    progress.phase = ScanPhase::Finalizing;
    progress.stage = "cancelled".to_string();
    progress.progress_percent = progress.progress_percent.min(99.0);
    progress.candidates_surfaced = results.len() as u64;
    progress.validated_hits = count_validated_hits(&results);
    progress.named_hits = count_named_hits(&results);
    progress.carved_hits = count_carved_hits(&results);
    progress.fragment_hits = count_fragment_hits(&results);
    progress.verified_hits = progress.validated_hits;
    progress.recoverable_hits = results
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.recoverability,
                rss_core::Recoverability::Good | rss_core::Recoverability::Partial
            )
        })
        .count() as u64;
    progress.artifacts_found = progress.validated_hits;
    progress.message = format!(
        "Scan cancelled: {} validated, {} named deleted files captured",
        progress.validated_hits, progress.named_hits
    );
    progress.updated_at = now_iso();
    progress.last_progress_at = progress.updated_at.clone();

    ScanExecution {
        progress,
        results,
        warnings,
        counters,
    }
}

fn collect_counters(results: &[ArtifactRecord]) -> ScanCounters {
    let mut counters = ScanCounters {
        total_results: results.len(),
        ..ScanCounters::default()
    };
    for artifact in results {
        match artifact.family {
            ArtifactFamily::Executable => counters.executable_results += 1,
            ArtifactFamily::Archive => counters.archive_results += 1,
            ArtifactFamily::Script => counters.script_results += 1,
            _ => {}
        }
        if artifact.origin_type == rss_core::OriginType::UnallocatedCarved {
            counters.carved_results += 1;
        }
        if matches!(
            artifact.recoverability,
            rss_core::Recoverability::Good | rss_core::Recoverability::Partial
        ) {
            counters.recoverable_results += 1;
        }
        if artifact.origin_type == rss_core::OriginType::PartialFragment
            || artifact.recoverability == rss_core::Recoverability::Partial
        {
            counters.partial_results += 1;
        }
    }
    counters
}

fn should_run_fast_carve(source: &ScanSource, options: &ScanOptions) -> bool {
    source.filesystem == FileSystemKind::Ntfs
        && options.carve_budget_bytes.unwrap_or(FAST_MODE_CARVE_BUDGET) > 0
}

fn adaptive_fast_carve_budget(
    baseline_budget: u64,
    candidates_surfaced: u64,
    named_hits: u64,
    recoverable_hits: u64,
) -> u64 {
    if baseline_budget == 0 {
        return 0;
    }

    let strong_named = named_hits >= 5_000
        && recoverable_hits.saturating_mul(100) >= named_hits.saturating_mul(60);
    let sparse_named = candidates_surfaced >= 1_000
        && named_hits.saturating_mul(100) < candidates_surfaced.saturating_mul(15);

    if strong_named {
        baseline_budget.saturating_mul(3) / 4
    } else if sparse_named {
        baseline_budget
    } else {
        baseline_budget.saturating_mul(7) / 8
    }
}

fn filter_scan_results(results: &mut Vec<ArtifactRecord>, include_low_confidence: bool) {
    if include_low_confidence {
        return;
    }
    results.retain(|artifact| should_keep_visible_result(artifact, include_low_confidence));
}

fn filtered_results_batch(
    results: &[ArtifactRecord],
    include_low_confidence: bool,
) -> Vec<ArtifactRecord> {
    results
        .iter()
        .filter(|artifact| should_keep_visible_result(artifact, include_low_confidence))
        .cloned()
        .collect()
}

fn should_keep_visible_result(artifact: &ArtifactRecord, include_low_confidence: bool) -> bool {
    include_low_confidence
        || artifact.confidence != Confidence::Low
        || keep_high_value_low_confidence(artifact)
}

fn keep_high_value_low_confidence(artifact: &ArtifactRecord) -> bool {
    let named = artifact.original_path.is_some()
        || !matches!(artifact.name_source, rss_core::NameSourceKind::Generated);
    let executable_family = matches!(artifact.family, ArtifactFamily::Executable);
    let high_value_extension = artifact
        .extension
        .as_deref()
        .is_some_and(is_high_value_deleted_extension);
    let meaningful_named_extension = artifact
        .extension
        .as_deref()
        .is_some_and(is_meaningful_deleted_extension);

    artifact.deleted_entry
        && artifact.filesystem_record.is_some()
        && named
        && (artifact.original_path.is_some()
            || executable_family
            || high_value_extension
            || meaningful_named_extension)
}

fn is_high_value_deleted_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "dll"
            | "exe"
            | "sys"
            | "ocx"
            | "scr"
            | "cpl"
            | "mui"
            | "cat"
            | "zip"
            | "jar"
            | "apk"
            | "cab"
            | "7z"
            | "rar"
            | "pdf"
            | "sqlite"
            | "db"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "webp"
            | "txt"
            | "log"
            | "json"
            | "xml"
            | "yaml"
            | "yml"
            | "ini"
            | "cfg"
            | "ps1"
            | "bat"
            | "cmd"
            | "reg"
            | "lnk"
    )
}

fn is_meaningful_deleted_extension(extension: &str) -> bool {
    let normalized = extension.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if matches!(
        normalized.as_str(),
        "tmp" | "dat" | "bin" | "chk" | "bk" | "old"
    ) {
        return false;
    }

    normalized.len() <= 10
}

fn count_recoverable_hits(results: &[ArtifactRecord]) -> u64 {
    results
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.recoverability,
                rss_core::Recoverability::Good | rss_core::Recoverability::Partial
            )
        })
        .count() as u64
}

fn count_validated_hits(results: &[ArtifactRecord]) -> u64 {
    results
        .iter()
        .filter(|artifact| {
            matches!(
                artifact.artifact_class,
                ArtifactClass::ValidatedHit
                    | ArtifactClass::Recoverable
                    | ArtifactClass::CarvedHit
                    | ArtifactClass::FragmentCandidate
            )
        })
        .count() as u64
}

fn count_named_hits(results: &[ArtifactRecord]) -> u64 {
    results
        .iter()
        .filter(|artifact| {
            artifact.original_path.is_some()
                || !matches!(artifact.name_source, rss_core::NameSourceKind::Generated)
        })
        .count() as u64
}

fn count_carved_hits(results: &[ArtifactRecord]) -> u64 {
    results
        .iter()
        .filter(|artifact| artifact.origin_type == OriginType::UnallocatedCarved)
        .count() as u64
}

fn count_fragment_hits(results: &[ArtifactRecord]) -> u64 {
    results
        .iter()
        .filter(|artifact| {
            artifact.is_fragment || artifact.origin_type == OriginType::PartialFragment
        })
        .count() as u64
}

fn note_stage_completion(
    timings: &mut std::collections::BTreeMap<String, u64>,
    stage_name: &str,
    stage_started: &mut Instant,
) {
    timings.insert(
        stage_name.to_string(),
        stage_started.elapsed().as_millis() as u64,
    );
    *stage_started = Instant::now();
}

fn merge_results<I>(results: &mut Vec<ArtifactRecord>, incoming: I)
where
    I: IntoIterator<Item = ArtifactRecord>,
{
    let mut seen_records: HashSet<u64> = results
        .iter()
        .filter_map(|artifact| artifact.filesystem_record)
        .collect();
    let mut seen_paths: HashSet<String> = results
        .iter()
        .filter_map(|artifact| {
            artifact
                .original_path
                .as_ref()
                .map(|path| normalize_path_key(path, artifact.size))
        })
        .collect();
    let mut seen_offsets: HashSet<(u64, rss_core::ArtifactKind, u64)> = results
        .iter()
        .filter_map(|artifact| {
            artifact
                .raw_offset
                .map(|offset| (offset, artifact.kind, artifact.size))
        })
        .collect();

    for artifact in incoming {
        if let Some(record) = artifact.filesystem_record
            && !seen_records.insert(record)
        {
            continue;
        }

        if let Some(path_key) = artifact
            .original_path
            .as_ref()
            .map(|path| normalize_path_key(path, artifact.size))
            && !seen_paths.insert(path_key)
        {
            continue;
        }

        if let Some(offset) = artifact.raw_offset {
            let key = (offset, artifact.kind, artifact.size);
            if !seen_offsets.insert(key) {
                continue;
            }
        }

        results.push(artifact);
    }
}

fn normalize_path_key(path: &str, size: u64) -> String {
    format!("{}:{size}", path.replace('/', "\\").to_ascii_lowercase())
}
