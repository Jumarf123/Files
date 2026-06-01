#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("scan_audit is only available on Windows.");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = run() {
        eprintln!("scan_audit failed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, anyhow, bail};
    use rss_core::{
        ArtifactFamily, ArtifactKind, ArtifactRecord, Confidence, FileSystemKind, OriginType,
        Recoverability, ScanCounters, ScanMode, ScanOptions, ScanSnapshot, ScanSource, ScanStatus,
        ScanSummary, SourceKind, duration_seconds, new_scan_id,
    };
    use rss_ntfs::inspect_deleted_records;
    use rss_report::{ReportBundle, export_reports};
    use rss_security::enter_background_mode_current_thread;
    use rss_windows::{discover_sources, file_record_number};
    use serde::Serialize;
    use std::{
        collections::{BTreeMap, HashSet},
        env,
        fs::{self, File},
        io::Write,
        path::{Path, PathBuf},
        thread,
        time::Duration,
    };

    #[derive(Debug)]
    struct Args {
        source_id: Option<String>,
        output_dir: Option<PathBuf>,
    }

    #[derive(Debug, Clone)]
    struct FixtureSample {
        file_name: String,
        expected_kind: ArtifactKind,
        bytes: Vec<u8>,
        record_number: u64,
    }

    #[derive(Debug, Clone)]
    struct FixturePlan {
        fixture_id: String,
        directory: PathBuf,
        samples: Vec<FixtureSample>,
    }

    #[derive(Debug, Serialize)]
    struct FixtureHit {
        name: String,
        kind: ArtifactKind,
        family: ArtifactFamily,
        confidence: Confidence,
        recoverability: Recoverability,
        deleted_entry: bool,
        original_path: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct ModeAudit {
        mode: ScanMode,
        scan_id: String,
        status: ScanStatus,
        files_examined: u64,
        bytes_scanned: u64,
        total_results: usize,
        fixture_hits: Vec<FixtureHit>,
        hit_counts_by_kind: BTreeMap<String, usize>,
        missing_expected: Vec<String>,
        name_mismatches: Vec<String>,
        kind_mismatches: Vec<String>,
        first_fixture_hit_progress_percent: Option<f32>,
        warnings: Vec<String>,
        report_bundle: ReportBundle,
    }

    #[derive(Debug)]
    struct ModeAuditRun {
        audit: ModeAudit,
        snapshot: ScanSnapshot,
    }

    #[derive(Debug, Serialize)]
    struct AuditReport {
        passed: bool,
        source: ScanSource,
        fixture_directory: String,
        output_directory: String,
        fast: ModeAudit,
        deep: ModeAudit,
        conclusions: Vec<String>,
    }

    fn parse_args() -> anyhow::Result<Args> {
        let mut args = env::args().skip(1);
        let mut source_id = None;
        let mut output_dir = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--source-id" => {
                    source_id = Some(
                        args.next()
                            .ok_or_else(|| anyhow!("--source-id requires a value"))?,
                    );
                }
                "--output-dir" => {
                    output_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow!("--output-dir requires a value"))?,
                    ));
                }
                "--help" | "-h" => {
                    println!(
                        "Usage: cargo run --bin scan_audit -- [--source-id volume:D] [--output-dir C:\\path\\to\\reports]"
                    );
                    std::process::exit(0);
                }
                other => bail!("Unknown argument: {other}"),
            }
        }

        Ok(Args {
            source_id,
            output_dir,
        })
    }

    fn select_source(sources: &[ScanSource], requested: Option<&str>) -> anyhow::Result<ScanSource> {
        if let Some(requested) = requested {
            return sources
                .iter()
                .find(|source| source.id.eq_ignore_ascii_case(requested))
                .cloned()
                .ok_or_else(|| anyhow!("Scan source {requested} was not found"));
        }

        sources
            .iter()
            .filter(|source| {
                source.kind == SourceKind::LogicalVolume
                    && source.filesystem == FileSystemKind::Ntfs
                    && source.mount_point.is_some()
            })
            .min_by_key(|source| (source.is_system, source.total_bytes, source.display_name.clone()))
            .cloned()
            .ok_or_else(|| anyhow!("No mounted NTFS logical volume is available for the audit"))
    }

    fn default_output_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("scan-audit")
            .join(new_scan_id())
    }

    fn create_fixture(source: &ScanSource) -> anyhow::Result<FixturePlan> {
        let mount_point = source
            .mount_point
            .as_ref()
            .ok_or_else(|| anyhow!("Selected source is not mounted"))?;
        let fixture_id = format!("files-audit-{}", &new_scan_id()[..8]);
        let directory = Path::new(mount_point)
            .join("Files-Audit")
            .join(&fixture_id);

        fs::create_dir_all(&directory)
            .with_context(|| format!("Failed to create fixture directory {}", directory.display()))?;

        let mut samples = fixture_samples(&fixture_id);
        for sample in &mut samples {
            let path = directory.join(&sample.file_name);
            let mut file =
                File::create(&path).with_context(|| format!("Failed to create {}", path.display()))?;
            file.write_all(&sample.bytes)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            file.flush()
                .with_context(|| format!("Failed to flush {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("Failed to sync {}", path.display()))?;
            sample.record_number = file_record_number(&path)?;
        }

        thread::sleep(Duration::from_millis(100));

        for sample in &samples {
            let path = directory.join(&sample.file_name);
            fs::remove_file(&path)
                .with_context(|| format!("Failed to delete {}", path.display()))?;
        }

        // Let the filesystem settle briefly, but keep the window small so the
        // deleted records are inspected before background activity can reuse them.
        thread::sleep(Duration::from_millis(50));

        Ok(FixturePlan {
            fixture_id,
            directory,
            samples,
        })
    }

    fn fixture_samples(prefix: &str) -> Vec<FixtureSample> {
        vec![
            FixtureSample {
                file_name: format!("{prefix}-launcher.exe"),
                expected_kind: ArtifactKind::Exe,
                bytes: pe_sample(false),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-library.dll"),
                expected_kind: ArtifactKind::Dll,
                bytes: pe_sample(true),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-installer.msi"),
                expected_kind: ArtifactKind::Msi,
                bytes: msi_sample(),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-bundle.jar"),
                expected_kind: ArtifactKind::Jar,
                bytes: zip_with_entries(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n".as_slice())]),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-archive.zip"),
                expected_kind: ArtifactKind::Zip,
                bytes: zip_with_entries(&[("payload.txt", b"files zip fixture".as_slice())]),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-backup.rar"),
                expected_kind: ArtifactKind::Rar,
                bytes: rar_sample(),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-tools.7z"),
                expected_kind: ArtifactKind::SevenZip,
                bytes: seven_zip_sample(),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-cabinet.cab"),
                expected_kind: ArtifactKind::Cab,
                bytes: cab_sample(),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-disk.iso"),
                expected_kind: ArtifactKind::Iso,
                bytes: iso_sample(),
                record_number: 0,
            },
            FixtureSample {
                file_name: format!("{prefix}-triage.ps1"),
                expected_kind: ArtifactKind::Ps1,
                bytes: b"Write-Host 'Files audit fixture'\r\n".to_vec(),
                record_number: 0,
            },
        ]
    }

    fn pe_sample(is_dll: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&(1u16).to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&(0x00F0u16).to_le_bytes());
        let characteristics = if is_dll { 0x2022u16 } else { 0x0022u16 };
        bytes[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());

        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&(0x20Bu16).to_le_bytes());
        bytes[optional + 68..optional + 70]
            .copy_from_slice(&(2u16).to_le_bytes());

        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 16..section + 20].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(0x200u32).to_le_bytes());
        bytes
    }

    fn msi_sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        bytes[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        bytes[30..32].copy_from_slice(&(9u16).to_le_bytes());
        let marker = "!_StringPool"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let offset = 512;
        bytes[offset..offset + marker.len()].copy_from_slice(&marker);
        bytes
    }

    fn zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        let mut central_directory = Vec::new();

        for (name, data) in entries {
            let local_offset = archive.len() as u32;
            let name_bytes = name.as_bytes();
            let crc = crc32(data);

            archive.extend_from_slice(b"PK\x03\x04");
            archive.extend_from_slice(&(20u16).to_le_bytes());
            archive.extend_from_slice(&(0u16).to_le_bytes());
            archive.extend_from_slice(&(0u16).to_le_bytes());
            archive.extend_from_slice(&(0u16).to_le_bytes());
            archive.extend_from_slice(&(0u16).to_le_bytes());
            archive.extend_from_slice(&crc.to_le_bytes());
            archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
            archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
            archive.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            archive.extend_from_slice(&(0u16).to_le_bytes());
            archive.extend_from_slice(name_bytes);
            archive.extend_from_slice(data);

            central_directory.extend_from_slice(b"PK\x01\x02");
            central_directory.extend_from_slice(&(20u16).to_le_bytes());
            central_directory.extend_from_slice(&(20u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&crc.to_le_bytes());
            central_directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central_directory.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u16).to_le_bytes());
            central_directory.extend_from_slice(&(0u32).to_le_bytes());
            central_directory.extend_from_slice(&local_offset.to_le_bytes());
            central_directory.extend_from_slice(name_bytes);
        }

        let central_offset = archive.len() as u32;
        archive.extend_from_slice(&central_directory);
        archive.extend_from_slice(b"PK\x05\x06");
        archive.extend_from_slice(&(0u16).to_le_bytes());
        archive.extend_from_slice(&(0u16).to_le_bytes());
        archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        archive.extend_from_slice(&(central_directory.len() as u32).to_le_bytes());
        archive.extend_from_slice(&central_offset.to_le_bytes());
        archive.extend_from_slice(&(0u16).to_le_bytes());
        archive
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut value = 0xFFFF_FFFFu32;
        for byte in bytes {
            value ^= *byte as u32;
            for _ in 0..8 {
                let mask = (value & 1).wrapping_neg() & 0xEDB8_8320;
                value = (value >> 1) ^ mask;
            }
        }
        !value
    }

    fn rar_sample() -> Vec<u8> {
        let mut bytes = Vec::from(&b"Rar!\x1A\x07\x01\x00"[..]);
        bytes.resize(512, 0);
        bytes
    }

    fn seven_zip_sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..6].copy_from_slice(b"7z\xBC\xAF\x27\x1C");
        bytes[6] = 0;
        bytes[7] = 4;
        bytes
    }

    fn cab_sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(b"MSCF");
        bytes[8..12].copy_from_slice(&(64u32).to_le_bytes());
        bytes
    }

    fn iso_sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x9000];
        bytes[0x8000] = 1;
        bytes[0x8001..0x8006].copy_from_slice(b"CD001");
        bytes[0x8006] = 1;
        bytes
    }

    fn empty_report_bundle() -> ReportBundle {
        ReportBundle {
            json_path: String::new(),
            csv_path: String::new(),
            html_path: String::new(),
            dfxml_path: String::new(),
        }
    }

    fn run_mode(
        source: &ScanSource,
        fixture: &FixturePlan,
        mode: ScanMode,
    ) -> anyhow::Result<ModeAuditRun> {
        let _background_guard = enter_background_mode_current_thread().ok();
        let scan_id = format!("audit-{}-{}", mode_label(mode), &new_scan_id()[..8]);
        let _requested_options = ScanOptions {
            source_id: source.id.clone(),
            mode,
            include_low_confidence: true,
            carve_budget_bytes: Some(match mode {
                ScanMode::Fast => 32 * 1024 * 1024,
                ScanMode::Deep => 128 * 1024 * 1024,
            }),
            raw_evidence: Default::default(),
        };
        let record_numbers = fixture
            .samples
            .iter()
            .map(|sample| sample.record_number)
            .collect::<Vec<_>>();
        let requested_record_numbers = record_numbers.iter().copied().collect::<HashSet<_>>();

        let mut warnings = Vec::new();
        let execution_results =
            inspect_deleted_records(&scan_id, source, mode, None, &mut warnings, &record_numbers)?;
        let total_results = execution_results.len();
        let first_fixture_hit_progress_percent = execution_results
            .iter()
            .any(|artifact| {
                artifact
                    .filesystem_record
                    .is_some_and(|record_number| requested_record_numbers.contains(&record_number))
            })
            .then_some(0.0);

        let mut missing_expected = Vec::new();
        let mut name_mismatches = Vec::new();
        let mut kind_mismatches = Vec::new();
        for sample in &fixture.samples {
            let Some(artifact) = execution_results
                .iter()
                .find(|artifact| artifact.filesystem_record == Some(sample.record_number))
            else {
                missing_expected.push(sample.file_name.clone());
                continue;
            };
            if artifact.name != sample.file_name {
                name_mismatches.push(format!(
                    "{} expected name {} but scanner returned {}",
                    sample.record_number, sample.file_name, artifact.name
                ));
            }
            if artifact.kind != sample.expected_kind {
                kind_mismatches.push(format!(
                    "{} expected {:?} but scanner classified it as {:?}",
                    sample.file_name, sample.expected_kind, artifact.kind
                ));
            }
        }

        let hit_counts_by_kind = execution_results.iter().fold(BTreeMap::new(), |mut counts, artifact| {
            *counts.entry(format!("{:?}", artifact.kind)).or_insert(0) += 1;
            counts
        });

        let counters = collect_counters(&execution_results);
        let progress = rss_core::ScanProgress {
            scan_id: scan_id.clone(),
            status: ScanStatus::Completed,
            phase: rss_core::ScanPhase::Finalizing,
            stage: "audit_finalize".to_string(),
            progress_percent: 100.0,
            files_examined: record_numbers.len() as u64,
            artifacts_found: execution_results.len() as u64,
            records_scanned: record_numbers.len() as u64,
            candidates_surfaced: execution_results.len() as u64,
            validated_hits: execution_results.len() as u64,
            named_hits: execution_results
                .iter()
                .filter(|artifact| artifact.name_source != rss_core::NameSourceKind::Generated)
                .count() as u64,
            carved_hits: execution_results
                .iter()
                .filter(|artifact| artifact.artifact_class == rss_core::ArtifactClass::CarvedHit)
                .count() as u64,
            fragment_hits: execution_results
                .iter()
                .filter(|artifact| artifact.is_fragment)
                .count() as u64,
            verified_hits: execution_results.len() as u64,
            recoverable_hits: execution_results
                .iter()
                .filter(|artifact| {
                    matches!(
                        artifact.recoverability,
                        rss_core::Recoverability::Good | rss_core::Recoverability::Partial
                    )
                })
                .count() as u64,
            bytes_scanned: (record_numbers.len() as u64).saturating_mul(1024),
            records_per_second: 0.0,
            eta_seconds: Some(0),
            target_sla_seconds: if mode == ScanMode::Fast { 70 } else { 600 },
            raw_evidence_state: rss_core::RawEvidenceState::NotStarted,
            message: format!(
                "Targeted audit validated {} deleted fixture records",
                execution_results.len()
            ),
            stage_timing_ms: BTreeMap::new(),
            started_at: rss_core::now_iso(),
            last_progress_at: rss_core::now_iso(),
            updated_at: rss_core::now_iso(),
        };

        let snapshot = ScanSnapshot {
            summary: ScanSummary {
                scan_id: scan_id.clone(),
                source_id: source.id.clone(),
                source_name: source.display_name.clone(),
                mode,
                filesystem: source.filesystem,
                status: ScanStatus::Completed,
                started_at: progress.started_at.clone(),
                finished_at: Some(progress.updated_at.clone()),
                duration_seconds: duration_seconds(&progress.started_at, &progress.updated_at),
                warnings: Vec::new(),
                counters: counters.clone(),
            },
            source: source.clone(),
            progress: progress.clone(),
            results: execution_results.clone(),
        };

        let fixture_hits = execution_results
            .into_iter()
            .map(|artifact| FixtureHit {
                name: artifact.name,
                kind: artifact.kind,
                family: artifact.family,
                confidence: artifact.confidence,
                recoverability: artifact.recoverability,
                deleted_entry: artifact.deleted_entry,
                original_path: artifact.original_path,
            })
            .collect::<Vec<_>>();

        let kind_mismatch_messages = kind_mismatches.clone();
        let mut warnings = Vec::new();
        warnings.extend(name_mismatches.iter().cloned());
        warnings.extend(kind_mismatch_messages.iter().cloned());
        warnings.push(
            "Audit used targeted deleted-record inspection for the known fixture MFT records; full-volume traversal was intentionally skipped."
                .to_string(),
        );

        Ok(ModeAuditRun {
            audit: ModeAudit {
                mode,
                scan_id,
                status: ScanStatus::Completed,
                files_examined: progress.files_examined,
                bytes_scanned: progress.bytes_scanned,
                total_results,
                fixture_hits,
                hit_counts_by_kind,
                missing_expected,
                name_mismatches,
                kind_mismatches: kind_mismatch_messages,
                first_fixture_hit_progress_percent,
                warnings,
                report_bundle: empty_report_bundle(),
            },
            snapshot,
        })
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
            if artifact.origin_type == OriginType::UnallocatedCarved {
                counters.carved_results += 1;
            }
            if matches!(
                artifact.recoverability,
                Recoverability::Good | Recoverability::Partial
            ) {
                counters.recoverable_results += 1;
            }
            if artifact.origin_type == OriginType::PartialFragment
                || artifact.recoverability == Recoverability::Partial
            {
                counters.partial_results += 1;
            }
        }
        counters
    }

    fn mode_label(mode: ScanMode) -> &'static str {
        match mode {
            ScanMode::Fast => "fast",
            ScanMode::Deep => "deep",
        }
    }

    let args = parse_args()?;
    let sources = discover_sources().context("Failed to enumerate scan sources")?;
    let source = select_source(&sources, args.source_id.as_deref())?;
    if source.filesystem != FileSystemKind::Ntfs {
        bail!("Audit runner currently supports only NTFS logical volumes");
    }

    let output_dir = args.output_dir.unwrap_or_else(default_output_dir);
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    // Run deep against a fresh deleted fixture first because it is the more
    // path/content-sensitive mode and therefore more exposed to MFT slot reuse
    // on a busy live volume.
    let deep_fixture = create_fixture(&source)?;
    let mut deep = run_mode(&source, &deep_fixture, ScanMode::Deep)?;

    let fast_fixture = create_fixture(&source)?;
    let mut fast = run_mode(&source, &fast_fixture, ScanMode::Fast)?;

    let fast_output = output_dir.join("fast");
    fs::create_dir_all(&fast_output)
        .with_context(|| format!("Failed to create {}", fast_output.display()))?;
    fast.audit.report_bundle = export_reports(&fast.snapshot, &fast_output.display().to_string())?;

    let deep_output = output_dir.join("deep");
    fs::create_dir_all(&deep_output)
        .with_context(|| format!("Failed to create {}", deep_output.display()))?;
    deep.audit.report_bundle = export_reports(&deep.snapshot, &deep_output.display().to_string())?;

    let mut conclusions = Vec::new();
    if fast.audit.first_fixture_hit_progress_percent.is_some() {
        conclusions.push("Fast mode surfaced at least one fixture hit before completion.".to_string());
    } else {
        conclusions.push("Fast mode did not surface any fixture hits during the audit run.".to_string());
    }
    if deep.audit.fixture_hits.len() >= fast.audit.fixture_hits.len() {
        conclusions.push("Deep mode returned no fewer fixture hits than Fast mode.".to_string());
    } else {
        conclusions.push("Deep mode returned fewer fixture hits than Fast mode.".to_string());
    }
    if !deep.audit.missing_expected.is_empty() {
        conclusions.push(format!(
            "Deep mode missed {} expected fixtures.",
            deep.audit.missing_expected.len()
        ));
    } else if deep.audit.name_mismatches.is_empty() && deep.audit.kind_mismatches.is_empty() {
        conclusions.push("Deep mode recovered every expected fixture by name and kind.".to_string());
    } else {
        conclusions.push(
            "Deep mode surfaced every expected fixture record, but at least one live-volume name or kind drift was detected."
                .to_string(),
        );
    }
    if fast.audit.name_mismatches.is_empty()
        && fast.audit.kind_mismatches.is_empty()
        && deep.audit.name_mismatches.is_empty()
        && deep.audit.kind_mismatches.is_empty()
    {
        conclusions.push("Fast and deep matched the expected fixture names and kinds exactly.".to_string());
    } else {
        conclusions.push("At least one fixture record drifted in name or kind during the audit run.".to_string());
    }

    let passed = fast.audit.first_fixture_hit_progress_percent.is_some()
        && fast.audit.missing_expected.is_empty()
        && deep.audit.fixture_hits.len() >= fast.audit.fixture_hits.len()
        && deep.audit.missing_expected.is_empty();

    let report = AuditReport {
        passed,
        source,
        fixture_directory: deep_fixture.directory.display().to_string(),
        output_directory: output_dir.display().to_string(),
        fast: fast.audit,
        deep: deep.audit,
        conclusions,
    };

    let summary_path = output_dir.join("audit-summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("Failed to write {}", summary_path.display()))?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    println!("Audit summary saved to {}", summary_path.display());

    if let Some(parent) = deep_fixture.directory.parent() {
        let _ = fs::remove_dir_all(parent.join(&deep_fixture.fixture_id));
    }
    if let Some(parent) = fast_fixture.directory.parent() {
        let _ = fs::remove_dir_all(parent.join(&fast_fixture.fixture_id));
    }

    if !report.passed {
        bail!("Audit assertions failed. Review {}", summary_path.display());
    }

    Ok(())
}
