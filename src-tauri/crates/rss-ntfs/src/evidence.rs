use anyhow::{Context, Result};
use ntfs_reader::{
    api::{ROOT_RECORD, ntfs_to_unix_time},
    attribute::DataRun,
    mft::Mft,
};
use rss_core::{
    ArtifactClass, ArtifactRecord, Confidence, DeletedTimeConfidence, DeletedTimeSource,
    NameSourceKind, PathConfidence, PathEvidence, PathEvidenceSource, PlacementKind, RecoveryPlan,
    ScanSource, infer_artifact_kind,
};
use rss_windows::RawReader;
use std::{
    collections::{HashMap, HashSet},
    os::windows::io::AsRawHandle,
    time::Instant,
};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1,
            USN_JOURNAL_DATA_V2, USN_REASON_CLOSE, USN_REASON_FILE_DELETE,
            USN_REASON_HARD_LINK_CHANGE, USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME,
        },
    },
};

const NTFS_ATTR_INDEX_ROOT: u32 = 0x90;
const NTFS_ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const NTFS_ATTR_DATA: u32 = 0x80;
const NTFS_ATTR_FILE_NAME: u32 = 0x30;
const INDEX_ROOT_HEADER_LEN: usize = 0x10;
const INDEX_NODE_HEADER_LEN: usize = 0x10;
const INDEX_ENTRY_HEADER_LEN: usize = 0x10;
const INDEX_ENTRY_NODE: u16 = 0x0001;
const INDEX_ENTRY_END: u16 = 0x0002;
const INDX_HEADER_LEN: usize = 0x18;
const SECTOR_SIZE: usize = 512;
const DEFAULT_INDEX_BUFFER_SIZE: usize = 4096;
const RAW_READ_WINDOW: u64 = 16 * 1024 * 1024;
const USN_READ_BUFFER_SIZE: usize = 1024 * 1024;
const USN_RAW_CARRY: usize = 4096;

#[derive(Debug, Clone)]
struct DirectoryPath {
    path: String,
    confidence: PathConfidence,
}

#[derive(Debug, Clone)]
struct I30Entry {
    file_reference: u64,
    parent_reference: u64,
    name: String,
    path: Option<String>,
    path_confidence: PathConfidence,
    size: u64,
    from_slack: bool,
    created_at: Option<String>,
    modified_at: Option<String>,
    last_metadata_change_at: Option<String>,
}

#[derive(Debug, Clone)]
struct UsnEvidence {
    file_reference: u64,
    parent_reference: u64,
    name: String,
    reason: u32,
    timestamp: Option<String>,
    path: Option<String>,
}

struct EvidenceMerger<'a> {
    scan_id: &'a str,
    source: &'a ScanSource,
    mft: &'a Mft,
    results: &'a mut Vec<ArtifactRecord>,
    by_reference: HashMap<u64, usize>,
    by_record_number: HashMap<u64, Vec<usize>>,
    created_keys: HashSet<String>,
}

impl<'a> EvidenceMerger<'a> {
    fn new(
        scan_id: &'a str,
        source: &'a ScanSource,
        mft: &'a Mft,
        results: &'a mut Vec<ArtifactRecord>,
    ) -> Self {
        let mut merger = Self {
            scan_id,
            source,
            mft,
            results,
            by_reference: HashMap::new(),
            by_record_number: HashMap::new(),
            created_keys: HashSet::new(),
        };
        merger.rebuild_indexes();
        merger
    }

    fn rebuild_indexes(&mut self) {
        self.by_reference.clear();
        self.by_record_number.clear();
        self.created_keys.clear();

        for (index, artifact) in self.results.iter().enumerate() {
            if let Some(record_number) = artifact.filesystem_record {
                self.by_record_number
                    .entry(record_number)
                    .or_default()
                    .push(index);
                if let Some(file) = self.mft.get_record(record_number) {
                    self.by_reference.insert(file.reference_number(), index);
                }
            }
            self.created_keys.insert(artifact_key(artifact));
        }
    }

    fn apply_i30(&mut self, entry: I30Entry) {
        let record_number = ntfs_record_number(entry.file_reference);
        if let Some(index) = self
            .by_reference
            .get(&entry.file_reference)
            .copied()
            .or_else(|| self.by_record_number.get(&record_number)?.first().copied())
        {
            let artifact = &mut self.results[index];
            let confidence = if entry.from_slack {
                PathConfidence::Partial
            } else {
                entry.path_confidence
            };
            apply_name_hint(artifact, &entry.name);
            if artifact.parent_reference.is_none() && entry.parent_reference != 0 {
                artifact.parent_reference = Some(entry.parent_reference);
            }
            if artifact.probable_path.is_none()
                && artifact.original_path.is_none()
                && let Some(path) = entry.path.clone()
            {
                artifact.probable_path = Some(path.clone());
                artifact.placement_kind = PlacementKind::BrokenParentChain;
                artifact.path_confidence = confidence;
            }
            apply_i30_timestamps(artifact, &entry);
            push_path_evidence(
                artifact,
                PathEvidenceSource::I30,
                entry.path,
                confidence,
                if entry.from_slack {
                    "$I30 slack preserved a directory index entry for this record."
                } else {
                    "$I30 directory index preserved a filename entry for this record."
                },
            );
            artifact.artifact_class = ArtifactClass::NamedMetadataCandidate;
            return;
        }

        if !entry.from_slack || should_skip_created_i30_entry(self.mft, &entry) {
            return;
        }

        let mut artifact = ArtifactRecord::new(self.scan_id, &self.source.id, &entry.name);
        artifact.filesystem_record = Some(record_number);
        artifact.parent_reference = Some(entry.parent_reference);
        artifact.size = entry.size;
        artifact.extension = super::extension(&entry.name);
        artifact.kind = infer_artifact_kind(&entry.name, None);
        artifact.family = artifact.kind.family();
        artifact.priority_score = artifact.kind.priority_score();
        artifact.name_source = NameSourceKind::Reconstructed;
        artifact.confidence = Confidence::Low;
        artifact.recoverability = rss_core::Recoverability::Unknown;
        artifact.recovery_plan = RecoveryPlan::Unrecoverable {
            reason: "Recovered only from NTFS $I30 directory index evidence".to_string(),
        };
        artifact.created_at = entry.created_at.clone();
        artifact.modified_at = entry.modified_at.clone();
        artifact.last_metadata_change_at = entry.last_metadata_change_at.clone();
        if let Some(path) = entry.path.clone() {
            artifact.probable_path = Some(path);
            artifact.placement_kind = PlacementKind::BrokenParentChain;
            artifact.path_confidence = PathConfidence::Partial;
        }
        apply_i30_timestamps(&mut artifact, &entry);
        push_path_evidence(
            &mut artifact,
            PathEvidenceSource::I30,
            entry.path,
            PathConfidence::Partial,
            "$I30 slack preserved metadata for a deleted or reused MFT record.",
        );
        artifact.notes.push(
            "Created from validated NTFS $I30 slack; content recovery depends on surviving MFT/data runs."
                .to_string(),
        );

        let key = artifact_key(&artifact);
        if self.created_keys.insert(key) {
            self.results.push(artifact);
            self.rebuild_indexes();
        }
    }

    fn apply_usn(&mut self, evidence: UsnEvidence) {
        let record_number = ntfs_record_number(evidence.file_reference);
        if let Some(index) = self
            .by_reference
            .get(&evidence.file_reference)
            .copied()
            .or_else(|| self.by_record_number.get(&record_number)?.first().copied())
        {
            let artifact = &mut self.results[index];
            apply_name_hint(artifact, &evidence.name);
            if artifact.parent_reference.is_none() && evidence.parent_reference != 0 {
                artifact.parent_reference = Some(evidence.parent_reference);
            }
            let path_confidence = if self.by_reference.contains_key(&evidence.file_reference) {
                PathConfidence::Reconstructed
            } else {
                PathConfidence::Partial
            };
            if artifact.original_path.is_none() {
                if path_confidence == PathConfidence::Reconstructed
                    && evidence.path.is_some()
                    && artifact.parent_reference == Some(evidence.parent_reference)
                {
                    artifact.original_path = evidence.path.clone();
                    artifact.probable_path = None;
                    artifact.placement_kind = PlacementKind::OriginalPath;
                    artifact.path_confidence = PathConfidence::Reconstructed;
                    artifact.confidence = Confidence::High;
                } else if artifact.probable_path.is_none() {
                    artifact.probable_path = evidence.path.clone();
                    if artifact.probable_path.is_some() {
                        artifact.placement_kind = PlacementKind::BrokenParentChain;
                        artifact.path_confidence = PathConfidence::Partial;
                    }
                }
            }
            apply_usn_time(artifact, &evidence);
            push_path_evidence(
                artifact,
                PathEvidenceSource::UsnJournal,
                evidence.path,
                path_confidence,
                "USN Journal preserved a delete/rename event for this file reference.",
            );
            return;
        }

        if evidence.reason & USN_REASON_FILE_DELETE == 0 || evidence.name.is_empty() {
            return;
        }

        let mut artifact = ArtifactRecord::new(self.scan_id, &self.source.id, &evidence.name);
        artifact.filesystem_record = Some(record_number);
        artifact.parent_reference = Some(evidence.parent_reference);
        artifact.extension = super::extension(&evidence.name);
        artifact.kind = infer_artifact_kind(&evidence.name, None);
        artifact.family = artifact.kind.family();
        artifact.priority_score = artifact.kind.priority_score();
        artifact.name_source = NameSourceKind::Reconstructed;
        artifact.confidence = Confidence::Medium;
        artifact.recovery_plan = RecoveryPlan::Unrecoverable {
            reason: "Recovered only from NTFS USN Journal delete evidence".to_string(),
        };
        if let Some(path) = evidence.path.clone() {
            artifact.probable_path = Some(path);
            artifact.placement_kind = PlacementKind::BrokenParentChain;
            artifact.path_confidence = PathConfidence::Partial;
        }
        apply_usn_time(&mut artifact, &evidence);
        push_path_evidence(
            &mut artifact,
            PathEvidenceSource::UsnJournal,
            evidence.path,
            PathConfidence::Partial,
            "USN Journal recorded deletion metadata for a file not recoverable from MFT alone.",
        );
        artifact.notes.push(
            "Created from USN Journal metadata; content recovery requires surviving MFT/data evidence."
                .to_string(),
        );

        let key = artifact_key(&artifact);
        if self.created_keys.insert(key) {
            self.results.push(artifact);
            self.rebuild_indexes();
        }
    }
}

pub(crate) fn apply_raw_evidence(
    scan_id: &str,
    source: &ScanSource,
    mft: &Mft,
    results: &mut Vec<ArtifactRecord>,
    warnings: &mut Vec<String>,
    config: &rss_core::RawEvidenceConfig,
) {
    let _ = apply_raw_evidence_with_progress(
        scan_id,
        source,
        mft,
        results,
        warnings,
        config,
        |_, _, _, _| true,
        || false,
    );
}

pub(crate) fn apply_raw_evidence_with_progress<P, C>(
    scan_id: &str,
    source: &ScanSource,
    mft: &Mft,
    results: &mut Vec<ArtifactRecord>,
    warnings: &mut Vec<String>,
    config: &rss_core::RawEvidenceConfig,
    mut on_progress: P,
    mut should_cancel: C,
) -> bool
where
    P: FnMut(&str, f32, u64, Option<u64>) -> bool,
    C: FnMut() -> bool,
{
    if !config.i30_enabled && !config.usn_enabled {
        return true;
    }

    let started = Instant::now();
    if should_cancel()
        || !on_progress(
            "building_directory_map",
            0.05,
            0,
            Some(mft.max_record.saturating_sub(ROOT_RECORD)),
        )
    {
        return false;
    }
    let directory_paths = build_directory_paths(source, mft, warnings);
    if should_cancel() || !on_progress("merging_evidence", 0.18, 0, None) {
        return false;
    }
    let mut merger = EvidenceMerger::new(scan_id, source, mft, results);

    if config.i30_enabled {
        let mut i30_entries = 0usize;
        if should_cancel()
            || !on_progress(
                "parsing_i30",
                0.25,
                0,
                Some(mft.max_record.saturating_sub(ROOT_RECORD)),
            )
        {
            return false;
        }
        if !collect_i30_evidence(
            source,
            mft,
            &directory_paths,
            warnings,
            |entry| {
                i30_entries += 1;
                merger.apply_i30(entry);
            },
            || should_cancel(),
        ) {
            return false;
        }
        if !on_progress("parsing_i30", 0.55, i30_entries as u64, None) {
            return false;
        }
        tracing::debug!("Parsed {i30_entries} NTFS $I30 directory evidence entries");
    }

    if config.usn_enabled {
        if should_cancel() || !on_progress("reading_usn", 0.58, 0, None) {
            return false;
        }
        let live_result = collect_live_usn_evidence(
            source,
            &directory_paths,
            warnings,
            |entry| merger.apply_usn(entry),
            || should_cancel(),
        );
        if let Err(error) = live_result {
            push_capped_warning(
                warnings,
                format!("[raw:usn:warning] USN Journal API evidence was skipped: {error}"),
            );
            if config.raw_usn_fallback
                && !should_cancel()
                && let Err(error) = collect_raw_usn_evidence(
                    source,
                    mft,
                    &directory_paths,
                    warnings,
                    |entry| merger.apply_usn(entry),
                    || should_cancel(),
                )
            {
                push_capped_warning(
                    warnings,
                    format!("[raw:usn:warning] Raw $UsnJrnl:$J fallback was skipped: {error}"),
                );
            }
        }
        if !on_progress("reading_usn", 0.82, 0, None) {
            return false;
        }
    }

    drop(merger);
    if should_cancel() || !on_progress("merging_evidence", 0.9, 0, None) {
        return false;
    }
    on_progress(
        "done",
        1.0,
        results.len() as u64,
        Some(results.len() as u64),
    );

    tracing::debug!(
        "NTFS raw evidence refinement completed in {} ms",
        started.elapsed().as_millis()
    );
    true
}

fn build_directory_paths(
    source: &ScanSource,
    mft: &Mft,
    warnings: &mut Vec<String>,
) -> HashMap<u64, DirectoryPath> {
    let mut cache = HashMap::new();
    let mut paths = HashMap::new();
    let root = source
        .mount_point
        .clone()
        .unwrap_or_else(|| source.device_path.clone());

    if let Some(root_file) = mft.get_record(ROOT_RECORD) {
        paths.insert(
            root_file.reference_number(),
            DirectoryPath {
                path: root.trim_end_matches('\\').to_string(),
                confidence: PathConfidence::Exact,
            },
        );
    }

    for record_number in ROOT_RECORD..mft.max_record {
        let Some(file) = mft.get_record(record_number) else {
            continue;
        };
        if !file.is_directory() {
            continue;
        }
        if record_number == ROOT_RECORD {
            continue;
        }
        let Some(name) = file.get_best_file_name(mft) else {
            continue;
        };
        let Some(resolution) =
            super::reconstruct_file_name_candidate_path(mft, &mut cache, &file, &name)
        else {
            continue;
        };
        if let Some(path) = super::normalize_path(
            &source.device_path,
            source.mount_point.as_deref(),
            &resolution.path,
        ) {
            paths.insert(
                file.reference_number(),
                DirectoryPath {
                    path,
                    confidence: resolution.confidence,
                },
            );
        }
    }

    if paths.len() <= 1 {
        push_capped_warning(
            warnings,
            "[raw:i30:warning] Directory path map is sparse; probable paths may remain under Unknown."
                .to_string(),
        );
    }

    paths
}

fn collect_i30_evidence<F, C>(
    source: &ScanSource,
    mft: &Mft,
    directory_paths: &HashMap<u64, DirectoryPath>,
    warnings: &mut Vec<String>,
    mut on_entry: F,
    mut should_cancel: C,
) -> bool
where
    F: FnMut(I30Entry),
    C: FnMut() -> bool,
{
    let mut raw_reader = None;
    let mut raw_open_failed = false;

    for record_number in ROOT_RECORD..mft.max_record {
        if should_cancel() {
            return false;
        }
        let Some(file) = mft.get_record(record_number) else {
            continue;
        };
        if !file.is_directory() {
            continue;
        }

        let directory_reference = file.reference_number();
        let directory_path = directory_paths.get(&directory_reference);
        let mut index_buffer_size = DEFAULT_INDEX_BUFFER_SIZE as u32;
        let mut allocation_runs: Vec<(u64, Vec<DataRun>)> = Vec::new();

        file.attributes(|attribute| match attribute.header.type_id {
            NTFS_ATTR_INDEX_ROOT => {
                if let Some(bytes) = attribute.get_resident() {
                    index_buffer_size = parse_index_root_buffer_size(bytes)
                        .unwrap_or(DEFAULT_INDEX_BUFFER_SIZE as u32)
                        .max(SECTOR_SIZE as u32);
                    for entry in
                        parse_index_root_entries(bytes, directory_reference, directory_path)
                    {
                        on_entry(entry);
                    }
                }
            }
            NTFS_ATTR_INDEX_ALLOCATION => {
                if let Ok((logical_size, runs)) = attribute.get_nonresident_data_runs(&mft.volume) {
                    allocation_runs.push((logical_size, runs));
                }
            }
            _ => {}
        });

        for (logical_size, runs) in allocation_runs {
            if raw_reader.is_none() && !raw_open_failed {
                match RawReader::open(&source.device_path) {
                    Ok(reader) => raw_reader = Some(reader),
                    Err(error) => {
                        raw_open_failed = true;
                        push_capped_warning(
                            warnings,
                            format!(
                                "[raw:i30:warning] $INDEX_ALLOCATION reads were skipped: {error}"
                            ),
                        );
                    }
                }
            }
            let Some(reader) = raw_reader.as_mut() else {
                continue;
            };
            if let Err(error) = read_index_allocation_runs(
                reader,
                &runs,
                logical_size,
                index_buffer_size as usize,
                directory_reference,
                directory_path,
                &mut on_entry,
                &mut should_cancel,
            ) {
                push_capped_warning(
                    warnings,
                    format!(
                        "[raw:i30:warning] $INDEX_ALLOCATION for directory record {record_number} was partially skipped: {error}"
                    ),
                );
            }
        }
    }
    true
}

fn collect_live_usn_evidence<F, C>(
    source: &ScanSource,
    directory_paths: &HashMap<u64, DirectoryPath>,
    _warnings: &mut Vec<String>,
    mut on_entry: F,
    mut should_cancel: C,
) -> Result<()>
where
    F: FnMut(UsnEvidence),
    C: FnMut() -> bool,
{
    let file = rss_windows::open_raw_readonly(&source.device_path)
        .with_context(|| format!("unable to open {} for USN reads", source.device_path))?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    let mut returned = 0u32;
    let mut journal = USN_JOURNAL_DATA_V2::default();

    unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut journal as *mut _ as *mut _),
            std::mem::size_of::<USN_JOURNAL_DATA_V2>() as u32,
            Some(&mut returned),
            None,
        )
    }
    .context("FSCTL_QUERY_USN_JOURNAL failed")?;

    let mut next_usn = journal.FirstUsn;
    let end_usn = journal.NextUsn;
    let reason_mask = USN_REASON_FILE_DELETE
        | USN_REASON_RENAME_OLD_NAME
        | USN_REASON_RENAME_NEW_NAME
        | USN_REASON_HARD_LINK_CHANGE
        | USN_REASON_CLOSE;
    let max_major = u16::min(3, journal.MaxSupportedMajorVersion);
    let mut buffer = vec![0u8; USN_READ_BUFFER_SIZE];
    let mut records = 0usize;

    while next_usn < end_usn {
        if should_cancel() {
            break;
        }
        let mut read = READ_USN_JOURNAL_DATA_V1 {
            StartUsn: next_usn,
            ReasonMask: reason_mask,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: 0,
            UsnJournalID: journal.UsnJournalID,
            MinMajorVersion: 2,
            MaxMajorVersion: max_major,
        };
        returned = 0;
        unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                Some(&mut read as *mut _ as *mut _),
                std::mem::size_of::<READ_USN_JOURNAL_DATA_V1>() as u32,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut returned),
                None,
            )
        }
        .with_context(|| format!("FSCTL_READ_USN_JOURNAL failed at USN {next_usn}"))?;

        if returned <= 8 {
            break;
        }

        let next = read_i64(&buffer[0..8]);
        let payload = &buffer[8..returned as usize];
        parse_usn_record_sequence(payload, |record| {
            if let Some(evidence) = usn_record_to_evidence(record, directory_paths) {
                records += 1;
                on_entry(evidence);
            }
        });

        if next <= next_usn {
            break;
        }
        next_usn = next;
    }

    tracing::debug!("Parsed {records} USN Journal evidence records");
    Ok(())
}

fn collect_raw_usn_evidence<F, C>(
    source: &ScanSource,
    mft: &Mft,
    directory_paths: &HashMap<u64, DirectoryPath>,
    warnings: &mut Vec<String>,
    mut on_entry: F,
    mut should_cancel: C,
) -> Result<()>
where
    F: FnMut(UsnEvidence),
    C: FnMut() -> bool,
{
    let Some((logical_size, runs)) = find_usn_journal_data_runs(mft) else {
        return Err(anyhow::anyhow!(
            "$Extend\\$UsnJrnl:$J data runs were not found"
        ));
    };
    let mut reader = RawReader::open(&source.device_path)?;
    let mut carry = Vec::new();
    let mut parsed = 0usize;

    for run in runs {
        if should_cancel() {
            break;
        }
        let DataRun::Data { lcn, length } = run else {
            continue;
        };
        let mut consumed = 0u64;
        while consumed < length && consumed < logical_size {
            if should_cancel() {
                break;
            }
            let to_read = (length - consumed).min(RAW_READ_WINDOW) as usize;
            let mut chunk = match reader.read_at(lcn.saturating_add(consumed), to_read) {
                Ok(bytes) => bytes,
                Err(error) => {
                    push_capped_warning(
                        warnings,
                        format!("[raw:usn:warning] Raw $J read chunk was skipped: {error}"),
                    );
                    break;
                }
            };
            if !carry.is_empty() {
                let mut merged = std::mem::take(&mut carry);
                merged.append(&mut chunk);
                chunk = merged;
            }
            scan_usn_records_in_raw_bytes(&chunk, |record| {
                if let Some(evidence) = usn_record_to_evidence(record, directory_paths) {
                    parsed += 1;
                    on_entry(evidence);
                }
            });
            let keep = chunk.len().min(USN_RAW_CARRY);
            carry = chunk[chunk.len() - keep..].to_vec();
            consumed = consumed.saturating_add(to_read as u64);
        }
    }

    tracing::debug!("Parsed {parsed} raw $UsnJrnl:$J evidence records");
    Ok(())
}

fn parse_index_root_buffer_size(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < INDEX_ROOT_HEADER_LEN {
        return None;
    }
    let indexed_type = read_u32(&bytes[0..4]);
    if indexed_type != NTFS_ATTR_FILE_NAME {
        return None;
    }
    Some(read_u32(&bytes[8..12]))
}

fn parse_index_root_entries(
    bytes: &[u8],
    directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
) -> Vec<I30Entry> {
    if bytes.len() < INDEX_ROOT_HEADER_LEN + INDEX_NODE_HEADER_LEN {
        return Vec::new();
    }
    if read_u32(&bytes[0..4]) != NTFS_ATTR_FILE_NAME {
        return Vec::new();
    }
    parse_index_node(
        bytes,
        INDEX_ROOT_HEADER_LEN,
        directory_reference,
        directory_path,
        false,
    )
}

fn read_index_allocation_runs<F, C>(
    reader: &mut RawReader,
    runs: &[DataRun],
    _logical_size: u64,
    index_buffer_size: usize,
    directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
    on_entry: &mut F,
    should_cancel: &mut C,
) -> Result<()>
where
    F: FnMut(I30Entry),
    C: FnMut() -> bool,
{
    let index_buffer_size = index_buffer_size.max(SECTOR_SIZE);
    for run in runs {
        if should_cancel() {
            break;
        }
        let DataRun::Data { lcn, length } = run else {
            continue;
        };
        let mut consumed = 0u64;
        while consumed < *length {
            if should_cancel() {
                break;
            }
            let remaining = *length - consumed;
            if remaining < index_buffer_size as u64 {
                break;
            }
            let mut to_read = remaining.min(RAW_READ_WINDOW) as usize;
            to_read -= to_read % index_buffer_size;
            if to_read == 0 {
                break;
            }
            let bytes = reader.read_at(lcn.saturating_add(consumed), to_read)?;
            for buffer in bytes.chunks(index_buffer_size) {
                if buffer.len() < index_buffer_size {
                    continue;
                }
                let mut fixed = buffer.to_vec();
                if apply_indx_fixup(&mut fixed).is_err() {
                    continue;
                }
                let active_entries = parse_index_node(
                    &fixed,
                    INDX_HEADER_LEN,
                    directory_reference,
                    directory_path,
                    false,
                );
                for entry in active_entries {
                    on_entry(entry);
                }
                for entry in scan_i30_slack(
                    &fixed,
                    directory_reference,
                    directory_path,
                    index_buffer_size,
                ) {
                    on_entry(entry);
                }
            }
            consumed = consumed.saturating_add(to_read as u64);
        }
    }
    Ok(())
}

fn apply_indx_fixup(buffer: &mut [u8]) -> Result<()> {
    if buffer.len() < INDX_HEADER_LEN || &buffer[0..4] != b"INDX" {
        return Err(anyhow::anyhow!("invalid INDX signature"));
    }
    let usa_offset = read_u16(&buffer[4..6]) as usize;
    let usa_words = read_u16(&buffer[6..8]) as usize;
    if usa_words < 2 {
        return Err(anyhow::anyhow!("invalid INDX update sequence length"));
    }
    let usa_end = usa_offset
        .checked_add(usa_words.saturating_mul(2))
        .ok_or_else(|| anyhow::anyhow!("INDX USA overflow"))?;
    if usa_end > buffer.len() {
        return Err(anyhow::anyhow!("INDX USA outside buffer"));
    }
    let sectors = buffer.len() / SECTOR_SIZE;
    if usa_words - 1 > sectors {
        return Err(anyhow::anyhow!("INDX USA sector count mismatch"));
    }
    let usn = [buffer[usa_offset], buffer[usa_offset + 1]];
    for index in 1..usa_words {
        let sector_end = index
            .checked_mul(SECTOR_SIZE)
            .and_then(|value| value.checked_sub(2))
            .ok_or_else(|| anyhow::anyhow!("INDX sector offset overflow"))?;
        if sector_end + 2 > buffer.len() {
            return Err(anyhow::anyhow!("INDX sector outside buffer"));
        }
        if buffer[sector_end..sector_end + 2] != usn {
            return Err(anyhow::anyhow!("INDX fixup mismatch"));
        }
        let replacement = usa_offset + index * 2;
        buffer[sector_end] = buffer[replacement];
        buffer[sector_end + 1] = buffer[replacement + 1];
    }
    Ok(())
}

fn parse_index_node(
    bytes: &[u8],
    node_header_offset: usize,
    directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
    from_slack: bool,
) -> Vec<I30Entry> {
    let Some(header_end) = node_header_offset.checked_add(INDEX_NODE_HEADER_LEN) else {
        return Vec::new();
    };
    if header_end > bytes.len() {
        return Vec::new();
    }
    let entries_offset = read_u32(&bytes[node_header_offset..node_header_offset + 4]) as usize;
    let entries_size = read_u32(&bytes[node_header_offset + 4..node_header_offset + 8]) as usize;
    let Some(mut cursor) = node_header_offset.checked_add(entries_offset) else {
        return Vec::new();
    };
    let Some(end) = node_header_offset.checked_add(entries_size) else {
        return Vec::new();
    };
    let end = end.min(bytes.len());
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    while cursor + INDEX_ENTRY_HEADER_LEN <= end {
        let Some((entry, flags, length)) = parse_index_entry_at(
            bytes,
            cursor,
            directory_reference,
            directory_path,
            from_slack,
        ) else {
            break;
        };
        if !seen.insert((entry.file_reference, entry.name.to_ascii_lowercase())) {
            break;
        }
        if flags & INDEX_ENTRY_END != 0 {
            break;
        }
        entries.push(entry);
        if length == 0 {
            break;
        }
        cursor = match cursor.checked_add(length) {
            Some(next) if next <= end => next,
            _ => break,
        };
    }

    entries
}

fn scan_i30_slack(
    bytes: &[u8],
    directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
    index_buffer_size: usize,
) -> Vec<I30Entry> {
    if bytes.len() < INDX_HEADER_LEN + INDEX_NODE_HEADER_LEN {
        return Vec::new();
    }
    let node_header_offset = INDX_HEADER_LEN;
    let entries_size = read_u32(&bytes[node_header_offset + 4..node_header_offset + 8]) as usize;
    let slack_start = node_header_offset
        .saturating_add(entries_size)
        .min(bytes.len())
        .max(INDX_HEADER_LEN + INDEX_NODE_HEADER_LEN);
    let slack_end = index_buffer_size.min(bytes.len());
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    let mut cursor = align_to_8(slack_start);
    while cursor + INDEX_ENTRY_HEADER_LEN <= slack_end {
        if let Some((entry, _flags, length)) =
            parse_index_entry_at(bytes, cursor, directory_reference, directory_path, true)
        {
            if entry.from_slack
                && seen.insert((entry.file_reference, entry.name.to_ascii_lowercase()))
            {
                entries.push(entry);
                cursor = cursor.saturating_add(length.max(8));
                continue;
            }
        }
        cursor = cursor.saturating_add(8);
    }

    entries
}

fn parse_index_entry_at(
    bytes: &[u8],
    offset: usize,
    directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
    from_slack: bool,
) -> Option<(I30Entry, u16, usize)> {
    if offset + INDEX_ENTRY_HEADER_LEN > bytes.len() {
        return None;
    }
    let file_reference = read_u64(&bytes[offset..offset + 8]);
    let entry_length = read_u16(&bytes[offset + 8..offset + 10]) as usize;
    let stream_length = read_u16(&bytes[offset + 10..offset + 12]) as usize;
    let flags = read_u16(&bytes[offset + 12..offset + 14]);
    if flags & INDEX_ENTRY_END != 0 {
        return Some((
            I30Entry {
                file_reference,
                parent_reference: 0,
                name: String::new(),
                path: None,
                path_confidence: PathConfidence::Unknown,
                size: 0,
                from_slack,
                created_at: None,
                modified_at: None,
                last_metadata_change_at: None,
            },
            flags,
            entry_length,
        ));
    }
    if entry_length < INDEX_ENTRY_HEADER_LEN
        || entry_length % 8 != 0
        || offset + entry_length > bytes.len()
        || stream_length < 0x42
        || stream_length > entry_length.saturating_sub(INDEX_ENTRY_HEADER_LEN)
    {
        return None;
    }
    let stream_start = offset + INDEX_ENTRY_HEADER_LEN;
    let stream_end = stream_start + stream_length;
    let entry = parse_file_name_stream(
        file_reference,
        &bytes[stream_start..stream_end],
        directory_reference,
        directory_path,
        from_slack,
    )?;
    if from_slack && !strong_i30_slack_entry(&entry, flags) {
        return None;
    }
    let _has_subnode = flags & INDEX_ENTRY_NODE != 0;
    Some((entry, flags, entry_length))
}

fn parse_file_name_stream(
    file_reference: u64,
    stream: &[u8],
    _directory_reference: u64,
    directory_path: Option<&DirectoryPath>,
    from_slack: bool,
) -> Option<I30Entry> {
    if stream.len() < 0x42 {
        return None;
    }
    let parent_reference = read_u64(&stream[0..8]);
    let name_len = stream[0x40] as usize;
    let namespace = stream[0x41];
    let name_bytes = name_len.checked_mul(2)?;
    if name_len == 0 || name_len > 255 || 0x42usize.checked_add(name_bytes)? > stream.len() {
        return None;
    }
    if namespace > 3 {
        return None;
    }
    let name = decode_utf16_name(&stream[0x42..0x42 + name_bytes])?;
    if !valid_file_name(&name) {
        return None;
    }
    let created_at = super::format_ntfs_filetime(read_u64(&stream[8..16]));
    let modified_at = super::format_ntfs_filetime(read_u64(&stream[16..24]));
    let last_metadata_change_at = super::format_ntfs_filetime(read_u64(&stream[24..32]));
    let size = read_u64(&stream[0x30..0x38]);
    let path = directory_path.map(|parent| join_ntfs_path(&parent.path, &name));
    let path_confidence = directory_path
        .map(|parent| parent.confidence)
        .unwrap_or(PathConfidence::Unknown);
    Some(I30Entry {
        file_reference,
        parent_reference,
        name,
        path,
        path_confidence,
        size,
        from_slack,
        created_at,
        modified_at,
        last_metadata_change_at,
    })
}

fn strong_i30_slack_entry(entry: &I30Entry, flags: u16) -> bool {
    if flags & !0x0003 != 0 {
        return false;
    }
    if ntfs_record_number(entry.file_reference) < 24 {
        return false;
    }
    if entry.parent_reference == 0 || ntfs_record_number(entry.parent_reference) == 0 {
        return false;
    }
    if entry.created_at.is_none()
        && entry.modified_at.is_none()
        && entry.last_metadata_change_at.is_none()
    {
        return false;
    }
    true
}

#[derive(Debug, Clone)]
struct UsnRecordRaw {
    file_reference: u64,
    parent_reference: u64,
    timestamp: i64,
    reason: u32,
    name: String,
}

fn parse_usn_record_sequence<F>(bytes: &[u8], mut on_record: F)
where
    F: FnMut(UsnRecordRaw),
{
    let mut cursor = 0usize;
    while cursor + 8 <= bytes.len() {
        let Some((record, length)) = parse_usn_record(&bytes[cursor..]) else {
            break;
        };
        on_record(record);
        cursor = cursor.saturating_add(length);
    }
}

fn scan_usn_records_in_raw_bytes<F>(bytes: &[u8], mut on_record: F)
where
    F: FnMut(UsnRecordRaw),
{
    let mut cursor = 0usize;
    while cursor + 64 <= bytes.len() {
        if let Some((record, length)) = parse_usn_record(&bytes[cursor..]) {
            on_record(record);
            cursor = cursor.saturating_add(length.max(8));
        } else {
            cursor = cursor.saturating_add(8);
        }
    }
}

fn parse_usn_record(bytes: &[u8]) -> Option<(UsnRecordRaw, usize)> {
    if bytes.len() < 64 {
        return None;
    }
    let record_length = read_u32(&bytes[0..4]) as usize;
    let major = read_u16(&bytes[4..6]);
    if !(major == 2 || major == 3) || record_length < 60 || record_length > bytes.len() {
        return None;
    }
    if record_length % 8 != 0 {
        return None;
    }
    let (file_reference, parent_reference, usn_offset) = match major {
        2 => {
            if record_length < 60 {
                return None;
            }
            (read_u64(&bytes[8..16]), read_u64(&bytes[16..24]), 24usize)
        }
        3 => {
            if record_length < 76 {
                return None;
            }
            (
                read_u128_low_u64(&bytes[8..24]),
                read_u128_low_u64(&bytes[24..40]),
                40usize,
            )
        }
        _ => return None,
    };
    let _usn = read_i64(&bytes[usn_offset..usn_offset + 8]);
    let timestamp = read_i64(&bytes[usn_offset + 8..usn_offset + 16]);
    let reason = read_u32(&bytes[usn_offset + 16..usn_offset + 20]);
    let file_name_length = read_u16(&bytes[usn_offset + 32..usn_offset + 34]) as usize;
    let file_name_offset = read_u16(&bytes[usn_offset + 34..usn_offset + 36]) as usize;
    if file_name_length == 0
        || file_name_length % 2 != 0
        || file_name_offset < usn_offset + 36
        || file_name_offset + file_name_length > record_length
    {
        return None;
    }
    let name = decode_utf16_name(&bytes[file_name_offset..file_name_offset + file_name_length])?;
    if !valid_file_name(&name) {
        return None;
    }
    Some((
        UsnRecordRaw {
            file_reference,
            parent_reference,
            timestamp,
            reason,
            name,
        },
        record_length,
    ))
}

fn usn_record_to_evidence(
    record: UsnRecordRaw,
    directory_paths: &HashMap<u64, DirectoryPath>,
) -> Option<UsnEvidence> {
    let relevant = record.reason
        & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME)
        != 0;
    if !relevant {
        return None;
    }
    let path = directory_paths
        .get(&record.parent_reference)
        .map(|parent| join_ntfs_path(&parent.path, &record.name));
    Some(UsnEvidence {
        file_reference: record.file_reference,
        parent_reference: record.parent_reference,
        name: record.name,
        reason: record.reason,
        timestamp: format_filetime_i64(record.timestamp),
        path,
    })
}

fn find_usn_journal_data_runs(mft: &Mft) -> Option<(u64, Vec<DataRun>)> {
    for record_number in ROOT_RECORD..mft.max_record {
        let Some(file) = mft.get_record(record_number) else {
            continue;
        };
        let Some(name) = file.get_best_file_name(mft) else {
            continue;
        };
        if !name.to_string().eq_ignore_ascii_case("$UsnJrnl") {
            continue;
        }
        let mut found = None;
        file.attributes(|attribute| {
            if attribute.header.type_id != NTFS_ATTR_DATA {
                return;
            }
            if attribute_name(attribute.data()).as_deref() != Some("$J") {
                return;
            }
            if attribute.header.is_non_resident != 0
                && let Ok((logical_size, runs)) = attribute.get_nonresident_data_runs(&mft.volume)
            {
                found = Some((logical_size, runs));
            }
        });
        if found.is_some() {
            return found;
        }
    }
    None
}

fn attribute_name(attribute_data: &[u8]) -> Option<String> {
    if attribute_data.len() < 0x10 {
        return None;
    }
    let name_length = attribute_data[9] as usize;
    if name_length == 0 {
        return None;
    }
    let name_offset = read_u16(&attribute_data[10..12]) as usize;
    let byte_len = name_length.checked_mul(2)?;
    if name_offset.checked_add(byte_len)? > attribute_data.len() {
        return None;
    }
    decode_utf16_name(&attribute_data[name_offset..name_offset + byte_len])
}

fn should_skip_created_i30_entry(mft: &Mft, entry: &I30Entry) -> bool {
    let record_number = ntfs_record_number(entry.file_reference);
    if let Some(file) = mft.get_record(record_number) {
        return file.reference_number() == entry.file_reference && file.is_used();
    }
    false
}

fn apply_name_hint(artifact: &mut ArtifactRecord, name: &str) {
    if name.is_empty() {
        return;
    }
    if matches!(artifact.name_source, NameSourceKind::Generated)
        || artifact.name.starts_with("deleted_record_")
    {
        artifact.name = name.to_string();
        artifact.name_source = NameSourceKind::Reconstructed;
        artifact.extension = super::extension(name);
        artifact.kind = infer_artifact_kind(name, None);
        artifact.family = artifact.kind.family();
        artifact.priority_score = artifact.kind.priority_score();
        if artifact.confidence == Confidence::Low {
            artifact.confidence = Confidence::Medium;
        }
    }
}

fn apply_i30_timestamps(artifact: &mut ArtifactRecord, entry: &I30Entry) {
    if artifact.created_at.is_none() {
        artifact.created_at = entry.created_at.clone();
    }
    if artifact.modified_at.is_none() {
        artifact.modified_at = entry.modified_at.clone();
    }
    if artifact.last_metadata_change_at.is_none() {
        artifact.last_metadata_change_at = entry.last_metadata_change_at.clone();
    }
    if artifact.deleted_at.is_none() && artifact.last_metadata_change_at.is_some() {
        artifact.deleted_time_source = Some(DeletedTimeSource::I30MftChange);
        artifact.deleted_time_confidence = DeletedTimeConfidence::Estimated;
    }
}

fn apply_usn_time(artifact: &mut ArtifactRecord, evidence: &UsnEvidence) {
    if evidence.reason & USN_REASON_FILE_DELETE == 0 {
        return;
    }
    if let Some(timestamp) = evidence.timestamp.clone() {
        artifact.deleted_at = Some(timestamp);
        artifact.deleted_time_source = Some(DeletedTimeSource::UsnJournal);
        artifact.deleted_time_confidence = DeletedTimeConfidence::Exact;
    }
}

fn push_path_evidence(
    artifact: &mut ArtifactRecord,
    source: PathEvidenceSource,
    path: Option<String>,
    confidence: PathConfidence,
    note: &str,
) {
    if artifact.path_evidence.iter().any(|existing| {
        existing.source == source && existing.path == path && existing.confidence == confidence
    }) {
        return;
    }
    artifact.path_evidence.push(PathEvidence {
        source,
        path,
        confidence,
        note: note.to_string(),
    });
}

fn artifact_key(artifact: &ArtifactRecord) -> String {
    format!(
        "{}|{}|{}|{}",
        artifact.filesystem_record.unwrap_or(0),
        artifact.parent_reference.unwrap_or(0),
        artifact.name.to_ascii_lowercase(),
        artifact.deleted_at.as_deref().unwrap_or("")
    )
}

fn push_capped_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.iter().any(|existing| existing == &warning) {
        return;
    }
    let prefix = warning.split(']').next().unwrap_or(&warning);
    let same_prefix = warnings
        .iter()
        .filter(|existing| existing.starts_with(prefix))
        .count();
    if same_prefix >= 8 && !warning.contains(":info]") {
        return;
    }
    warnings.push(warning);
}

fn join_ntfs_path(parent: &str, name: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{name}")
    } else {
        format!("{parent}\\{name}")
    }
}

fn ntfs_record_number(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

fn align_to_8(value: usize) -> usize {
    (value + 7) & !7
}

fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.chars().any(|ch| ch == '\0' || ch == '/' || ch == '\\')
}

fn decode_utf16_name(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&units).ok()
}

fn format_filetime_i64(value: i64) -> Option<String> {
    if value <= 0 {
        return None;
    }
    let time = ntfs_to_unix_time(value as u64);
    time.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_i64(bytes: &[u8]) -> i64 {
    i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_u128_low_u64(bytes: &[u8]) -> u64 {
    read_u64(&bytes[0..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{PathConfidence, PathEvidenceSource};

    fn file_name_stream(parent: u64, name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x42 + name.encode_utf16().count() * 2];
        bytes[0..8].copy_from_slice(&parent.to_le_bytes());
        bytes[8..16].copy_from_slice(&132_537_600_000_000_000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&132_537_600_100_000_000u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&132_537_600_200_000_000u64.to_le_bytes());
        bytes[0x30..0x38].copy_from_slice(&1234u64.to_le_bytes());
        bytes[0x38..0x3c].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[0x40] = name.encode_utf16().count() as u8;
        bytes[0x41] = 1;
        for (index, unit) in name.encode_utf16().enumerate() {
            let start = 0x42 + index * 2;
            bytes[start..start + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn index_entry(file_ref: u64, stream: &[u8], flags: u16) -> Vec<u8> {
        let len = align_to_8(INDEX_ENTRY_HEADER_LEN + stream.len());
        let mut bytes = vec![0u8; len];
        bytes[0..8].copy_from_slice(&file_ref.to_le_bytes());
        bytes[8..10].copy_from_slice(&(len as u16).to_le_bytes());
        bytes[10..12].copy_from_slice(&(stream.len() as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&flags.to_le_bytes());
        bytes[INDEX_ENTRY_HEADER_LEN..INDEX_ENTRY_HEADER_LEN + stream.len()]
            .copy_from_slice(stream);
        bytes
    }

    #[test]
    fn parses_index_root_resident_file_name() {
        let mut root = vec![0u8; INDEX_ROOT_HEADER_LEN + INDEX_NODE_HEADER_LEN];
        root[0..4].copy_from_slice(&NTFS_ATTR_FILE_NAME.to_le_bytes());
        root[8..12].copy_from_slice(&(4096u32).to_le_bytes());
        root[INDEX_ROOT_HEADER_LEN..INDEX_ROOT_HEADER_LEN + 4]
            .copy_from_slice(&(INDEX_NODE_HEADER_LEN as u32).to_le_bytes());
        let stream = file_name_stream(0x3000_0000_0000_002a, "demo.jar");
        let entry = index_entry(0x4000_0000_0000_0100, &stream, 0);
        let node_size = (INDEX_NODE_HEADER_LEN + entry.len()) as u32;
        root[INDEX_ROOT_HEADER_LEN + 4..INDEX_ROOT_HEADER_LEN + 8]
            .copy_from_slice(&node_size.to_le_bytes());
        root.extend_from_slice(&entry);

        let directory = DirectoryPath {
            path: "C:\\ProgramData".to_string(),
            confidence: PathConfidence::Exact,
        };
        let entries = parse_index_root_entries(&root, 0x3000_0000_0000_002a, Some(&directory));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "demo.jar");
        assert_eq!(
            entries[0].path.as_deref(),
            Some("C:\\ProgramData\\demo.jar")
        );
        assert!(!entries[0].from_slack);
    }

    #[test]
    fn rejects_bad_indx_fixup() {
        let mut buffer = vec![0u8; 4096];
        buffer[0..4].copy_from_slice(b"INDX");
        buffer[4..6].copy_from_slice(&(0x28u16).to_le_bytes());
        buffer[6..8].copy_from_slice(&(2u16).to_le_bytes());
        buffer[0x28..0x2a].copy_from_slice(&0xaaaa_u16.to_le_bytes());
        buffer[0x2a..0x2c].copy_from_slice(&0xbbbb_u16.to_le_bytes());
        buffer[510..512].copy_from_slice(&0xcccc_u16.to_le_bytes());

        assert!(apply_indx_fixup(&mut buffer).is_err());
    }

    #[test]
    fn parses_slack_i30_entry_after_used_entries() {
        let mut buffer = vec![0u8; 4096];
        buffer[0..4].copy_from_slice(b"INDX");
        let node = INDX_HEADER_LEN;
        buffer[node..node + 4].copy_from_slice(&(INDEX_NODE_HEADER_LEN as u32).to_le_bytes());
        buffer[node + 4..node + 8].copy_from_slice(&(INDEX_NODE_HEADER_LEN as u32).to_le_bytes());
        let stream = file_name_stream(0x3000_0000_0000_002a, "lost.jar");
        let entry = index_entry(0x4000_0000_0000_0200, &stream, 0);
        let slack_start = align_to_8(node + INDEX_NODE_HEADER_LEN);
        buffer[slack_start..slack_start + entry.len()].copy_from_slice(&entry);
        let directory = DirectoryPath {
            path: "C:\\ProgramData".to_string(),
            confidence: PathConfidence::Exact,
        };

        let entries = scan_i30_slack(&buffer, 0x3000_0000_0000_002a, Some(&directory), 4096);

        assert_eq!(entries.len(), 1);
        assert!(entries[0].from_slack);
        assert_eq!(entries[0].name, "lost.jar");
    }

    #[test]
    fn parses_usn_v2_delete_record() {
        let name = "old.jar";
        let name_bytes = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let record_len = align_to_8(60 + name_bytes.len());
        let mut bytes = vec![0u8; record_len];
        bytes[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x4000_0000_0000_0200u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x3000_0000_0000_002au64.to_le_bytes());
        bytes[24..32].copy_from_slice(&42i64.to_le_bytes());
        bytes[32..40].copy_from_slice(&132_537_600_000_000_000i64.to_le_bytes());
        bytes[40..44].copy_from_slice(&USN_REASON_FILE_DELETE.to_le_bytes());
        bytes[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        bytes[58..60].copy_from_slice(&60u16.to_le_bytes());
        bytes[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);

        let parsed = parse_usn_record(&bytes).expect("record should parse").0;

        assert_eq!(parsed.file_reference, 0x4000_0000_0000_0200);
        assert_eq!(parsed.parent_reference, 0x3000_0000_0000_002a);
        assert_eq!(parsed.name, "old.jar");
        assert_ne!(parsed.reason & USN_REASON_FILE_DELETE, 0);
    }

    #[test]
    fn usn_evidence_uses_parent_path_without_open_file_by_id() {
        let mut dirs = HashMap::new();
        dirs.insert(
            0x3000_0000_0000_002a,
            DirectoryPath {
                path: "C:\\ProgramData".to_string(),
                confidence: PathConfidence::Exact,
            },
        );
        let raw = UsnRecordRaw {
            file_reference: 0x4000_0000_0000_0200,
            parent_reference: 0x3000_0000_0000_002a,
            timestamp: 132_537_600_000_000_000,
            reason: USN_REASON_FILE_DELETE,
            name: "old.jar".to_string(),
        };

        let evidence = usn_record_to_evidence(raw, &dirs).expect("evidence");

        assert_eq!(evidence.path.as_deref(), Some("C:\\ProgramData\\old.jar"));
        assert!(evidence.timestamp.is_some());
    }

    #[test]
    fn path_evidence_does_not_duplicate_same_source() {
        let mut artifact = ArtifactRecord::new("scan", "source", "demo.jar");
        push_path_evidence(
            &mut artifact,
            PathEvidenceSource::I30,
            Some("C:\\demo.jar".to_string()),
            PathConfidence::Partial,
            "first",
        );
        push_path_evidence(
            &mut artifact,
            PathEvidenceSource::I30,
            Some("C:\\demo.jar".to_string()),
            PathConfidence::Partial,
            "second",
        );

        assert_eq!(artifact.path_evidence.len(), 1);
    }
}
