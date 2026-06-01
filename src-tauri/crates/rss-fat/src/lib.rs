use anyhow::{Result, anyhow};
use rss_core::{
    ArtifactRecord, Confidence, FileSystemKind, Recoverability, RecoveryPlan, ScanMode, ScanSource,
    infer_artifact_kind,
};
use rss_windows::read_bytes;
use std::collections::HashSet;

const DIR_ENTRY_SIZE: usize = 32;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_VOLUME_ID: u8 = 0x08;

#[derive(Debug, Clone)]
struct FatContext {
    source_path: String,
    _bytes_per_sector: u16,
    _sectors_per_cluster: u8,
    _reserved_sectors: u16,
    _fats: u8,
    _sectors_per_fat: u32,
    root_cluster: u32,
    _fat_offset: u64,
    data_offset: u64,
    cluster_size: u64,
    fat_bytes: Vec<u8>,
}

impl FatContext {
    fn read(source: &ScanSource) -> Result<Self> {
        if source.filesystem != FileSystemKind::Fat32 {
            return Err(anyhow!("{} is not FAT32", source.display_name));
        }

        let boot = read_bytes(&source.device_path, 0, 512)?;
        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
        let sectors_per_cluster = boot[13];
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]);
        let fats = boot[16];
        let root_entries = u16::from_le_bytes([boot[17], boot[18]]);
        let sectors_per_fat_16 = u16::from_le_bytes([boot[22], boot[23]]);
        let sectors_per_fat = if sectors_per_fat_16 == 0 {
            u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]])
        } else {
            sectors_per_fat_16 as u32
        };
        let root_cluster = u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]);
        if root_entries != 0 || root_cluster < 2 {
            return Err(anyhow!("Only FAT32 volumes are supported in this release"));
        }

        let bytes_per_sector_u64 = bytes_per_sector as u64;
        let fat_offset = reserved_sectors as u64 * bytes_per_sector_u64;
        let fat_length = sectors_per_fat as u64 * bytes_per_sector_u64;
        let data_offset = fat_offset + fat_length * fats as u64;
        let cluster_size = sectors_per_cluster as u64 * bytes_per_sector_u64;
        let fat_bytes = read_bytes(&source.device_path, fat_offset, fat_length as usize)?;

        Ok(Self {
            source_path: source.device_path.clone(),
            _bytes_per_sector: bytes_per_sector,
            _sectors_per_cluster: sectors_per_cluster,
            _reserved_sectors: reserved_sectors,
            _fats: fats,
            _sectors_per_fat: sectors_per_fat,
            root_cluster,
            _fat_offset: fat_offset,
            data_offset,
            cluster_size,
            fat_bytes,
        })
    }

    fn cluster_offset(&self, cluster: u32) -> u64 {
        self.data_offset + ((cluster as u64 - 2) * self.cluster_size)
    }

    fn fat_entry(&self, cluster: u32) -> Option<u32> {
        let offset = cluster as usize * 4;
        let bytes = self.fat_bytes.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?) & 0x0FFF_FFFF)
    }

    fn is_cluster_free(&self, cluster: u32) -> bool {
        self.fat_entry(cluster).unwrap_or(0x0FFF_FFFF) == 0
    }

    fn read_cluster(&self, cluster: u32) -> Result<Vec<u8>> {
        read_bytes(
            &self.source_path,
            self.cluster_offset(cluster),
            self.cluster_size as usize,
        )
    }

    fn read_chain(&self, start_cluster: u32) -> Result<Vec<u8>> {
        let mut cluster = start_cluster;
        let mut visited = HashSet::new();
        let mut bytes = Vec::new();
        while cluster >= 2 && !visited.contains(&cluster) {
            visited.insert(cluster);
            bytes.extend(self.read_cluster(cluster)?);
            let next = self.fat_entry(cluster).unwrap_or(0x0FFF_FFFF);
            if next >= 0x0FFF_FFF8 || next == 0 {
                break;
            }
            cluster = next;
        }
        Ok(bytes)
    }
}

struct FatScanState<'a, F>
where
    F: FnMut(&[ArtifactRecord]) -> bool,
{
    scan_id: &'a str,
    source: &'a ScanSource,
    context: &'a FatContext,
    visited_dirs: &'a mut HashSet<u32>,
    results: &'a mut Vec<ArtifactRecord>,
    on_progress: &'a mut F,
}

pub fn scan_deleted_entries<F>(
    scan_id: &str,
    source: &ScanSource,
    _mode: ScanMode,
    mut on_progress: F,
) -> Result<Vec<ArtifactRecord>>
where
    F: FnMut(&[ArtifactRecord]) -> bool,
{
    let context = FatContext::read(source)?;
    let mut results = Vec::new();
    let mut visited_dirs = HashSet::new();
    let should_continue = scan_directory(
        &mut FatScanState {
            scan_id,
            source,
            context: &context,
            visited_dirs: &mut visited_dirs,
            results: &mut results,
            on_progress: &mut on_progress,
        },
        context.root_cluster,
        source
            .mount_point
            .clone()
            .unwrap_or_else(|| "F:\\".to_string()),
    )?;
    if should_continue {
        let _ = on_progress(&results);
    }
    results.sort_by_key(|artifact| std::cmp::Reverse(artifact.priority_score));
    Ok(results)
}

fn scan_directory<F>(
    state: &mut FatScanState<'_, F>,
    start_cluster: u32,
    current_path: String,
) -> Result<bool>
where
    F: FnMut(&[ArtifactRecord]) -> bool,
{
    if !state.visited_dirs.insert(start_cluster) {
        return Ok(true);
    }

    let directory_bytes = state.context.read_chain(start_cluster)?;
    for entry in directory_bytes.chunks(DIR_ENTRY_SIZE) {
        if entry.len() < DIR_ENTRY_SIZE {
            continue;
        }

        let first = entry[0];
        if first == 0x00 {
            break;
        }
        let attr = entry[11];
        if attr == ATTR_LONG_NAME {
            continue;
        }
        if attr & ATTR_VOLUME_ID == ATTR_VOLUME_ID {
            continue;
        }

        let name = short_name(entry);
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }

        let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
        let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
        let start_cluster = (high << 16) | low;
        let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]) as u64;
        let full_path = format!("{}\\{}", current_path.trim_end_matches('\\'), name);

        if first == 0xE5 {
            if attr & ATTR_DIRECTORY == ATTR_DIRECTORY {
                continue;
            }

            let mut record = ArtifactRecord::new(state.scan_id, &state.source.id, &name);
            record.original_path = Some(full_path);
            record.placement_kind = rss_core::PlacementKind::OriginalPath;
            record.path_confidence = rss_core::PathConfidence::Exact;
            record.name_source = rss_core::NameSourceKind::LongName;
            record.size = size;
            record.extension = name
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase());
            record.kind = infer_artifact_kind(&name, None);
            record.family = record.kind.family();
            record.priority_score = record.kind.priority_score();
            record.confidence = Confidence::Medium;

            if start_cluster >= 2 && state.context.is_cluster_free(start_cluster) {
                let clusters_needed = ((size + state.context.cluster_size.saturating_sub(1))
                    / state.context.cluster_size)
                    .max(1);
                let mut runs = Vec::new();
                let mut contiguous = 0u64;
                for index in 0..clusters_needed {
                    let cluster = start_cluster + index as u32;
                    if !state.context.is_cluster_free(cluster) {
                        break;
                    }
                    contiguous += 1;
                    runs.push(rss_core::ByteRun {
                        offset: state.context.cluster_offset(cluster),
                        length: state.context.cluster_size,
                        sparse: false,
                    });
                }

                if contiguous > 0 {
                    record.recoverability = if clusters_needed == 1 {
                        Recoverability::Good
                    } else {
                        Recoverability::Partial
                    };
                    if clusters_needed > 1 {
                        record.notes.push(
                            "FAT deleted recovery assumes contiguous free clusters beyond the first one."
                                .to_string(),
                        );
                    }
                    record.recovery_plan = RecoveryPlan::RawRuns {
                        source_path: state.source.device_path.clone(),
                        runs,
                        logical_size: size,
                    };
                    record.content_source = rss_core::ContentSourceKind::RawRuns;
                    record.artifact_class = rss_core::ArtifactClass::Recoverable;
                } else {
                    record.recoverability = Recoverability::Poor;
                    record.recovery_plan = RecoveryPlan::Unrecoverable {
                        reason: "Starting cluster is no longer free".to_string(),
                    };
                    record.artifact_class = rss_core::ArtifactClass::NamedMetadataCandidate;
                }
            } else {
                record.recoverability = Recoverability::Poor;
                record.recovery_plan = RecoveryPlan::Unrecoverable {
                    reason: "Deleted FAT entry has no recoverable starting cluster".to_string(),
                };
            }

            state.results.push(record);
            if state.results.len().is_multiple_of(16) {
                state
                    .results
                    .sort_by_key(|artifact| std::cmp::Reverse(artifact.priority_score));
                if !(state.on_progress)(state.results) {
                    return Ok(false);
                }
            }
            continue;
        }

        if attr & ATTR_DIRECTORY == ATTR_DIRECTORY && start_cluster >= 2 {
            let should_continue = scan_directory(state, start_cluster, full_path)?;
            if !should_continue {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

fn short_name(entry: &[u8]) -> String {
    let raw_name = &entry[0..8];
    let raw_ext = &entry[8..11];
    let first = if raw_name[0] == 0xE5 {
        "_".to_string()
    } else {
        String::from_utf8_lossy(&raw_name[0..1]).to_string()
    };
    let mut name = format!(
        "{}{}",
        first,
        String::from_utf8_lossy(&raw_name[1..])
            .trim()
            .trim_matches(char::from(0x00))
    );
    let ext = String::from_utf8_lossy(raw_ext)
        .trim()
        .trim_matches(char::from(0x00))
        .to_string();
    if !ext.is_empty() {
        name.push('.');
        name.push_str(&ext);
    }
    name
}
