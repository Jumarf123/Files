use anyhow::{Context, Result, anyhow};
use directories::ProjectDirs;
use ntfs_reader::{
    api::{NtfsAttributeType, ROOT_RECORD},
    file::NtfsFile,
    file_info::{FileInfo, VecCache},
    mft::Mft,
    volume::Volume,
};
use rss_core::{
    BrowseSourceRequest, FileSystemKind, ScanSource, SourceAccessState, SourceDirectoryListing,
    SourceEntry, SourceEntryClass, SourceKind,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::OffsetDateTime;

const CATALOG_SCHEMA_VERSION: &str = "5";
const DEFAULT_PAGE_SIZE: usize = 256;
const MAX_PAGE_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct CatalogProgress {
    pub phase: CatalogPhase,
    pub progress_percent: f32,
    pub indexed_entries: u64,
    pub total_estimated_entries: Option<u64>,
    pub cache_state: CatalogCacheState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogPhase {
    OpeningVolume,
    EnumeratingFiles,
    AugmentingNtfsMetadata,
    BuildingIndexes,
    Finalizing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogCacheState {
    Cold,
    Warm,
    DeltaRefresh,
    Rebuild,
}

#[derive(Debug, Clone)]
pub struct CatalogStore {
    root: Arc<PathBuf>,
}

#[derive(Debug, Clone)]
struct CatalogIdentity {
    fingerprint: String,
    signature: String,
    db_path: PathBuf,
    temp_path: PathBuf,
}

#[derive(Debug, Clone)]
struct PendingNtfsEntry {
    record: u64,
    parent_record: u64,
    name: String,
    extension: Option<String>,
    is_directory: bool,
    is_metafile: bool,
    size: u64,
    created_at: Option<String>,
    modified_at: Option<String>,
    accessed_at: Option<String>,
    hidden: bool,
    system: bool,
    read_only: bool,
    attr_bits: u32,
    access_state: SourceAccessState,
}

#[derive(Debug, Clone)]
struct CatalogEntryRow {
    object_key: String,
    record: Option<u64>,
    parent_record: Option<u64>,
    parent_path_key: String,
    path: String,
    path_key: String,
    name: String,
    extension: Option<String>,
    is_directory: bool,
    is_metafile: bool,
    entry_class: SourceEntryClass,
    size: u64,
    created_at: Option<String>,
    modified_at: Option<String>,
    accessed_at: Option<String>,
    hidden: bool,
    system: bool,
    read_only: bool,
    attr_bits: u32,
    access_state: SourceAccessState,
}

impl CatalogStore {
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "Jumarf", "Files")
            .ok_or_else(|| anyhow!("Unable to resolve Files application data directory"))?;
        let root = dirs.data_local_dir().join("catalogs");
        fs::create_dir_all(&root)
            .with_context(|| format!("Failed to create catalog directory {}", root.display()))?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn load_or_build<F, C>(
        &self,
        source: &ScanSource,
        force_rebuild: bool,
        mut on_progress: F,
        is_cancelled: C,
    ) -> Result<()>
    where
        F: FnMut(CatalogProgress) -> Result<()>,
        C: Fn() -> bool,
    {
        ensure_catalog_supported(source)?;
        let identity = catalog_identity(source, &self.root);

        if !force_rebuild && identity.db_path.exists() && catalog_matches(&identity)? {
            let connection = open_catalog_connection(&identity.db_path)?;
            let indexed_entries = read_meta(&connection, "entry_count")?
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_else(|| count_entries_from_connection(&connection).unwrap_or(0));
            on_progress(CatalogProgress {
                phase: CatalogPhase::Finalizing,
                progress_percent: 100.0,
                indexed_entries,
                total_estimated_entries: None,
                cache_state: CatalogCacheState::Warm,
            })?;
            return Ok(());
        }

        if identity.temp_path.exists() {
            let _ = fs::remove_file(&identity.temp_path);
        }

        on_progress(CatalogProgress {
            phase: CatalogPhase::OpeningVolume,
            progress_percent: 0.0,
            indexed_entries: 0,
            total_estimated_entries: None,
            cache_state: if force_rebuild {
                CatalogCacheState::Rebuild
            } else {
                CatalogCacheState::Cold
            },
        })?;

        let indexed_entries =
            build_catalog_database(source, &identity, &mut on_progress, &is_cancelled)?;

        if identity.db_path.exists() {
            fs::remove_file(&identity.db_path).with_context(|| {
                format!(
                    "Failed to replace existing catalog {}",
                    identity.db_path.display()
                )
            })?;
        }
        fs::rename(&identity.temp_path, &identity.db_path)
            .with_context(|| format!("Failed to publish catalog {}", identity.db_path.display()))?;

        on_progress(CatalogProgress {
            phase: CatalogPhase::Finalizing,
            progress_percent: 100.0,
            indexed_entries,
            total_estimated_entries: None,
            cache_state: if force_rebuild {
                CatalogCacheState::Rebuild
            } else {
                CatalogCacheState::Cold
            },
        })?;

        Ok(())
    }

    pub fn browse_source(
        &self,
        source: &ScanSource,
        request: &BrowseSourceRequest,
    ) -> Result<SourceDirectoryListing> {
        ensure_catalog_supported(source)?;
        let identity = catalog_identity(source, &self.root);
        if !identity.db_path.exists() || !catalog_matches(&identity)? {
            return Err(anyhow!("catalog_not_ready"));
        }

        let root_path = source
            .mount_point
            .clone()
            .ok_or_else(|| anyhow!("Mounted source path is unavailable"))?;
        let path = request
            .path
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(normalize_display_string)
            .unwrap_or_else(|| normalize_display_string(&root_path));

        let connection = open_catalog_connection(&identity.db_path)?;
        let target = lookup_entry_by_path(&connection, &path)?
            .ok_or_else(|| anyhow!("Requested path was not found"))?;
        let page_size = request
            .limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        let start = request
            .cursor
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let total_entry_count = count_children(
            &connection,
            &target.path_key,
            request.directories_only.unwrap_or(false),
        )?;
        let entries = load_children(
            &connection,
            &target.path_key,
            &path,
            start,
            page_size,
            request.directories_only.unwrap_or(false),
        )?;
        let end = start.saturating_add(entries.len());

        Ok(SourceDirectoryListing {
            source_id: source.id.clone(),
            root_path: normalize_display_string(&root_path),
            path: path.clone(),
            parent_path: normalize_parent_path(&path, &root_path),
            entries,
            deleted_artifacts: Vec::new(),
            total_entry_count,
            deleted_artifact_count: 0,
            next_cursor: (end < total_entry_count).then(|| end.to_string()),
            deleted_artifact_next_cursor: None,
            indexing_complete: true,
            indexed_entries: total_entry_count as u64,
            total_estimated_entries: Some(total_entry_count as u64),
            index_generation: 1,
            deleted_subtree_count: 0,
        })
    }

    pub fn entry_details(&self, source: &ScanSource, path: &str) -> Result<SourceEntry> {
        ensure_catalog_supported(source)?;
        let identity = catalog_identity(source, &self.root);
        if !identity.db_path.exists() || !catalog_matches(&identity)? {
            return Err(anyhow!("catalog_not_ready"));
        }

        let connection = open_catalog_connection(&identity.db_path)?;
        let entry = lookup_entry_by_path(&connection, &normalize_display_string(path))?
            .ok_or_else(|| anyhow!("Source entry was not found"))?;
        Ok(entry.into_source_entry())
    }
}

impl CatalogEntryRow {
    fn into_source_entry(self) -> SourceEntry {
        let parent_path = Path::new(&self.path)
            .parent()
            .map(normalize_display_path)
            .unwrap_or_else(|| self.path.clone());
        SourceEntry {
            name: self.name,
            path: self.path,
            parent_path,
            mft_reference: self.record,
            parent_reference: self.parent_record,
            extension: self.extension,
            is_directory: self.is_directory,
            has_children: Some(catalog_entry_can_navigate(
                self.is_directory,
                self.attr_bits,
                self.access_state,
            )),
            is_metafile: self.is_metafile,
            entry_class: self.entry_class,
            size: if self.is_directory { 0 } else { self.size },
            created_at: self.created_at,
            modified_at: self.modified_at,
            accessed_at: self.accessed_at,
            hidden: self.hidden,
            system: self.system,
            read_only: self.read_only,
            attr_bits: Some(self.attr_bits),
            attributes: attribute_labels(self.attr_bits, self.read_only),
            deleted_hits: 0,
            access_state: self.access_state,
        }
    }
}

fn ensure_catalog_supported(source: &ScanSource) -> Result<()> {
    if source.kind != SourceKind::LogicalVolume {
        return Err(anyhow!(
            "Catalog loading is available only for mounted logical volumes"
        ));
    }
    if source.mount_point.is_none() {
        return Err(anyhow!("Mounted source path is unavailable"));
    }
    Ok(())
}

fn catalog_identity(source: &ScanSource, root: &Path) -> CatalogIdentity {
    let fingerprint = format!(
        "{}|{}|{}|{:?}|{}|{}|{}",
        source.id,
        source.device_path,
        source.mount_point.as_deref().unwrap_or(""),
        source.filesystem,
        source.volume_serial.unwrap_or_default(),
        source.total_bytes,
        source.cluster_size.unwrap_or_default(),
    );
    let signature = format!(
        "{}|{}|{}|{}|{}",
        fingerprint,
        source.volume_label.as_deref().unwrap_or(""),
        source.is_system,
        source.requires_elevation,
        CATALOG_SCHEMA_VERSION,
    );
    let mut digest = Sha256::new();
    digest.update(fingerprint.as_bytes());
    let fingerprint_hash = format!("{:x}", digest.finalize());
    let db_path = root.join(format!("{fingerprint_hash}.sqlite3"));
    let temp_path = root.join(format!("{fingerprint_hash}.tmp.sqlite3"));
    CatalogIdentity {
        fingerprint,
        signature,
        db_path,
        temp_path,
    }
}

fn open_catalog_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)
        .with_context(|| format!("Failed to open catalog {}", path.display()))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .context("Failed to configure catalog journal mode")?;
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .context("Failed to configure catalog sync mode")?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .context("Failed to configure catalog temp store")?;
    connection
        .pragma_update(None, "cache_size", -24_000i64)
        .context("Failed to configure catalog cache size")?;
    Ok(connection)
}

fn open_build_catalog_connection(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path)
        .with_context(|| format!("Failed to open build catalog {}", path.display()))?;
    connection
        .pragma_update(None, "page_size", 32_768i64)
        .context("Failed to configure build catalog page size")?;
    connection
        .pragma_update(None, "journal_mode", "OFF")
        .context("Failed to configure build catalog journal mode")?;
    connection
        .pragma_update(None, "synchronous", "OFF")
        .context("Failed to configure build catalog sync mode")?;
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .context("Failed to configure build catalog locking mode")?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .context("Failed to configure build catalog temp store")?;
    connection
        .pragma_update(None, "cache_size", -64_000i64)
        .context("Failed to configure build catalog cache size")?;
    connection
        .pragma_update(None, "mmap_size", 268_435_456i64)
        .context("Failed to configure build catalog mmap size")?;
    Ok(connection)
}

fn initialize_catalog_database(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS catalog_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entries (
            entry_id INTEGER PRIMARY KEY,
            object_key TEXT NOT NULL,
            record INTEGER,
            parent_record INTEGER,
            parent_path_key TEXT NOT NULL,
            path TEXT NOT NULL,
            path_key TEXT NOT NULL,
            name TEXT NOT NULL,
            lower_name TEXT NOT NULL,
            ext TEXT,
            is_directory INTEGER NOT NULL,
            is_metafile INTEGER NOT NULL,
            entry_class TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_at TEXT,
            modified_at TEXT,
            accessed_at TEXT,
            attr_bits INTEGER,
            hidden INTEGER NOT NULL,
            system INTEGER NOT NULL,
            read_only INTEGER NOT NULL,
            access_state TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn finalize_catalog_database(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS idx_entries_path_key
        ON entries(path_key);
        CREATE INDEX IF NOT EXISTS idx_entries_parent_sort
        ON entries(parent_path_key, is_directory DESC, lower_name);
        "#,
    )?;
    Ok(())
}

fn write_meta(connection: &Connection, key: &str, value: impl ToString) -> Result<()> {
    connection.execute(
        "INSERT OR REPLACE INTO catalog_meta(key, value) VALUES(?1, ?2)",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn read_meta(connection: &Connection, key: &str) -> Result<Option<String>> {
    connection
        .query_row(
            "SELECT value FROM catalog_meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(Into::into)
}

fn catalog_matches(identity: &CatalogIdentity) -> Result<bool> {
    let connection = open_catalog_connection(&identity.db_path)?;
    let ready = read_meta(&connection, "ready")?;
    let schema = read_meta(&connection, "schema_version")?;
    let signature = read_meta(&connection, "signature")?;
    Ok(ready.as_deref() == Some("1")
        && schema.as_deref() == Some(CATALOG_SCHEMA_VERSION)
        && signature.as_deref() == Some(identity.signature.as_str()))
}

fn count_entries_from_connection(connection: &Connection) -> Result<u64> {
    let count = connection.query_row("SELECT COUNT(*) FROM entries", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(count.max(0) as u64)
}

fn build_catalog_database<F, C>(
    source: &ScanSource,
    identity: &CatalogIdentity,
    on_progress: &mut F,
    is_cancelled: &C,
) -> Result<u64>
where
    F: FnMut(CatalogProgress) -> Result<()>,
    C: Fn() -> bool,
{
    let connection = open_build_catalog_connection(&identity.temp_path)?;
    initialize_catalog_database(&connection)?;
    write_meta(&connection, "ready", "0")?;
    write_meta(&connection, "schema_version", CATALOG_SCHEMA_VERSION)?;
    write_meta(&connection, "signature", &identity.signature)?;
    write_meta(&connection, "fingerprint", &identity.fingerprint)?;
    write_meta(
        &connection,
        "root_path",
        source.mount_point.as_deref().unwrap_or_default(),
    )?;

    let rows = match source.filesystem {
        FileSystemKind::Ntfs => build_ntfs_rows(source, on_progress, is_cancelled)?,
        _ => build_filesystem_rows(source, on_progress, is_cancelled)?,
    };
    let row_count = rows.len() as u64;

    let transaction = connection.unchecked_transaction()?;
    insert_rows(&transaction, rows.into_values(), row_count, on_progress)?;
    finalize_catalog_database(&transaction)?;
    on_progress(CatalogProgress {
        phase: CatalogPhase::Finalizing,
        progress_percent: 99.0,
        indexed_entries: row_count,
        total_estimated_entries: Some(row_count),
        cache_state: CatalogCacheState::Cold,
    })?;
    write_meta(&transaction, "ready", "1")?;
    write_meta(&transaction, "entry_count", row_count)?;
    transaction.commit()?;
    Ok(row_count)
}

fn build_ntfs_rows<F, C>(
    source: &ScanSource,
    on_progress: &mut F,
    is_cancelled: &C,
) -> Result<HashMap<String, CatalogEntryRow>>
where
    F: FnMut(CatalogProgress) -> Result<()>,
    C: Fn() -> bool,
{
    let root_path = source.mount_point.as_deref().unwrap_or_default();
    let volume = match Volume::new(&source.device_path) {
        Ok(volume) => volume,
        Err(_) => return build_filesystem_rows(source, on_progress, is_cancelled),
    };
    let mft = match Mft::new(volume) {
        Ok(mft) => mft,
        Err(_) => return build_filesystem_rows(source, on_progress, is_cancelled),
    };
    let total_estimated = mft.max_record.max(1);
    let entries =
        collect_pending_ntfs_entries(source, &mft, total_estimated, on_progress, is_cancelled)?;
    resolve_ntfs_catalog_rows(root_path, entries, on_progress)
}

fn collect_pending_ntfs_entries<F, C>(
    source: &ScanSource,
    mft: &Mft,
    total_estimated: u64,
    on_progress: &mut F,
    is_cancelled: &C,
) -> Result<HashMap<u64, PendingNtfsEntry>>
where
    F: FnMut(CatalogProgress) -> Result<()>,
    C: Fn() -> bool,
{
    let mut cache = VecCache::default();
    let mut entries = HashMap::new();

    for record_number in 0..mft.max_record {
        if is_cancelled() {
            return Err(anyhow!("Source catalog load cancelled"));
        }
        if record_number == ROOT_RECORD {
            continue;
        }

        if record_number % 4096 == 0 {
            let progress_percent = if total_estimated == 0 {
                12.0
            } else {
                6.0 + (record_number as f32 / total_estimated as f32) * 52.0
            };
            on_progress(CatalogProgress {
                phase: CatalogPhase::EnumeratingFiles,
                progress_percent,
                indexed_entries: entries.len() as u64,
                total_estimated_entries: Some(total_estimated),
                cache_state: CatalogCacheState::Cold,
            })?;
        }

        let Some(file) = mft.get_record(record_number) else {
            continue;
        };
        if !file.is_used() {
            continue;
        }
        let Some(name_attr) = file.get_best_file_name(mft) else {
            continue;
        };

        let info = FileInfo::with_cache(mft, &file, &mut cache);
        let name = if info.name.is_empty() {
            name_attr.to_string()
        } else {
            info.name.clone()
        };
        if name.is_empty() {
            continue;
        }

        let attr_bits = name_attr.header.file_attributes;
        let read_only = attr_bits & 0x0001 != 0;
        let hidden = attr_bits & 0x0002 != 0;
        let system = attr_bits & 0x0004 != 0;
        let is_metafile = record_number < ROOT_RECORD
            || name.starts_with('$')
            || info
                .path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().starts_with('$'));
        let logical_size = ntfs_primary_logical_size(&file).max(info.size);

        entries.insert(
            record_number,
            PendingNtfsEntry {
                record: record_number,
                parent_record: name_attr.parent(),
                name: name.clone(),
                extension: (!file.is_directory())
                    .then(|| {
                        Path::new(&name)
                            .extension()
                            .map(|value| value.to_string_lossy().to_ascii_lowercase())
                    })
                    .flatten(),
                is_directory: file.is_directory(),
                is_metafile,
                size: logical_size,
                created_at: info.created.and_then(format_time),
                modified_at: info.modified.and_then(format_time),
                accessed_at: info.accessed.and_then(format_time),
                hidden,
                system,
                read_only,
                attr_bits,
                access_state: if source.mount_point.is_some() {
                    SourceAccessState::Readable
                } else {
                    SourceAccessState::Unknown
                },
            },
        );
    }

    Ok(entries)
}

fn resolve_ntfs_catalog_rows<F>(
    root_path: &str,
    entries: HashMap<u64, PendingNtfsEntry>,
    on_progress: &mut F,
) -> Result<HashMap<String, CatalogEntryRow>>
where
    F: FnMut(CatalogProgress) -> Result<()>,
{
    let root_display = normalize_display_string(root_path);
    let root_path_key = normalize_compare_string(&root_display);
    let mut path_cache = HashMap::new();
    path_cache.insert(ROOT_RECORD, root_display.clone());
    let mut children_by_parent: HashMap<u64, Vec<u64>> = HashMap::new();
    for entry in entries.values() {
        children_by_parent
            .entry(entry.parent_record)
            .or_default()
            .push(entry.record);
    }
    for children in children_by_parent.values_mut() {
        children.sort_unstable();
    }

    on_progress(CatalogProgress {
        phase: CatalogPhase::AugmentingNtfsMetadata,
        progress_percent: 70.0,
        indexed_entries: entries.len() as u64,
        total_estimated_entries: Some(entries.len() as u64),
        cache_state: CatalogCacheState::Cold,
    })?;

    let mut deduped = HashMap::new();
    push_best_row(
        &mut deduped,
        CatalogEntryRow {
            object_key: format!("ntfs:record:{ROOT_RECORD}"),
            record: Some(ROOT_RECORD),
            parent_record: None,
            parent_path_key: String::new(),
            path: root_display.clone(),
            path_key: root_path_key.clone(),
            name: root_display.clone(),
            extension: None,
            is_directory: true,
            is_metafile: false,
            entry_class: SourceEntryClass::Directory,
            size: 0,
            created_at: None,
            modified_at: None,
            accessed_at: None,
            hidden: false,
            system: false,
            read_only: false,
            attr_bits: 0,
            access_state: SourceAccessState::Readable,
        },
    );

    let mut processed = 0usize;
    let mut queue = VecDeque::from([ROOT_RECORD]);
    while let Some(parent_record) = queue.pop_front() {
        let Some(children) = children_by_parent.remove(&parent_record) else {
            continue;
        };
        let parent_path = path_cache
            .get(&parent_record)
            .cloned()
            .unwrap_or_else(|| root_display.clone());
        for child_record in children {
            let entry = entries
                .get(&child_record)
                .ok_or_else(|| anyhow!("Failed to resolve NTFS record {}", child_record))?;
            processed = processed.saturating_add(1);
            if processed == 1 || processed.is_multiple_of(4096) {
                let progress_percent =
                    58.0 + (processed as f32 / entries.len().max(1) as f32) * 28.0;
                on_progress(CatalogProgress {
                    phase: CatalogPhase::AugmentingNtfsMetadata,
                    progress_percent,
                    indexed_entries: processed as u64,
                    total_estimated_entries: Some(entries.len() as u64),
                    cache_state: CatalogCacheState::Cold,
                })?;
            }
            let path = join_display_path(&parent_path, &entry.name);
            path_cache.insert(child_record, path.clone());
            push_best_row(
                &mut deduped,
                CatalogEntryRow {
                    object_key: format!("ntfs:record:{}", entry.record),
                    record: Some(entry.record),
                    parent_record: Some(entry.parent_record),
                    parent_path_key: normalize_compare_string(&parent_path),
                    path: path.clone(),
                    path_key: normalize_compare_string(&path),
                    name: entry.name.clone(),
                    extension: entry.extension.clone(),
                    is_directory: entry.is_directory,
                    is_metafile: entry.is_metafile,
                    entry_class: classify_source_entry(entry.is_directory, entry.is_metafile),
                    size: entry.size,
                    created_at: entry.created_at.clone(),
                    modified_at: entry.modified_at.clone(),
                    accessed_at: entry.accessed_at.clone(),
                    hidden: entry.hidden,
                    system: entry.system,
                    read_only: entry.read_only,
                    attr_bits: entry.attr_bits,
                    access_state: entry.access_state,
                },
            );
            if entry.is_directory || children_by_parent.contains_key(&child_record) {
                queue.push_back(child_record);
            }
        }
    }

    let mut remaining_records = children_by_parent
        .into_values()
        .flatten()
        .collect::<Vec<_>>();
    remaining_records.sort_unstable();
    for child_record in remaining_records {
        let entry = entries
            .get(&child_record)
            .ok_or_else(|| anyhow!("Failed to resolve NTFS record {}", child_record))?;
        processed = processed.saturating_add(1);
        if processed.is_multiple_of(4096) {
            let progress_percent = 58.0 + (processed as f32 / entries.len().max(1) as f32) * 28.0;
            on_progress(CatalogProgress {
                phase: CatalogPhase::AugmentingNtfsMetadata,
                progress_percent,
                indexed_entries: processed as u64,
                total_estimated_entries: Some(entries.len() as u64),
                cache_state: CatalogCacheState::Cold,
            })?;
        }
        let parent_path = path_cache
            .get(&entry.parent_record)
            .cloned()
            .unwrap_or_else(|| root_display.clone());
        let path = join_display_path(&parent_path, &entry.name);
        path_cache.insert(child_record, path.clone());
        push_best_row(
            &mut deduped,
            CatalogEntryRow {
                object_key: format!("ntfs:record:{}", entry.record),
                record: Some(entry.record),
                parent_record: Some(entry.parent_record),
                parent_path_key: normalize_compare_string(&parent_path),
                path: path.clone(),
                path_key: normalize_compare_string(&path),
                name: entry.name.clone(),
                extension: entry.extension.clone(),
                is_directory: entry.is_directory,
                is_metafile: entry.is_metafile,
                entry_class: classify_source_entry(entry.is_directory, entry.is_metafile),
                size: entry.size,
                created_at: entry.created_at.clone(),
                modified_at: entry.modified_at.clone(),
                accessed_at: entry.accessed_at.clone(),
                hidden: entry.hidden,
                system: entry.system,
                read_only: entry.read_only,
                attr_bits: entry.attr_bits,
                access_state: entry.access_state,
            },
        );
    }

    Ok(deduped)
}

fn build_filesystem_rows<F, C>(
    source: &ScanSource,
    on_progress: &mut F,
    is_cancelled: &C,
) -> Result<HashMap<String, CatalogEntryRow>>
where
    F: FnMut(CatalogProgress) -> Result<()>,
    C: Fn() -> bool,
{
    let root_path = source
        .mount_point
        .clone()
        .ok_or_else(|| anyhow!("Mounted source path is unavailable"))?;
    let root = PathBuf::from(&root_path);
    let root_display = normalize_display_path(&root);
    let root_path_key = normalize_compare_string(&root_display);

    let mut deduped = HashMap::new();
    push_best_row(
        &mut deduped,
        build_row_from_filesystem_path(&root, "", Some(root_display.clone()))?,
    );

    let mut queue = VecDeque::from([root]);
    let mut enumerated = 0u64;

    while let Some(directory) = queue.pop_front() {
        if is_cancelled() {
            return Err(anyhow!("Source catalog load cancelled"));
        }

        if enumerated == 0 || enumerated.is_multiple_of(256) {
            let percent = (10.0 + ((enumerated as f32).ln_1p() / 12.0) * 55.0).min(68.0);
            on_progress(CatalogProgress {
                phase: CatalogPhase::EnumeratingFiles,
                progress_percent: percent,
                indexed_entries: deduped.len() as u64,
                total_estimated_entries: None,
                cache_state: CatalogCacheState::Cold,
            })?;
        }

        let parent_display = normalize_display_path(&directory);
        let parent_path_key = normalize_compare_string(&parent_display);
        let read_dir = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                mark_directory_access_state(&mut deduped, &parent_path_key, &error);
                continue;
            }
        };

        for entry in read_dir {
            let Ok(entry) = entry else {
                continue;
            };
            let child_path = entry.path();
            let row = build_row_from_filesystem_path(
                &child_path,
                &normalize_compare_string(&parent_display),
                None,
            )?;
            if catalog_entry_is_traversable_directory(&row) {
                queue.push_back(child_path);
            }
            push_best_row(&mut deduped, row);
            enumerated = enumerated.saturating_add(1);
        }
    }

    on_progress(CatalogProgress {
        phase: CatalogPhase::AugmentingNtfsMetadata,
        progress_percent: 88.0,
        indexed_entries: deduped.len() as u64,
        total_estimated_entries: Some(deduped.len() as u64),
        cache_state: CatalogCacheState::Cold,
    })?;

    if !deduped.contains_key(&root_path_key) {
        push_best_row(
            &mut deduped,
            build_row_from_filesystem_path(Path::new(&root_path), "", Some(root_display))?,
        );
    }
    Ok(deduped)
}

fn build_row_from_filesystem_path(
    path: &Path,
    parent_path_key: &str,
    display_override: Option<String>,
) -> Result<CatalogEntryRow> {
    let path_display = display_override.unwrap_or_else(|| normalize_display_path(path));
    let path_key = normalize_compare_string(&path_display);
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| path_display.clone());

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let attributes = metadata.file_attributes();
            let is_directory = metadata.is_dir();
            let read_only = attributes & 0x0001 != 0 || metadata.permissions().readonly();
            let is_metafile = name.starts_with('$');
            Ok(CatalogEntryRow {
                object_key: format!("fs:{path_key}"),
                record: None,
                parent_record: None,
                parent_path_key: parent_path_key.to_string(),
                path: path_display,
                path_key,
                name: name.clone(),
                extension: (!is_directory)
                    .then(|| {
                        path.extension()
                            .map(|value| value.to_string_lossy().to_ascii_lowercase())
                    })
                    .flatten(),
                is_directory,
                is_metafile,
                entry_class: classify_source_entry(is_directory, is_metafile),
                size: if is_directory { 0 } else { metadata.len() },
                created_at: metadata.created().ok().and_then(system_time_to_iso),
                modified_at: metadata.modified().ok().and_then(system_time_to_iso),
                accessed_at: metadata.accessed().ok().and_then(system_time_to_iso),
                hidden: attributes & 0x0002 != 0,
                system: attributes & 0x0004 != 0,
                read_only,
                attr_bits: attributes,
                access_state: SourceAccessState::Readable,
            })
        }
        Err(error) => {
            let is_directory = path.is_dir();
            let access_state = if is_access_denied(&error) {
                SourceAccessState::Denied
            } else {
                SourceAccessState::Unknown
            };
            let is_metafile = name.starts_with('$');
            Ok(CatalogEntryRow {
                object_key: format!("fs:{path_key}"),
                record: None,
                parent_record: None,
                parent_path_key: parent_path_key.to_string(),
                path: path_display,
                path_key,
                name,
                extension: (!is_directory)
                    .then(|| {
                        path.extension()
                            .map(|value| value.to_string_lossy().to_ascii_lowercase())
                    })
                    .flatten(),
                is_directory,
                is_metafile,
                entry_class: classify_source_entry(is_directory, is_metafile),
                size: 0,
                created_at: None,
                modified_at: None,
                accessed_at: None,
                hidden: false,
                system: false,
                read_only: false,
                attr_bits: 0,
                access_state,
            })
        }
    }
}

fn push_best_row(rows: &mut HashMap<String, CatalogEntryRow>, candidate: CatalogEntryRow) {
    match rows.get(&candidate.path_key) {
        Some(existing) if !prefers_catalog_row(&candidate, existing) => {}
        _ => {
            rows.insert(candidate.path_key.clone(), candidate);
        }
    }
}

fn prefers_catalog_row(candidate: &CatalogEntryRow, existing: &CatalogEntryRow) -> bool {
    let candidate_rank = catalog_row_rank(candidate);
    let existing_rank = catalog_row_rank(existing);
    candidate_rank < existing_rank
        || (candidate_rank == existing_rank && candidate.path.len() < existing.path.len())
}

fn catalog_row_rank(row: &CatalogEntryRow) -> (u8, u8, u8, u8, u64) {
    (
        match row.entry_class {
            SourceEntryClass::MetadataDirectory => 0,
            SourceEntryClass::Directory => 1,
            SourceEntryClass::MetadataFile => 2,
            SourceEntryClass::File => 3,
        },
        match row.access_state {
            SourceAccessState::Readable => 0,
            SourceAccessState::Unknown => 1,
            SourceAccessState::Denied => 2,
        },
        u8::from(row.created_at.is_none())
            + u8::from(row.modified_at.is_none())
            + u8::from(row.accessed_at.is_none()),
        u8::from(row.size == 0),
        row.path.len() as u64,
    )
}

fn insert_rows<F, I>(
    transaction: &rusqlite::Transaction<'_>,
    rows: I,
    row_count: u64,
    on_progress: &mut F,
) -> Result<()>
where
    F: FnMut(CatalogProgress) -> Result<()>,
    I: IntoIterator<Item = CatalogEntryRow>,
{
    let mut statement = transaction.prepare(
        r#"
        INSERT INTO entries(
            object_key, record, parent_record, parent_path_key, path, path_key, name, lower_name, ext,
            is_directory, is_metafile, entry_class, size, created_at, modified_at, accessed_at,
            attr_bits, hidden, system, read_only, access_state
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
        "#,
    )?;

    let total_rows = row_count.max(1) as f32;
    for (index, row) in rows.into_iter().enumerate() {
        if index == 0 || index % 8192 == 0 {
            let progress_percent = 88.0 + (index as f32 / total_rows) * 10.0;
            on_progress(CatalogProgress {
                phase: CatalogPhase::BuildingIndexes,
                progress_percent,
                indexed_entries: index as u64,
                total_estimated_entries: Some(row_count),
                cache_state: CatalogCacheState::Cold,
            })?;
        }
        let lower_name = row.name.to_ascii_lowercase();
        statement.execute(params![
            &row.object_key,
            row.record.map(|value| value as i64),
            row.parent_record.map(|value| value as i64),
            &row.parent_path_key,
            &row.path,
            &row.path_key,
            &row.name,
            &lower_name,
            row.extension.as_deref(),
            row.is_directory as i64,
            row.is_metafile as i64,
            entry_class_name(row.entry_class),
            row.size as i64,
            row.created_at.as_deref(),
            row.modified_at.as_deref(),
            row.accessed_at.as_deref(),
            row.attr_bits as i64,
            row.hidden as i64,
            row.system as i64,
            row.read_only as i64,
            access_state_name(row.access_state),
        ])?;
    }

    Ok(())
}

fn ntfs_primary_logical_size(file: &NtfsFile<'_>) -> u64 {
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

fn lookup_entry_by_path(connection: &Connection, path: &str) -> Result<Option<CatalogEntryRow>> {
    connection
        .query_row(
            r#"
            SELECT object_key, record, parent_record, parent_path_key, path, path_key, name, ext, is_directory,
                   is_metafile, entry_class, size, created_at, modified_at, accessed_at, hidden,
                   system, read_only, attr_bits, access_state
            FROM entries
            WHERE path_key = ?1
            "#,
            params![normalize_compare_string(path)],
            row_to_catalog_entry,
        )
        .optional()
        .map_err(Into::into)
}

fn load_children(
    connection: &Connection,
    parent_path_key: &str,
    parent_path: &str,
    start: usize,
    limit: usize,
    directories_only: bool,
) -> Result<Vec<SourceEntry>> {
    let query = if directories_only {
        r#"
        SELECT object_key, record, parent_record, parent_path_key, path, path_key, name, ext, is_directory,
               is_metafile, entry_class, size, created_at, modified_at, accessed_at, hidden,
               system, read_only, attr_bits, access_state
        FROM entries
        WHERE parent_path_key = ?1 AND is_directory = 1
        ORDER BY is_directory DESC, lower_name
        LIMIT ?2 OFFSET ?3
        "#
    } else {
        r#"
        SELECT object_key, record, parent_record, parent_path_key, path, path_key, name, ext, is_directory,
               is_metafile, entry_class, size, created_at, modified_at, accessed_at, hidden,
               system, read_only, attr_bits, access_state
        FROM entries
        WHERE parent_path_key = ?1
        ORDER BY is_directory DESC, lower_name
        LIMIT ?2 OFFSET ?3
        "#
    };

    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map(
        params![parent_path_key, limit as i64, start as i64],
        row_to_catalog_entry,
    )?;

    let mut entries = Vec::new();
    for row in rows {
        let row = row?;
        entries.push(SourceEntry {
            name: row.name,
            path: row.path,
            parent_path: parent_path.to_string(),
            mft_reference: row.record,
            parent_reference: row.parent_record,
            extension: row.extension,
            is_directory: row.is_directory,
            has_children: Some(catalog_entry_can_navigate(
                row.is_directory,
                row.attr_bits,
                row.access_state,
            )),
            is_metafile: row.is_metafile,
            entry_class: row.entry_class,
            size: if row.is_directory { 0 } else { row.size },
            created_at: row.created_at,
            modified_at: row.modified_at,
            accessed_at: row.accessed_at,
            hidden: row.hidden,
            system: row.system,
            read_only: row.read_only,
            attr_bits: Some(row.attr_bits),
            attributes: attribute_labels(row.attr_bits, row.read_only),
            deleted_hits: 0,
            access_state: row.access_state,
        });
    }

    Ok(entries)
}

fn count_children(
    connection: &Connection,
    parent_path_key: &str,
    directories_only: bool,
) -> Result<usize> {
    let query = if directories_only {
        "SELECT COUNT(*) FROM entries WHERE parent_path_key = ?1 AND is_directory = 1"
    } else {
        "SELECT COUNT(*) FROM entries WHERE parent_path_key = ?1"
    };
    let count =
        connection.query_row(query, params![parent_path_key], |row| row.get::<_, i64>(0))?;
    Ok(count.max(0) as usize)
}

fn row_to_catalog_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<CatalogEntryRow> {
    Ok(CatalogEntryRow {
        object_key: row.get(0)?,
        record: row.get::<_, Option<i64>>(1)?.map(|value| value as u64),
        parent_record: row.get::<_, Option<i64>>(2)?.map(|value| value as u64),
        parent_path_key: row.get(3)?,
        path: row.get(4)?,
        path_key: row.get(5)?,
        name: row.get(6)?,
        extension: row.get(7)?,
        is_directory: row.get::<_, i64>(8)? != 0,
        is_metafile: row.get::<_, i64>(9)? != 0,
        entry_class: entry_class_from_name(&row.get::<_, String>(10)?),
        size: row.get::<_, i64>(11)?.max(0) as u64,
        created_at: row.get(12)?,
        modified_at: row.get(13)?,
        accessed_at: row.get(14)?,
        hidden: row.get::<_, i64>(15)? != 0,
        system: row.get::<_, i64>(16)? != 0,
        read_only: row.get::<_, i64>(17)? != 0,
        attr_bits: row.get::<_, i64>(18)? as u32,
        access_state: access_state_from_name(&row.get::<_, String>(19)?),
    })
}

fn normalize_parent_path(path: &str, root: &str) -> Option<String> {
    if normalize_compare_string(path) == normalize_compare_string(root) {
        return None;
    }
    Path::new(path)
        .parent()
        .map(normalize_display_path)
        .filter(|parent| !parent.is_empty())
}

fn normalize_display_path(path: &Path) -> String {
    let rendered = path.to_string_lossy().replace('/', "\\");
    if rendered.ends_with(':') {
        format!("{rendered}\\")
    } else {
        rendered
    }
}

fn normalize_display_string(path: &str) -> String {
    let rendered = path.replace('/', "\\");
    if rendered.ends_with(':') {
        format!("{rendered}\\")
    } else {
        rendered
    }
}

fn normalize_compare_string(value: &str) -> String {
    if value.len() <= 3 {
        value.replace('/', "\\").to_ascii_lowercase()
    } else {
        value
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    }
}

fn join_display_path(parent: &str, child: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{child}")
    } else {
        format!("{parent}\\{child}")
    }
}

fn classify_source_entry(is_directory: bool, is_metafile: bool) -> SourceEntryClass {
    match (is_directory, is_metafile) {
        (true, true) => SourceEntryClass::MetadataDirectory,
        (false, true) => SourceEntryClass::MetadataFile,
        (true, false) => SourceEntryClass::Directory,
        (false, false) => SourceEntryClass::File,
    }
}

fn entry_class_name(value: SourceEntryClass) -> &'static str {
    match value {
        SourceEntryClass::File => "file",
        SourceEntryClass::Directory => "directory",
        SourceEntryClass::MetadataFile => "metadata_file",
        SourceEntryClass::MetadataDirectory => "metadata_directory",
    }
}

fn entry_class_from_name(value: &str) -> SourceEntryClass {
    match value {
        "directory" => SourceEntryClass::Directory,
        "metadata_file" => SourceEntryClass::MetadataFile,
        "metadata_directory" => SourceEntryClass::MetadataDirectory,
        _ => SourceEntryClass::File,
    }
}

fn access_state_name(value: SourceAccessState) -> &'static str {
    match value {
        SourceAccessState::Readable => "readable",
        SourceAccessState::Denied => "denied",
        SourceAccessState::Unknown => "unknown",
    }
}

fn access_state_from_name(value: &str) -> SourceAccessState {
    match value {
        "readable" => SourceAccessState::Readable,
        "denied" => SourceAccessState::Denied,
        _ => SourceAccessState::Unknown,
    }
}

fn catalog_entry_is_traversable_directory(row: &CatalogEntryRow) -> bool {
    catalog_entry_can_navigate(row.is_directory, row.attr_bits, row.access_state)
}

fn catalog_entry_can_navigate(
    is_directory: bool,
    attr_bits: u32,
    access_state: SourceAccessState,
) -> bool {
    is_directory && access_state == SourceAccessState::Readable && attr_bits & 0x0400 == 0
}

fn mark_directory_access_state(
    rows: &mut HashMap<String, CatalogEntryRow>,
    path_key: &str,
    error: &std::io::Error,
) {
    let Some(row) = rows.get_mut(path_key) else {
        return;
    };
    row.access_state = if is_access_denied(error) {
        SourceAccessState::Denied
    } else {
        SourceAccessState::Unknown
    };
}

fn attribute_labels(attributes: u32, read_only: bool) -> Vec<String> {
    let mut labels = Vec::new();
    if attributes & 0x0002 != 0 {
        labels.push("hidden".to_string());
    }
    if attributes & 0x0004 != 0 {
        labels.push("system".to_string());
    }
    if read_only {
        labels.push("read_only".to_string());
    }
    if attributes & 0x0400 != 0 {
        labels.push("reparse_point".to_string());
    }
    if attributes & 0x0200 != 0 {
        labels.push("sparse".to_string());
    }
    if attributes & 0x0800 != 0 {
        labels.push("compressed".to_string());
    }
    if attributes & 0x4000 != 0 {
        labels.push("encrypted".to_string());
    }
    if attributes & 0x1000 != 0 {
        labels.push("offline".to_string());
    }
    if attributes & 0x0100 != 0 {
        labels.push("temporary".to_string());
    }
    if attributes & 0x2000 != 0 {
        labels.push("not_content_indexed".to_string());
    }
    labels
}

fn format_time(value: OffsetDateTime) -> Option<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn system_time_to_iso(value: std::time::SystemTime) -> Option<String> {
    let duration = value
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?;
    OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn is_access_denied(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(5))
}
