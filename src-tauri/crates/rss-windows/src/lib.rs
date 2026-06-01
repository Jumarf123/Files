use anyhow::{Context, Result, anyhow};
use ntfs_reader::{
    api::{FIRST_NORMAL_RECORD, NtfsAttributeType, ROOT_RECORD},
    attribute::DataRun,
    file_info::{FileInfo, VecCache},
    mft::Mft,
    volume::Volume,
};
use rss_core::{
    ByteRun, FileSystemKind, ScanSource, SourceAccessState, SourceDirectoryListing, SourceEntry,
    SourceEntryClass, SourceKind,
};
use rss_security::security_context;
use std::{
    collections::HashMap,
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    os::windows::fs::MetadataExt,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::SystemTime,
};
use time::OffsetDateTime;
use windows::{
    Win32::{
        Foundation::{ERROR_MORE_DATA, HANDLE},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_COMPRESSED,
            FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM,
            FILE_ATTRIBUTE_TEMPORARY, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetDiskFreeSpaceExW, GetDiskFreeSpaceW, GetDriveTypeW,
            GetFileInformationByHandle, GetLogicalDrives, GetVolumeInformationW, OPEN_EXISTING,
        },
        System::{
            IO::DeviceIoControl,
            Ioctl::{
                DISK_GEOMETRY_EX, FSCTL_ALLOW_EXTENDED_DASD_IO, FSCTL_GET_VOLUME_BITMAP,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, STARTING_LCN_INPUT_BUFFER, VOLUME_BITMAP_BUFFER,
            },
            SystemInformation::GetWindowsDirectoryW,
        },
    },
    core::PCWSTR,
};

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DEFAULT_BROWSE_PAGE_SIZE: usize = 256;
const MAX_BROWSE_PAGE_SIZE: usize = 1024;
static NTFS_BROWSE_CACHE: OnceLock<Mutex<HashMap<String, Arc<NtfsBrowseIndex>>>> = OnceLock::new();

pub struct RawReader {
    file: File,
    alignment: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct NtfsBrowseEntry {
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

#[derive(Debug)]
struct NtfsBrowseIndex {
    source_id: String,
    root_path: String,
    root_record: u64,
    entries: RwLock<HashMap<u64, NtfsBrowseEntry>>,
    children: RwLock<HashMap<u64, Vec<u64>>>,
    path_cache: RwLock<HashMap<u64, String>>,
    reverse_path_cache: RwLock<HashMap<String, u64>>,
    indexed_entries: AtomicU64,
    total_estimated_entries: AtomicU64,
    index_generation: AtomicU64,
    indexing_complete: AtomicBool,
    indexing_error: RwLock<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct VolumeBitmap {
    pub cluster_size: u64,
    pub extents: Vec<ByteRun>,
}

impl VolumeBitmap {
    pub fn covers_range(&self, offset: u64, length: u64) -> bool {
        if length == 0 {
            return true;
        }

        let end = offset.saturating_add(length);
        let index = self
            .extents
            .partition_point(|extent| extent.offset <= offset);
        let Some(extent) = index
            .checked_sub(1)
            .and_then(|candidate| self.extents.get(candidate))
        else {
            return false;
        };

        offset >= extent.offset && end <= extent.offset.saturating_add(extent.length)
    }
}

pub fn discover_sources() -> Result<Vec<ScanSource>> {
    let context = security_context().map_err(|err| anyhow!(err.to_string()))?;
    let system_root = windows_root().ok();
    let mut sources = logical_volume_sources(context.is_elevated, system_root.as_deref())?;
    sources.extend(physical_disk_sources(context.is_elevated)?);
    sources.sort_by(|left, right| left.display_name.cmp(&right.display_name));
    Ok(sources)
}

pub fn clear_browse_cache() {
    if let Some(cache) = NTFS_BROWSE_CACHE.get()
        && let Ok(mut guard) = cache.lock()
    {
        guard.clear();
    }
}

pub fn read_volume_bitmap(source: &ScanSource) -> Result<VolumeBitmap> {
    let cluster_size = source
        .cluster_size
        .ok_or_else(|| anyhow!("Cluster size is unknown for {}", source.display_name))?;

    let file = open_raw_readonly(&source.device_path)?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    let header_size = size_of::<VOLUME_BITMAP_BUFFER>() - 1;

    let mut start_lcn = 0u64;
    let mut extents = Vec::new();
    let mut current_free_start: Option<u64> = None;
    let mut current_free_len = 0u64;

    loop {
        let input = STARTING_LCN_INPUT_BUFFER {
            StartingLcn: start_lcn as i64,
        };
        let mut buffer = vec![0u8; header_size + (1 << 20)];
        let mut bytes_returned = 0u32;

        let response = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_VOLUME_BITMAP,
                Some(&input as *const _ as *const _),
                size_of::<STARTING_LCN_INPUT_BUFFER>() as u32,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut bytes_returned as *mut u32),
                None,
            )
        };

        let more_data = match response {
            Ok(_) => false,
            Err(err) if err.code() == ERROR_MORE_DATA.to_hresult() => true,
            Err(err) => return Err(anyhow!("FSCTL_GET_VOLUME_BITMAP failed: {err}")),
        };

        if bytes_returned as usize <= header_size {
            break;
        }

        let bitmap = unsafe { &*(buffer.as_ptr() as *const VOLUME_BITMAP_BUFFER) };
        let bitmap_start = bitmap.StartingLcn.max(0) as u64;
        let byte_len = bytes_returned as usize - header_size;
        let bits = &buffer[header_size..header_size + byte_len];
        for (byte_index, byte) in bits.iter().enumerate() {
            let base_lcn = bitmap_start + (byte_index as u64) * 8;
            match *byte {
                0x00 => {
                    if current_free_start.is_none() {
                        current_free_start = Some(base_lcn);
                        current_free_len = 0;
                    }
                    current_free_len += 8;
                }
                0xFF => {
                    if let Some(free_start) = current_free_start.take() {
                        extents.push(ByteRun {
                            offset: free_start.saturating_mul(cluster_size),
                            length: current_free_len.saturating_mul(cluster_size),
                            sparse: false,
                        });
                        current_free_len = 0;
                    }
                }
                other => {
                    for bit in 0..8u64 {
                        let allocated = (other & (1u8 << bit)) != 0;
                        let lcn = base_lcn + bit;

                        if allocated {
                            if let Some(free_start) = current_free_start.take() {
                                extents.push(ByteRun {
                                    offset: free_start.saturating_mul(cluster_size),
                                    length: current_free_len.saturating_mul(cluster_size),
                                    sparse: false,
                                });
                                current_free_len = 0;
                            }
                        } else if current_free_start.is_none() {
                            current_free_start = Some(lcn);
                            current_free_len = 1;
                        } else {
                            current_free_len += 1;
                        }
                    }
                }
            }
        }

        if !more_data {
            break;
        }

        start_lcn = bitmap_start.saturating_add((byte_len as u64) * 8);
    }

    if let Some(free_start) = current_free_start.take() {
        extents.push(ByteRun {
            offset: free_start.saturating_mul(cluster_size),
            length: current_free_len.saturating_mul(cluster_size),
            sparse: false,
        });
    }

    extents.sort_by_key(|extent| extent.offset);

    Ok(VolumeBitmap {
        cluster_size,
        extents,
    })
}

pub fn open_raw_readonly(path: &str) -> Result<File> {
    let wide = to_wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            FILE_CREATION_DISPOSITION(OPEN_EXISTING.0),
            FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_NORMAL.0),
            None,
        )
    }
    .with_context(|| format!("Unable to open raw device: {path}"))?;

    let file = unsafe { File::from_raw_handle(handle.0) };
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    let mut returned = 0u32;
    let _ = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_ALLOW_EXTENDED_DASD_IO,
            None,
            0,
            None,
            0,
            Some(&mut returned as *mut u32),
            None,
        )
    };

    Ok(file)
}

impl RawReader {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self {
            file: open_raw_readonly(path)?,
            alignment: if path.starts_with(r"\\.\") { 4096 } else { 1 },
            path: path.to_string(),
        })
    }

    pub fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let aligned_offset = offset / self.alignment * self.alignment;
        let prefix = offset.saturating_sub(aligned_offset) as usize;
        let requested_len = prefix.saturating_add(length);
        let aligned_len = if self.alignment > 1 {
            requested_len
                .div_ceil(self.alignment as usize)
                .saturating_mul(self.alignment as usize)
        } else {
            requested_len
        };

        self.file
            .seek(SeekFrom::Start(aligned_offset))
            .with_context(|| format!("Failed to seek to {offset:#x} in {}", self.path))?;

        let mut buffer = vec![0u8; aligned_len];
        let mut total_read = 0usize;
        while total_read < buffer.len() {
            let read = self.file.read(&mut buffer[total_read..]).with_context(|| {
                format!("Failed to read {aligned_len} bytes from {}", self.path)
            })?;
            if read == 0 {
                break;
            }
            total_read += read;
        }

        let required_len = prefix.saturating_add(length);
        if total_read < required_len {
            return Err(anyhow!(
                "Failed to read {length} bytes from {}: requested window extends past available data",
                self.path
            ));
        }

        Ok(buffer[prefix..required_len].to_vec())
    }
}

pub fn read_bytes(path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut reader = RawReader::open(path)?;
    reader.read_at(offset, length)
}

pub fn file_record_number(path: &Path) -> Result<u64> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open {} for file ID lookup", path.display()))?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .with_context(|| format!("Failed to query file information for {}", path.display()))?;

    Ok((((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64) & 0x0000_FFFF_FFFF_FFFF)
}

pub fn browse_source_directory(
    source: &ScanSource,
    requested_path: Option<&str>,
    cursor: Option<&str>,
    limit: Option<usize>,
    directories_only: bool,
) -> Result<SourceDirectoryListing> {
    if source.filesystem == FileSystemKind::Ntfs && source.mount_point.is_some() {
        let index = ntfs_browse_index(source)?;
        return browse_ntfs_directory(&index, requested_path, cursor, limit, directories_only);
    }

    let root = source
        .mount_point
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("Directory browsing is available only for mounted sources"))?;

    let root_display = normalize_display_path(&root);
    let target_path = resolve_browse_path(&root, requested_path)?;
    let path_display = normalize_display_path(&target_path);

    let mut entries = fs::read_dir(&target_path)
        .with_context(|| format!("Failed to enumerate {}", target_path.display()))?
        .filter_map(|entry| build_source_entry(entry.ok(), &path_display).transpose())
        .collect::<Result<Vec<_>>>()?;

    if directories_only {
        entries.retain(|entry| entry.is_directory);
    }

    entries.sort_by(|left, right| {
        right.is_directory.cmp(&left.is_directory).then_with(|| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        })
    });

    let total_entry_count = entries.len();
    let page_size = limit
        .unwrap_or(DEFAULT_BROWSE_PAGE_SIZE)
        .clamp(1, MAX_BROWSE_PAGE_SIZE);
    let start = cursor
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default()
        .min(total_entry_count);
    let end = start.saturating_add(page_size).min(total_entry_count);
    let entries = entries
        .into_iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect::<Vec<_>>();

    Ok(SourceDirectoryListing {
        source_id: source.id.clone(),
        root_path: root_display.clone(),
        path: path_display.clone(),
        parent_path: normalize_parent_path(&path_display, &root_display),
        entries,
        deleted_artifacts: Vec::new(),
        total_entry_count,
        deleted_artifact_count: 0,
        next_cursor: (end < total_entry_count).then(|| end.to_string()),
        deleted_artifact_next_cursor: None,
        indexing_complete: true,
        indexed_entries: total_entry_count as u64,
        total_estimated_entries: Some(total_entry_count as u64),
        index_generation: 0,
        deleted_subtree_count: 0,
    })
}

pub fn inspect_source_entry(source: &ScanSource, requested_path: &str) -> Result<SourceEntry> {
    if source.filesystem == FileSystemKind::Ntfs && source.mount_point.is_some() {
        let index = ntfs_browse_index(source)?;
        let path = normalize_display_string(requested_path);
        let record = resolve_ntfs_record(&index, &path)?;
        let parent_path = normalize_parent_path(&path, &index.root_path)
            .unwrap_or_else(|| index.root_path.clone());
        return build_ntfs_source_entry(&index, record, &parent_path)?
            .ok_or_else(|| anyhow!("Source entry {path} was not found"));
    }

    let root = source
        .mount_point
        .as_ref()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("Directory browsing is available only for mounted sources"))?;
    let target_path = resolve_browse_path(&root, Some(requested_path))?;
    let parent_display = target_path
        .parent()
        .map(normalize_display_path)
        .unwrap_or_else(|| normalize_display_path(&root));
    build_source_entry_from_path(&target_path, &parent_display)?
        .ok_or_else(|| anyhow!("Source entry {} was not found", target_path.display()))
}

pub fn read_source_range(
    source: &ScanSource,
    requested_path: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }

    let direct_path = PathBuf::from(requested_path);
    if direct_path.exists()
        && let Ok(bytes) = read_file_range(&direct_path, offset, length)
    {
        return Ok(bytes);
    }

    if source.filesystem == FileSystemKind::Ntfs && source.mount_point.is_some() {
        let index = ntfs_browse_index(source)?;
        let path = normalize_display_string(requested_path);
        let record = resolve_ntfs_record(&index, &path)?;
        return read_ntfs_record_range(source, record, offset, length);
    }

    Err(anyhow!("Unable to open {}", requested_path))
}

pub fn read_ntfs_record_range_for_source(
    source: &ScanSource,
    record_number: u64,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    read_ntfs_record_range(source, record_number, offset, length)
}

fn ntfs_browse_index(source: &ScanSource) -> Result<Arc<NtfsBrowseIndex>> {
    let cache = NTFS_BROWSE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .map_err(|_| anyhow!("Failed to acquire NTFS browse cache"))?;

    if let Some(index) = guard.get(&source.id) {
        return Ok(Arc::clone(index));
    }

    let index = Arc::new(new_ntfs_browse_index(source)?);
    guard.insert(source.id.clone(), Arc::clone(&index));
    spawn_ntfs_browse_indexer(source.clone(), Arc::clone(&index));
    Ok(index)
}

fn new_ntfs_browse_index(source: &ScanSource) -> Result<NtfsBrowseIndex> {
    let root_path = source
        .mount_point
        .clone()
        .ok_or_else(|| anyhow!("NTFS directory browsing requires a mounted volume"))?;
    let mut path_cache = HashMap::new();
    path_cache.insert(ROOT_RECORD, normalize_display_string(&root_path));
    let mut reverse_path_cache = HashMap::new();
    reverse_path_cache.insert(normalize_compare_string(&root_path), ROOT_RECORD);

    Ok(NtfsBrowseIndex {
        source_id: source.id.clone(),
        root_path: normalize_display_string(&root_path),
        root_record: ROOT_RECORD,
        entries: RwLock::new(HashMap::new()),
        children: RwLock::new(HashMap::new()),
        path_cache: RwLock::new(path_cache),
        reverse_path_cache: RwLock::new(reverse_path_cache),
        indexed_entries: AtomicU64::new(0),
        total_estimated_entries: AtomicU64::new(0),
        index_generation: AtomicU64::new(0),
        indexing_complete: AtomicBool::new(false),
        indexing_error: RwLock::new(None),
    })
}

fn spawn_ntfs_browse_indexer(source: ScanSource, index: Arc<NtfsBrowseIndex>) {
    thread::spawn(move || {
        if let Err(err) = populate_ntfs_browse_index(&source, &index) {
            if let Ok(mut guard) = index.indexing_error.write() {
                *guard = Some(err.to_string());
            }
            index.indexing_complete.store(true, Ordering::Release);
            index.index_generation.fetch_add(1, Ordering::AcqRel);
        }
    });
}

fn populate_ntfs_browse_index(source: &ScanSource, index: &Arc<NtfsBrowseIndex>) -> Result<()> {
    let volume = Volume::new(&source.device_path)
        .with_context(|| format!("Failed to open NTFS volume {}", source.device_path))?;
    let mft = Mft::new(volume).context("Failed to read NTFS MFT for browser")?;
    index.total_estimated_entries.store(
        mft.max_record.saturating_sub(FIRST_NORMAL_RECORD),
        Ordering::Release,
    );

    let mut cache = VecCache::default();
    let mut pending_entries = Vec::new();
    let mut pending_children: HashMap<u64, Vec<u64>> = HashMap::new();

    for record_number in FIRST_NORMAL_RECORD..mft.max_record {
        let Some(file) = mft.get_record(record_number) else {
            maybe_flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
            continue;
        };
        if !file.is_used() {
            maybe_flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
            continue;
        }

        let Some(name_attr) = file.get_best_file_name(&mft) else {
            maybe_flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
            continue;
        };

        let info = FileInfo::with_cache(&mft, &file, &mut cache);
        let name = if info.name.is_empty() {
            name_attr.to_string()
        } else {
            info.name.clone()
        };
        if name.is_empty() {
            maybe_flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
            continue;
        }

        let parent_record = name_attr.parent();
        let attr_bits = name_attr.header.file_attributes;
        let read_only = attr_bits & 0x0001 != 0;
        let hidden = attr_bits & 0x0002 != 0;
        let system = attr_bits & 0x0004 != 0;
        let is_metafile = name.starts_with('$')
            || info
                .path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().starts_with('$'));

        pending_entries.push((
            record_number,
            NtfsBrowseEntry {
                record: record_number,
                parent_record,
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
                size: info.size,
                created_at: info.created.and_then(format_time),
                modified_at: info.modified.and_then(format_time),
                accessed_at: info.accessed.and_then(format_time),
                hidden,
                system,
                read_only,
                attr_bits,
                access_state: SourceAccessState::Readable,
            },
        ));
        pending_children
            .entry(parent_record)
            .or_default()
            .push(record_number);

        if pending_entries.len() >= 256 {
            flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
        }
    }

    flush_ntfs_browse_batch(index, &mut pending_entries, &mut pending_children)?;
    index.indexing_complete.store(true, Ordering::Release);
    index.index_generation.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

fn maybe_flush_ntfs_browse_batch(
    index: &Arc<NtfsBrowseIndex>,
    pending_entries: &mut Vec<(u64, NtfsBrowseEntry)>,
    pending_children: &mut HashMap<u64, Vec<u64>>,
) -> Result<()> {
    if pending_entries.len() >= 256 {
        flush_ntfs_browse_batch(index, pending_entries, pending_children)?;
    }
    Ok(())
}

fn flush_ntfs_browse_batch(
    index: &Arc<NtfsBrowseIndex>,
    pending_entries: &mut Vec<(u64, NtfsBrowseEntry)>,
    pending_children: &mut HashMap<u64, Vec<u64>>,
) -> Result<()> {
    if pending_entries.is_empty() && pending_children.is_empty() {
        return Ok(());
    }

    let added_entries = pending_entries.len() as u64;
    {
        let mut entries = index
            .entries
            .write()
            .map_err(|_| anyhow!("Failed to update NTFS browse entries"))?;
        for (record, entry) in pending_entries.drain(..) {
            entries.insert(record, entry);
        }
    }
    {
        let mut children = index
            .children
            .write()
            .map_err(|_| anyhow!("Failed to update NTFS browse children"))?;
        for (parent, mut child_records) in pending_children.drain() {
            children
                .entry(parent)
                .or_default()
                .append(&mut child_records);
        }
    }

    index
        .indexed_entries
        .fetch_add(added_entries, Ordering::AcqRel);
    index.index_generation.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

fn browse_ntfs_directory(
    index: &NtfsBrowseIndex,
    requested_path: Option<&str>,
    cursor: Option<&str>,
    limit: Option<usize>,
    directories_only: bool,
) -> Result<SourceDirectoryListing> {
    let path = requested_path
        .filter(|value| !value.trim().is_empty())
        .map(normalize_display_string)
        .unwrap_or_else(|| index.root_path.clone());
    let record = match resolve_ntfs_record(index, &path) {
        Ok(record) => record,
        Err(_err) if !index.indexing_complete.load(Ordering::Acquire) => {
            return Ok(empty_ntfs_listing(index, &path));
        }
        Err(err) => return Err(err),
    };
    let mut entries = index
        .children
        .read()
        .map_err(|_| anyhow!("Failed to read NTFS browse children"))?
        .get(&record)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|child_record| build_ntfs_source_entry(index, child_record, &path).transpose())
        .collect::<Result<Vec<_>>>()?;

    if directories_only {
        entries.retain(|entry| entry.is_directory);
    }

    entries.sort_by(|left, right| {
        right.is_directory.cmp(&left.is_directory).then_with(|| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        })
    });

    let total_entry_count = entries.len();
    let page_size = limit
        .unwrap_or(DEFAULT_BROWSE_PAGE_SIZE)
        .clamp(1, MAX_BROWSE_PAGE_SIZE);
    let start = cursor
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default()
        .min(total_entry_count);
    let end = start.saturating_add(page_size).min(total_entry_count);
    let entries = entries
        .into_iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect::<Vec<_>>();

    Ok(SourceDirectoryListing {
        source_id: index.source_id.clone(),
        root_path: index.root_path.clone(),
        path: path.clone(),
        parent_path: normalize_parent_path(&path, &index.root_path),
        entries,
        deleted_artifacts: Vec::new(),
        total_entry_count,
        deleted_artifact_count: 0,
        next_cursor: (end < total_entry_count).then(|| end.to_string()),
        deleted_artifact_next_cursor: None,
        indexing_complete: index.indexing_complete.load(Ordering::Acquire),
        indexed_entries: index.indexed_entries.load(Ordering::Acquire),
        total_estimated_entries: match index.total_estimated_entries.load(Ordering::Acquire) {
            0 => None,
            value => Some(value),
        },
        index_generation: index.index_generation.load(Ordering::Acquire),
        deleted_subtree_count: 0,
    })
}

fn empty_ntfs_listing(index: &NtfsBrowseIndex, path: &str) -> SourceDirectoryListing {
    SourceDirectoryListing {
        source_id: index.source_id.clone(),
        root_path: index.root_path.clone(),
        path: path.to_string(),
        parent_path: normalize_parent_path(path, &index.root_path),
        entries: Vec::new(),
        deleted_artifacts: Vec::new(),
        total_entry_count: 0,
        deleted_artifact_count: 0,
        next_cursor: None,
        deleted_artifact_next_cursor: None,
        indexing_complete: index.indexing_complete.load(Ordering::Acquire),
        indexed_entries: index.indexed_entries.load(Ordering::Acquire),
        total_estimated_entries: match index.total_estimated_entries.load(Ordering::Acquire) {
            0 => None,
            value => Some(value),
        },
        index_generation: index.index_generation.load(Ordering::Acquire),
        deleted_subtree_count: 0,
    }
}

fn build_ntfs_source_entry(
    index: &NtfsBrowseIndex,
    record: u64,
    parent_path: &str,
) -> Result<Option<SourceEntry>> {
    let meta = {
        let entries = index
            .entries
            .read()
            .map_err(|_| anyhow!("Failed to read NTFS browse entries"))?;
        let Some(meta) = entries.get(&record) else {
            return Ok(None);
        };
        meta.clone()
    };

    let path = resolve_ntfs_path(index, record)?;
    let has_children = if meta.is_directory {
        Some(
            index
                .children
                .read()
                .map_err(|_| anyhow!("Failed to read NTFS child entries"))?
                .get(&record)
                .is_some_and(|children| !children.is_empty()),
        )
    } else {
        Some(false)
    };

    Ok(Some(SourceEntry {
        name: meta.name.clone(),
        path,
        parent_path: parent_path.to_string(),
        mft_reference: Some(meta.record),
        parent_reference: Some(meta.parent_record),
        extension: meta.extension.clone(),
        is_directory: meta.is_directory,
        has_children,
        is_metafile: meta.is_metafile,
        entry_class: classify_source_entry(meta.is_directory, meta.is_metafile),
        size: if meta.is_directory { 0 } else { meta.size },
        created_at: meta.created_at.clone(),
        modified_at: meta.modified_at.clone(),
        accessed_at: meta.accessed_at.clone(),
        hidden: meta.hidden,
        system: meta.system,
        read_only: meta.read_only,
        attr_bits: Some(meta.attr_bits),
        attributes: attribute_labels(meta.attr_bits, meta.read_only),
        deleted_hits: 0,
        access_state: meta.access_state,
    }))
}

fn resolve_ntfs_record(index: &NtfsBrowseIndex, path: &str) -> Result<u64> {
    let normalized = normalize_compare_string(path);
    if normalized == normalize_compare_string(&index.root_path) {
        return Ok(index.root_record);
    }

    if let Ok(cache) = index.reverse_path_cache.read()
        && let Some(record) = cache.get(&normalized)
    {
        return Ok(*record);
    }

    let root_normalized = normalize_compare_string(&index.root_path);
    if !normalized.starts_with(&root_normalized) {
        return Err(anyhow!("Requested path is outside the selected source"));
    }

    let mut current_record = index.root_record;
    let mut current_path = index.root_path.clone();
    let suffix = path
        .trim_start_matches(index.root_path.trim_end_matches('\\'))
        .trim_matches('\\');
    let children = index
        .children
        .read()
        .map_err(|_| anyhow!("Failed to read NTFS browse children"))?;
    let entries = index
        .entries
        .read()
        .map_err(|_| anyhow!("Failed to read NTFS browse entries"))?;

    for segment in suffix.split('\\').filter(|segment| !segment.is_empty()) {
        let Some(children) = children.get(&current_record) else {
            return Err(anyhow!("Requested path was not found in NTFS metadata"));
        };
        let Some(next_record) = children.iter().copied().find(|candidate| {
            entries
                .get(candidate)
                .is_some_and(|entry| entry.name.eq_ignore_ascii_case(segment))
        }) else {
            return Err(anyhow!("Requested path was not found in NTFS metadata"));
        };
        current_record = next_record;
        current_path = join_display_path(&current_path, segment);
        cache_ntfs_path(index, current_record, &current_path);
    }

    Ok(current_record)
}

fn resolve_ntfs_path(index: &NtfsBrowseIndex, record: u64) -> Result<String> {
    if let Ok(cache) = index.path_cache.read()
        && let Some(path) = cache.get(&record)
    {
        return Ok(path.clone());
    }

    let entries = index
        .entries
        .read()
        .map_err(|_| anyhow!("Failed to read NTFS browse entries"))?;
    let mut components = Vec::new();
    let mut current = record;
    loop {
        if current == index.root_record {
            break;
        }

        let Some(entry) = entries.get(&current) else {
            return Err(anyhow!("Failed to resolve NTFS path for record {record}"));
        };

        components.push((current, entry.name.clone()));
        current = entry.parent_record;
        if components.len() > entries.len().max(1) {
            return Err(anyhow!("Detected a loop while resolving NTFS path"));
        }
    }

    let mut path = index.root_path.clone();
    for (component_record, name) in components.iter().rev() {
        path = join_display_path(&path, name);
        cache_ntfs_path(index, *component_record, &path);
    }
    Ok(path)
}

fn cache_ntfs_path(index: &NtfsBrowseIndex, record: u64, path: &str) {
    if let Ok(mut cache) = index.path_cache.write() {
        cache.insert(record, path.to_string());
    }
    if let Ok(mut reverse) = index.reverse_path_cache.write() {
        reverse.insert(normalize_compare_string(path), record);
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

fn source_entry_can_navigate(
    is_directory: bool,
    attributes: u32,
    access_state: SourceAccessState,
) -> bool {
    is_directory
        && access_state == SourceAccessState::Readable
        && attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
}

fn resolve_browse_path(root: &Path, requested_path: Option<&str>) -> Result<PathBuf> {
    let candidate = requested_path
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| root.to_path_buf());

    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    };

    let root_check = normalize_compare_path(root);
    let candidate_check = normalize_compare_path(&candidate);
    if !candidate_check.starts_with(&root_check) {
        return Err(anyhow!("Requested path is outside the selected source"));
    }

    Ok(candidate)
}

fn build_source_entry(
    entry: Option<fs::DirEntry>,
    parent_path: &str,
) -> Result<Option<SourceEntry>> {
    let Some(entry) = entry else {
        return Ok(None);
    };

    let path = entry.path();
    let name = entry.file_name().to_string_lossy().trim().to_string();

    if name.is_empty() {
        return Ok(None);
    }

    let path_display = normalize_display_path(&path);
    let file_type = entry.file_type().ok();

    let source_entry = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            let attributes = metadata.file_attributes();
            let is_directory = metadata.is_dir();
            let read_only =
                attributes & FILE_ATTRIBUTE_READONLY.0 != 0 || metadata.permissions().readonly();

            SourceEntry {
                name: name.clone(),
                path: path_display,
                parent_path: parent_path.to_string(),
                mft_reference: None,
                parent_reference: None,
                extension: (!is_directory)
                    .then(|| {
                        path.extension()
                            .map(|value| value.to_string_lossy().to_string())
                    })
                    .flatten(),
                is_directory,
                has_children: Some(source_entry_can_navigate(
                    is_directory,
                    attributes,
                    SourceAccessState::Readable,
                )),
                is_metafile: name.starts_with('$'),
                entry_class: classify_source_entry(is_directory, name.starts_with('$')),
                size: if is_directory { 0 } else { metadata.len() },
                created_at: metadata.created().ok().and_then(system_time_to_iso),
                modified_at: metadata.modified().ok().and_then(system_time_to_iso),
                accessed_at: metadata.accessed().ok().and_then(system_time_to_iso),
                hidden: attributes & FILE_ATTRIBUTE_HIDDEN.0 != 0,
                system: attributes & FILE_ATTRIBUTE_SYSTEM.0 != 0,
                read_only,
                attr_bits: Some(attributes),
                attributes: attribute_labels(attributes, read_only),
                deleted_hits: 0,
                access_state: SourceAccessState::Readable,
            }
        }
        Err(error) => {
            let is_directory = file_type.map(|value| value.is_dir()).unwrap_or(false);
            let access_state = if is_access_denied(&error) {
                SourceAccessState::Denied
            } else {
                SourceAccessState::Unknown
            };

            SourceEntry {
                name: name.clone(),
                path: path_display,
                parent_path: parent_path.to_string(),
                mft_reference: None,
                parent_reference: None,
                extension: (!is_directory)
                    .then(|| {
                        path.extension()
                            .map(|value| value.to_string_lossy().to_string())
                    })
                    .flatten(),
                is_directory,
                has_children: Some(false),
                is_metafile: name.starts_with('$'),
                entry_class: classify_source_entry(is_directory, name.starts_with('$')),
                size: 0,
                created_at: None,
                modified_at: None,
                accessed_at: None,
                hidden: false,
                system: false,
                read_only: false,
                attr_bits: None,
                attributes: vec!["access_denied".to_string()],
                deleted_hits: 0,
                access_state,
            }
        }
    };

    Ok(Some(source_entry))
}

fn build_source_entry_from_path(path: &Path, parent_path: &str) -> Result<Option<SourceEntry>> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| normalize_display_path(path));

    let path_display = normalize_display_path(path);
    let source_entry = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let attributes = metadata.file_attributes();
            let is_directory = metadata.is_dir();
            let read_only =
                attributes & FILE_ATTRIBUTE_READONLY.0 != 0 || metadata.permissions().readonly();

            SourceEntry {
                name: name.clone(),
                path: path_display,
                parent_path: parent_path.to_string(),
                mft_reference: None,
                parent_reference: None,
                extension: (!is_directory)
                    .then(|| {
                        path.extension()
                            .map(|value| value.to_string_lossy().to_string())
                    })
                    .flatten(),
                is_directory,
                has_children: Some(source_entry_can_navigate(
                    is_directory,
                    attributes,
                    SourceAccessState::Readable,
                )),
                is_metafile: name.starts_with('$'),
                entry_class: classify_source_entry(is_directory, name.starts_with('$')),
                size: if is_directory { 0 } else { metadata.len() },
                created_at: metadata.created().ok().and_then(system_time_to_iso),
                modified_at: metadata.modified().ok().and_then(system_time_to_iso),
                accessed_at: metadata.accessed().ok().and_then(system_time_to_iso),
                hidden: attributes & FILE_ATTRIBUTE_HIDDEN.0 != 0,
                system: attributes & FILE_ATTRIBUTE_SYSTEM.0 != 0,
                read_only,
                attr_bits: Some(attributes),
                attributes: attribute_labels(attributes, read_only),
                deleted_hits: 0,
                access_state: SourceAccessState::Readable,
            }
        }
        Err(error) => {
            let is_directory = path.is_dir();
            let access_state = if is_access_denied(&error) {
                SourceAccessState::Denied
            } else {
                SourceAccessState::Unknown
            };

            SourceEntry {
                name: name.clone(),
                path: path_display,
                parent_path: parent_path.to_string(),
                mft_reference: None,
                parent_reference: None,
                extension: path
                    .extension()
                    .map(|value| value.to_string_lossy().to_string()),
                is_directory,
                has_children: Some(false),
                is_metafile: name.starts_with('$'),
                entry_class: classify_source_entry(is_directory, name.starts_with('$')),
                size: 0,
                created_at: None,
                modified_at: None,
                accessed_at: None,
                hidden: false,
                system: false,
                read_only: false,
                attr_bits: None,
                attributes: vec!["access_denied".to_string()],
                deleted_hits: 0,
                access_state,
            }
        }
    };

    Ok(Some(source_entry))
}

fn read_file_range(path: &Path, offset: u64, length: u64) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("Failed to seek in {}", path.display()))?;
    let mut buffer = vec![0u8; length as usize];
    let mut total_read = 0usize;
    while total_read < buffer.len() {
        let read = file
            .read(&mut buffer[total_read..])
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        total_read += read;
    }
    buffer.truncate(total_read);
    Ok(buffer)
}

fn read_ntfs_record_range(
    source: &ScanSource,
    record_number: u64,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    let volume = Volume::new(&source.device_path)
        .with_context(|| format!("Failed to open NTFS volume {}", source.device_path))?;
    let mft = Mft::new(volume).context("Failed to read NTFS MFT for source preview")?;
    let Some(file) = mft.get_record(record_number) else {
        return Err(anyhow!("NTFS record {record_number} is unavailable"));
    };
    if file.is_directory() {
        return Err(anyhow!("Directories do not expose byte preview"));
    }

    let Some(data_stream) = best_ntfs_data_stream(&file, &mft)? else {
        return Err(anyhow!(
            "NTFS record {record_number} has no readable $DATA attribute"
        ));
    };

    if let NtfsPreviewData::Resident(bytes) = data_stream {
        let start = offset.min(bytes.len() as u64) as usize;
        let end = offset.saturating_add(length).min(bytes.len() as u64) as usize;
        return Ok(bytes.get(start..end).unwrap_or(&[]).to_vec());
    }

    let NtfsPreviewData::NonResident { logical_size, runs } = data_stream else {
        unreachable!();
    };
    let mut source_reader = RawReader::open(&source.device_path)?;
    read_ntfs_data_window(
        &mut source_reader,
        &runs,
        logical_size,
        offset,
        length,
        &source.device_path,
    )
}

enum NtfsPreviewData {
    Resident(Vec<u8>),
    NonResident {
        logical_size: u64,
        runs: Vec<DataRun>,
    },
}

fn read_ntfs_data_window(
    reader: &mut RawReader,
    runs: &[DataRun],
    logical_size: u64,
    offset: u64,
    length: u64,
    source_path: &str,
) -> Result<Vec<u8>> {
    let end_offset = offset.saturating_add(length).min(logical_size);
    if end_offset <= offset {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity((end_offset - offset) as usize);
    let mut logical_cursor = 0u64;

    for run in runs {
        let (run_offset, run_length, sparse) = match run {
            DataRun::Data { lcn, length } => (*lcn, *length, false),
            DataRun::Sparse { length } => (0, *length, true),
        };

        let run_end = logical_cursor.saturating_add(run_length);
        if run_end <= offset {
            logical_cursor = run_end;
            continue;
        }
        if logical_cursor >= end_offset {
            break;
        }

        let slice_start = offset.saturating_sub(logical_cursor);
        let slice_end = (end_offset - logical_cursor).min(run_length);
        let to_read = slice_end.saturating_sub(slice_start);
        if to_read == 0 {
            logical_cursor = run_end;
            continue;
        }

        if sparse {
            output.extend(std::iter::repeat_n(0u8, to_read as usize));
        } else {
            match reader.read_at(run_offset.saturating_add(slice_start), to_read as usize) {
                Ok(buffer) => output.extend_from_slice(&buffer),
                Err(error) if output.is_empty() => {
                    return Err(
                        error.context(format!("Failed to read {to_read} bytes from {source_path}"))
                    );
                }
                Err(_) => break,
            }
        }

        logical_cursor = run_end;
    }

    Ok(output)
}

fn best_ntfs_data_stream(
    file: &ntfs_reader::file::NtfsFile<'_>,
    mft: &Mft,
) -> Result<Option<NtfsPreviewData>> {
    let mut unnamed: Option<(u64, NtfsPreviewData)> = None;
    let mut named: Option<(u64, NtfsPreviewData)> = None;

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
                        NtfsPreviewData::NonResident { logical_size, runs },
                    )
                })
        } else {
            attribute.as_resident_data().map(|bytes| {
                (
                    bytes.len() as u64,
                    NtfsPreviewData::Resident(bytes.to_vec()),
                )
            })
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

fn join_display_path(parent: &str, child: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{child}")
    } else {
        format!("{parent}\\{child}")
    }
}

fn normalize_compare_path(path: &Path) -> String {
    normalize_compare_string(&normalize_display_path(path))
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

fn is_access_denied(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
}

fn attribute_labels(attributes: u32, read_only: bool) -> Vec<String> {
    let mut labels = Vec::new();
    if attributes & FILE_ATTRIBUTE_HIDDEN.0 != 0 {
        labels.push("hidden".to_string());
    }
    if attributes & FILE_ATTRIBUTE_SYSTEM.0 != 0 {
        labels.push("system".to_string());
    }
    if read_only {
        labels.push("read_only".to_string());
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        labels.push("reparse_point".to_string());
    }
    if attributes & FILE_ATTRIBUTE_SPARSE_FILE.0 != 0 {
        labels.push("sparse".to_string());
    }
    if attributes & FILE_ATTRIBUTE_COMPRESSED.0 != 0 {
        labels.push("compressed".to_string());
    }
    if attributes & FILE_ATTRIBUTE_ENCRYPTED.0 != 0 {
        labels.push("encrypted".to_string());
    }
    if attributes & FILE_ATTRIBUTE_OFFLINE.0 != 0 {
        labels.push("offline".to_string());
    }
    if attributes & FILE_ATTRIBUTE_TEMPORARY.0 != 0 {
        labels.push("temporary".to_string());
    }
    if attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED.0 != 0 {
        labels.push("not_content_indexed".to_string());
    }
    labels
}

fn system_time_to_iso(value: SystemTime) -> Option<String> {
    let date_time = OffsetDateTime::from(value);
    date_time
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn format_time(value: OffsetDateTime) -> Option<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

fn logical_volume_sources(is_elevated: bool, system_root: Option<&str>) -> Result<Vec<ScanSource>> {
    let bitmask = unsafe { GetLogicalDrives() };
    let mut sources = Vec::new();

    for index in 0..26u8 {
        if bitmask & (1u32 << index) == 0 {
            continue;
        }

        let letter = (b'A' + index) as char;
        let root = format!("{letter}:\\");
        let wide_root = to_wide(&root);
        let drive_type = unsafe { GetDriveTypeW(PCWSTR::from_raw(wide_root.as_ptr())) };
        if drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE {
            continue;
        }

        let mut volume_name = [0u16; 256];
        let mut fs_name = [0u16; 64];
        let mut serial = 0u32;
        let mut max_component = 0u32;
        let mut flags = 0u32;
        unsafe {
            GetVolumeInformationW(
                PCWSTR::from_raw(wide_root.as_ptr()),
                Some(&mut volume_name),
                Some(&mut serial),
                Some(&mut max_component),
                Some(&mut flags),
                Some(&mut fs_name),
            )
        }
        .ok();

        let mut free_bytes = 0u64;
        let mut total_bytes = 0u64;
        let mut total_free = 0u64;
        unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR::from_raw(wide_root.as_ptr()),
                Some(&mut free_bytes),
                Some(&mut total_bytes),
                Some(&mut total_free),
            )
        }
        .with_context(|| format!("Failed to query size for {root}"))?;

        let mut sectors_per_cluster = 0u32;
        let mut bytes_per_sector = 0u32;
        let mut number_of_free_clusters = 0u32;
        let mut total_number_of_clusters = 0u32;
        unsafe {
            GetDiskFreeSpaceW(
                PCWSTR::from_raw(wide_root.as_ptr()),
                Some(&mut sectors_per_cluster),
                Some(&mut bytes_per_sector),
                Some(&mut number_of_free_clusters),
                Some(&mut total_number_of_clusters),
            )
        }
        .ok();

        let volume_label = from_wide(&volume_name);
        let fs = from_wide(&fs_name);
        let device_path = format!(r"\\.\{}:", letter);
        let display_name = if volume_label.is_empty() {
            format!("{root} ({fs})")
        } else {
            format!("{root} {volume_label} ({fs})")
        };

        sources.push(ScanSource {
            id: format!("volume:{letter}"),
            kind: SourceKind::LogicalVolume,
            device_path,
            mount_point: Some(root.clone()),
            display_name,
            volume_label: (!volume_label.is_empty()).then_some(volume_label),
            filesystem: fs_kind(&fs),
            volume_serial: Some(serial),
            total_bytes,
            free_bytes: total_free,
            cluster_size: (sectors_per_cluster > 0 && bytes_per_sector > 0)
                .then_some(sectors_per_cluster as u64 * bytes_per_sector as u64),
            is_system: system_root
                .map(|candidate| {
                    candidate
                        .to_ascii_lowercase()
                        .starts_with(&root.to_ascii_lowercase())
                })
                .unwrap_or(false),
            requires_elevation: is_elevated,
        });
    }

    Ok(sources)
}

fn physical_disk_sources(is_elevated: bool) -> Result<Vec<ScanSource>> {
    let mut sources = Vec::new();

    for index in 0..16u32 {
        let path = format!(r"\\.\PhysicalDrive{index}");
        let Ok(file) = open_raw_readonly(&path) else {
            continue;
        };

        let handle = HANDLE(file.as_raw_handle() as *mut _);
        let mut geometry_bytes = vec![0u8; size_of::<DISK_GEOMETRY_EX>() + 128];
        let mut returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(geometry_bytes.as_mut_ptr() as *mut _),
                geometry_bytes.len() as u32,
                Some(&mut returned as *mut u32),
                None,
            )
        };
        if result.is_err() || returned < size_of::<DISK_GEOMETRY_EX>() as u32 {
            continue;
        }

        let geometry = unsafe { &*(geometry_bytes.as_ptr() as *const DISK_GEOMETRY_EX) };
        let total_bytes = geometry.DiskSize.max(0) as u64;
        sources.push(ScanSource {
            id: format!("disk:{index}"),
            kind: SourceKind::PhysicalDisk,
            device_path: path.clone(),
            mount_point: None,
            display_name: format!("PhysicalDrive{index}"),
            volume_label: None,
            filesystem: FileSystemKind::Unknown,
            volume_serial: None,
            total_bytes,
            free_bytes: 0,
            cluster_size: None,
            is_system: index == 0,
            requires_elevation: is_elevated,
        });
    }

    Ok(sources)
}

fn windows_root() -> Result<String> {
    let mut buffer = [0u16; 260];
    let written = unsafe { GetWindowsDirectoryW(Some(&mut buffer)) };
    if written == 0 {
        return Err(anyhow!("GetWindowsDirectoryW returned 0"));
    }
    Ok(String::from_utf16_lossy(&buffer[..written as usize]))
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end]).trim().to_string()
}

fn fs_kind(value: &str) -> FileSystemKind {
    match value.to_ascii_lowercase().as_str() {
        "ntfs" => FileSystemKind::Ntfs,
        "fat32" => FileSystemKind::Fat32,
        "exfat" => FileSystemKind::ExFat,
        _ => FileSystemKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::Write,
        path::PathBuf,
        thread,
        time::{Duration, SystemTime},
    };

    #[test]
    fn ntfs_browser_surfaces_metadata_entries() -> Result<()> {
        if std::env::var_os("RSS_FILES_LIVE_VOLUME_TESTS").is_none() {
            return Ok(());
        }

        let Some(source) = discover_sources()?.into_iter().find(|source| {
            source.filesystem == FileSystemKind::Ntfs && source.mount_point.is_some()
        }) else {
            return Ok(());
        };

        let mut listing = browse_source_directory(&source, None, None, Some(512), false)?;
        let extend_path = format!("{}$Extend", source.mount_point.clone().unwrap_or_default());
        let mut metadata_visible = listing
            .entries
            .iter()
            .any(|entry| entry.is_metafile || entry.name.starts_with('$'));
        for _ in 0..40 {
            if metadata_visible || inspect_source_entry(&source, &extend_path).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
            listing = browse_source_directory(&source, None, None, Some(512), false)?;
            metadata_visible = listing
                .entries
                .iter()
                .any(|entry| entry.is_metafile || entry.name.starts_with('$'));
            if listing.indexing_complete && metadata_visible {
                break;
            }
        }
        if listing.indexed_entries == 0 && !listing.indexing_complete {
            return Ok(());
        }
        let metadata_fields_present = listing
            .entries
            .iter()
            .any(|entry| entry.mft_reference.is_some() && entry.attr_bits.is_some())
            || inspect_source_entry(&source, &extend_path)
                .map(|entry| entry.mft_reference.is_some() && entry.attr_bits.is_some())
                .unwrap_or(false);
        assert!(
            metadata_fields_present,
            "expected NTFS root listing to include MFT-backed metadata fields"
        );

        Ok(())
    }

    #[test]
    fn read_ntfs_data_window_returns_partial_prefix_when_later_run_fails() -> Result<()> {
        let path = temp_test_file("ntfs-data-window-partial.bin");
        let mut file = File::create(&path)?;
        file.write_all(&(0u8..16).collect::<Vec<_>>())?;
        drop(file);

        let mut reader = RawReader::open(path.to_string_lossy().as_ref())?;
        let runs = vec![
            DataRun::Data { lcn: 0, length: 8 },
            DataRun::Data { lcn: 64, length: 8 },
        ];

        let bytes = read_ntfs_data_window(
            &mut reader,
            &runs,
            16,
            0,
            16,
            path.to_string_lossy().as_ref(),
        )?;

        assert_eq!(bytes, (0u8..8).collect::<Vec<_>>());
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn read_ntfs_data_window_preserves_sparse_regions() -> Result<()> {
        let path = temp_test_file("ntfs-data-window-sparse.bin");
        let mut file = File::create(&path)?;
        file.write_all(&(0u8..16).collect::<Vec<_>>())?;
        drop(file);

        let mut reader = RawReader::open(path.to_string_lossy().as_ref())?;
        let runs = vec![
            DataRun::Data { lcn: 0, length: 4 },
            DataRun::Sparse { length: 4 },
            DataRun::Data { lcn: 4, length: 4 },
        ];

        let bytes = read_ntfs_data_window(
            &mut reader,
            &runs,
            12,
            0,
            12,
            path.to_string_lossy().as_ref(),
        )?;

        assert_eq!(bytes, vec![0, 1, 2, 3, 0, 0, 0, 0, 4, 5, 6, 7]);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn volume_bitmap_covers_range_uses_sorted_extent_search() {
        let bitmap = VolumeBitmap {
            cluster_size: 4096,
            extents: vec![
                ByteRun {
                    offset: 0x1000,
                    length: 0x1000,
                    sparse: false,
                },
                ByteRun {
                    offset: 0x4000,
                    length: 0x3000,
                    sparse: false,
                },
                ByteRun {
                    offset: 0x9000,
                    length: 0x1000,
                    sparse: false,
                },
            ],
        };

        assert!(bitmap.covers_range(0x4000, 0x3000));
        assert!(bitmap.covers_range(0x5000, 0x0800));
        assert!(!bitmap.covers_range(0x3000, 0x1000));
        assert!(!bitmap.covers_range(0x6000, 0x2000));
        assert!(bitmap.covers_range(0x7000, 0));
    }

    #[test]
    fn source_entry_navigation_blocks_reparse_points_and_denied_dirs() {
        assert!(source_entry_can_navigate(
            true,
            0,
            SourceAccessState::Readable
        ));
        assert!(!source_entry_can_navigate(
            true,
            FILE_ATTRIBUTE_REPARSE_POINT.0,
            SourceAccessState::Readable
        ));
        assert!(!source_entry_can_navigate(
            true,
            0,
            SourceAccessState::Denied
        ));
        assert!(!source_entry_can_navigate(
            false,
            0,
            SourceAccessState::Readable
        ));
    }

    fn temp_test_file(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("files-{nonce}-{name}"))
    }
}
