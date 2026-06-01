mod artifact_intel;

use anyhow::{Result, anyhow};
use rss_case::CaseStore;
use rss_catalog::{CatalogCacheState, CatalogPhase, CatalogStore};
use rss_core::{
    ArchivePreviewPage, ArtifactKind, ArtifactPreviewRequest, ArtifactPreviewResponse,
    ArtifactRecord, ArtifactSignatureSummary, ArtifactSummary, AsyncJobState, AsyncJobStatus,
    BootstrapInfo, BrowseSourceRequest, ContentPreviewRequest, ContentPreviewResponse,
    ContentTarget, OriginType, PreviewChunkResponse, PreviewSessionInfo, PreviewSessionOpenRequest,
    RawEvidenceConfig, RawEvidenceMode, RawEvidenceRefinementPhase, RawEvidenceRefinementProgress,
    RawEvidenceRefinementRequest, RawEvidenceState, RecoveryRequest, RecoverySummary, ScanOptions,
    ScanProgress, ScanSnapshot, ScanSource, ScanStatus, ScanSummary, SourceAccessState,
    SourceCatalogCacheState, SourceCatalogPhase, SourceCatalogState, SourceCatalogStatus,
    SourceDirectoryListing, SourceEntry, SourceEntryClass, SourceEntryDetails, duration_seconds,
    new_scan_id, now_iso,
};
use rss_fs::{ScanExecution, refine_ntfs_raw_evidence, run_scan};
use rss_recovery::recover_selected;
use rss_report::{ReportBundle, export_reports};
use rss_security::{enter_background_mode_current_thread, security_context};
use rss_windows::{
    browse_source_directory, clear_browse_cache, discover_sources, inspect_source_entry,
};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use tauri::{AppHandle, Emitter, Runtime};
use tracing::error;

use crate::artifact_intel::{
    build_entry_preview, build_preview, inspect_entry_signature, inspect_signature,
    open_preview_session_for_target, read_archive_page, read_preview_chunk, session_info,
};

pub const SCAN_PROGRESS_EVENT: &str = "scan-progress";
pub const SOURCE_LOAD_PROGRESS_EVENT: &str = "source-load-progress";
pub const SOURCE_LOAD_COMPLETE_EVENT: &str = "source-load-complete";
pub const DELETED_BROWSE_PROGRESS_EVENT: &str = "deleted-browse-progress";
pub const DELETED_BROWSE_READY_EVENT: &str = "deleted-browse-ready";

#[derive(Debug, Clone)]
pub struct BridgeState {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    version: String,
    eula_path: String,
    sources: RwLock<Vec<ScanSource>>,
    sessions: Mutex<HashMap<String, ScanSession>>,
    source_catalog_statuses: Mutex<HashMap<String, SourceCatalogStatus>>,
    source_catalog_loads: Mutex<HashMap<String, CatalogLoadHandle>>,
    preview_jobs: Mutex<HashMap<String, PreviewJob>>,
    raw_evidence_jobs: Mutex<HashMap<String, RawEvidenceJob>>,
    preview_sessions: Mutex<HashMap<String, PreviewSession>>,
    entry_details_jobs: Mutex<HashMap<String, EntryDetailsJob>>,
    catalog_store: CatalogStore,
    case_store: CaseStore,
    is_elevated: bool,
}

#[derive(Debug, Clone)]
struct ScanSession {
    source: ScanSource,
    options: ScanOptions,
    progress: ScanProgress,
    results: Vec<ArtifactRecord>,
    deleted_browse_cache: Option<DeletedBrowseCache>,
    result_ids: HashSet<String>,
    warnings: Vec<String>,
    summary: Option<ScanSummary>,
    cancel_requested: bool,
}

#[derive(Debug, Clone)]
struct DeletedBrowseCache {
    root_path: String,
    direct_artifact_indices_by_folder: HashMap<String, Vec<usize>>,
    synthetic_folders: HashMap<String, DeletedFolderNode>,
    synthetic_folders_by_parent: HashMap<String, Vec<DeletedFolderNode>>,
    route_folders_by_parent: HashMap<String, Vec<DeletedFolderNode>>,
    subtree_deleted_counts: HashMap<String, usize>,
    unknown_artifact_indices: Vec<usize>,
    unknown_artifact_indices_by_extension: HashMap<String, Vec<usize>>,
    probable_artifact_indices: Vec<usize>,
    probable_artifact_indices_by_extension: HashMap<String, Vec<usize>>,
}

impl DeletedBrowseCache {
    fn has_deleted_child_folder(&self, path: &str) -> bool {
        let normalized_path = normalize_browser_path(path);
        self.route_folders_by_parent
            .get(&normalized_path)
            .is_some_and(|children| !children.is_empty())
    }

    fn direct_artifact_indices_for_folder(&self, normalized_path: &str) -> &[usize] {
        self.direct_artifact_indices_by_folder
            .get(normalized_path)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone)]
struct DeletedFolderNode {
    path: String,
    parent_path: Option<String>,
    name: String,
}

#[derive(Debug, Clone)]
struct DeletedArtifactLocator {
    result_index: usize,
    original_path: Option<String>,
    probable_path: Option<String>,
    name: String,
    extension: Option<String>,
    kind: ArtifactKind,
}

#[derive(Debug, Clone)]
struct RawEvidenceJob {
    cancel: Arc<AtomicBool>,
    progress: RawEvidenceRefinementProgress,
}

#[derive(Debug, Clone, Serialize)]
struct DeletedBrowseReadyEvent {
    scan_id: String,
    source_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeletedBrowseProgressEvent {
    scan_id: String,
    source_id: String,
    processed_artifacts: usize,
    total_artifacts: usize,
    progress_percent: f32,
}

#[derive(Debug, Clone)]
struct CatalogLoadHandle {
    cancel: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct PreviewJob {
    cancel: Arc<AtomicBool>,
    status: AsyncJobStatus,
    result: Option<ContentPreviewResponse>,
}

#[derive(Debug, Clone)]
struct PreviewSession {
    prepared: crate::artifact_intel::PreparedPreviewSession,
    target: crate::artifact_intel::PreviewSessionTarget,
}

#[derive(Debug, Clone)]
struct EntryDetailsJob {
    cancel: Arc<AtomicBool>,
    status: AsyncJobStatus,
    result: Option<SourceEntryDetails>,
}

impl BridgeState {
    pub fn new(version: &str, eula_path: &str) -> Result<Self> {
        let sources = discover_sources()?;
        let context = security_context().map_err(|err| anyhow!(err.to_string()))?;
        let catalog_store = CatalogStore::new()?;
        let mut catalog_statuses = HashMap::new();
        for source in &sources {
            catalog_statuses.insert(source.id.clone(), unloaded_catalog_status(&source.id));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                version: version.to_string(),
                eula_path: eula_path.to_string(),
                sources: RwLock::new(sources),
                sessions: Mutex::new(HashMap::new()),
                source_catalog_statuses: Mutex::new(catalog_statuses),
                source_catalog_loads: Mutex::new(HashMap::new()),
                preview_jobs: Mutex::new(HashMap::new()),
                raw_evidence_jobs: Mutex::new(HashMap::new()),
                preview_sessions: Mutex::new(HashMap::new()),
                entry_details_jobs: Mutex::new(HashMap::new()),
                catalog_store,
                case_store: CaseStore::new()?,
                is_elevated: context.is_elevated,
            }),
        })
    }

    pub fn bootstrap(&self) -> Result<BootstrapInfo> {
        let sources = self.list_sources()?;
        Ok(BootstrapInfo {
            app_name: "Files".to_string(),
            app_author: "Jumarf".to_string(),
            app_version: self.inner.version.clone(),
            license: "GPL-3.0-or-later".to_string(),
            eula_path: self.inner.eula_path.clone(),
            is_elevated: self.inner.is_elevated,
            source_count: sources.len(),
        })
    }

    pub fn list_sources(&self) -> Result<Vec<ScanSource>> {
        self.inner
            .sources
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| anyhow!("Failed to read sources"))
    }

    pub fn refresh_sources(&self) -> Result<Vec<ScanSource>> {
        let fresh = discover_sources()?;
        clear_browse_cache();
        *self
            .inner
            .sources
            .write()
            .map_err(|_| anyhow!("Failed to update sources"))? = fresh.clone();
        let mut statuses = self
            .inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to update source catalog statuses"))?;
        statuses.retain(|source_id, _| fresh.iter().any(|source| source.id == *source_id));
        for source in &fresh {
            statuses
                .entry(source.id.clone())
                .or_insert_with(|| unloaded_catalog_status(&source.id));
        }
        Ok(fresh)
    }

    pub fn source_catalog_status(&self, source_id: &str) -> Result<SourceCatalogStatus> {
        let statuses = self
            .inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to read source catalog statuses"))?;
        Ok(statuses
            .get(source_id)
            .cloned()
            .unwrap_or_else(|| unloaded_catalog_status(source_id)))
    }

    pub fn cancel_source_load(&self, load_id: &str) -> Result<()> {
        let loads = self
            .inner
            .source_catalog_loads
            .lock()
            .map_err(|_| anyhow!("Failed to cancel source load"))?;
        let handle = loads
            .get(load_id)
            .ok_or_else(|| anyhow!("Source load {load_id} not found"))?;
        handle.cancel.store(true, Ordering::Release);
        Ok(())
    }

    pub fn load_source_catalog<R: Runtime>(
        &self,
        app: AppHandle<R>,
        source_id: &str,
        force_rebuild: bool,
    ) -> Result<String> {
        let source = self
            .list_sources()?
            .into_iter()
            .find(|source| source.id == source_id)
            .ok_or_else(|| anyhow!("Unknown source id {}", source_id))?;

        let load_id = new_scan_id();
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut statuses = self
                .inner
                .source_catalog_statuses
                .lock()
                .map_err(|_| anyhow!("Failed to update source catalog status"))?;
            statuses.insert(
                source.id.clone(),
                SourceCatalogStatus {
                    state: SourceCatalogState::Loading,
                    source_id: source.id.clone(),
                    load_id: Some(load_id.clone()),
                    phase: Some(SourceCatalogPhase::OpeningVolume),
                    progress_percent: 0.0,
                    indexed_entries: 0,
                    total_estimated_entries: None,
                    cache_state: if force_rebuild {
                        SourceCatalogCacheState::Rebuild
                    } else {
                        SourceCatalogCacheState::Cold
                    },
                    started_at: Some(now_iso()),
                    updated_at: now_iso(),
                    error: None,
                    error_code: None,
                    error_detail: None,
                },
            );
        }
        {
            let mut loads = self
                .inner
                .source_catalog_loads
                .lock()
                .map_err(|_| anyhow!("Failed to register source load"))?;
            loads.insert(
                load_id.clone(),
                CatalogLoadHandle {
                    cancel: Arc::clone(&cancel),
                },
            );
        }

        let state = self.clone();
        let app_handle = app.clone();
        let load_id_clone = load_id.clone();
        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            let result = state.inner.catalog_store.load_or_build(
                &source,
                force_rebuild,
                |progress| {
                    state.emit_catalog_progress(&app_handle, &source.id, &load_id_clone, progress)
                },
                || cancel.load(Ordering::Acquire),
            );

            if let Err(error) = result {
                let message = error.to_string();
                let cancelled = message.contains("cancelled");
                let _ = state.finish_catalog_load(
                    &app_handle,
                    &source.id,
                    &load_id_clone,
                    if cancelled {
                        SourceCatalogState::Unloaded
                    } else {
                        SourceCatalogState::Failed
                    },
                    if cancelled { None } else { Some(message) },
                );
            } else {
                let _ = state.finish_catalog_load(
                    &app_handle,
                    &source.id,
                    &load_id_clone,
                    SourceCatalogState::Ready,
                    None,
                );
            }
        });

        Ok(load_id)
    }

    pub fn browse_source(&self, request: &BrowseSourceRequest) -> Result<SourceDirectoryListing> {
        let source = self
            .list_sources()?
            .into_iter()
            .find(|source| source.id == request.source_id)
            .ok_or_else(|| anyhow!("Unknown source id {}", request.source_id))?;

        let deleted_scan_id = self.latest_deleted_browse_scan_id(&source.id)?;
        if let Some(scan_id) = deleted_scan_id.as_deref()
            && let Some(requested_path) = request.path.as_deref()
            && (is_unknown_bucket_path_for_source(requested_path, &source.id)
                || is_probable_bucket_path_for_source(requested_path, &source.id))
        {
            let sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            if let Some(session) = sessions.get(scan_id)
                && let Some(deleted_cache) = session.deleted_browse_cache.as_ref()
            {
                if is_probable_bucket_path_for_source(requested_path, &source.id) {
                    return self.build_probable_deleted_listing(
                        &source,
                        deleted_cache,
                        &session.results,
                        request,
                    );
                }
                return self.build_unknown_deleted_listing(
                    &source,
                    deleted_cache,
                    &session.results,
                    request,
                );
            }
        }

        let live_listing = if source_uses_catalog(&source) {
            let status = self.source_catalog_status(&source.id)?;
            if status.state == SourceCatalogState::Ready {
                self.inner.catalog_store.browse_source(&source, request)
            } else {
                browse_source_directory(
                    &source,
                    request.path.as_deref(),
                    request.cursor.as_deref(),
                    request.limit,
                    request.directories_only.unwrap_or(false),
                )
            }
        } else {
            browse_source_directory(
                &source,
                request.path.as_deref(),
                request.cursor.as_deref(),
                request.limit,
                request.directories_only.unwrap_or(false),
            )
        };

        match live_listing {
            Ok(mut listing) => {
                if let Some(scan_id) = deleted_scan_id.as_deref() {
                    let sessions = self
                        .inner
                        .sessions
                        .lock()
                        .map_err(|_| anyhow!("Failed to acquire session lock"))?;
                    if let Some(session) = sessions.get(scan_id)
                        && let Some(deleted_cache) = session.deleted_browse_cache.as_ref()
                    {
                        self.augment_listing_with_deleted(
                            &source,
                            deleted_cache,
                            &session.results,
                            request,
                            &mut listing,
                        )?;
                    }
                }
                Ok(listing)
            }
            Err(error) => {
                if let Some(scan_id) = deleted_scan_id.as_deref()
                    && let Some(requested_path) = request.path.as_deref()
                    && is_path_not_found_error(&error)
                {
                    let sessions = self
                        .inner
                        .sessions
                        .lock()
                        .map_err(|_| anyhow!("Failed to acquire session lock"))?;
                    if let Some(session) = sessions.get(scan_id)
                        && let Some(deleted_cache) = session.deleted_browse_cache.as_ref()
                        && deleted_cache
                            .synthetic_folders
                            .contains_key(&normalize_browser_path(requested_path))
                    {
                        return self.build_synthetic_deleted_listing(
                            &source,
                            deleted_cache,
                            &session.results,
                            request,
                        );
                    }
                }
                Err(error)
            }
        }
    }

    fn latest_deleted_browse_scan_id(&self, source_id: &str) -> Result<Option<String>> {
        let sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;

        Ok(sessions
            .iter()
            .filter(|(_, session)| {
                session.source.id == source_id
                    && matches!(
                        session.progress.status,
                        ScanStatus::Completed
                            | ScanStatus::CompletedWithWarnings
                            | ScanStatus::Cancelled
                    )
                    && session.deleted_browse_cache.is_some()
            })
            .max_by(|left, right| left.1.progress.updated_at.cmp(&right.1.progress.updated_at))
            .map(|(scan_id, _)| scan_id.clone()))
    }

    fn deleted_artifact_page(
        &self,
        results: &[ArtifactRecord],
        indices: &[usize],
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<ArtifactSummary>, Option<String>)> {
        let start = offset.min(indices.len());
        let end = start.saturating_add(limit).min(indices.len());
        let page = indices[start..end]
            .iter()
            .filter_map(|index| results.get(*index))
            .map(ArtifactRecord::to_summary)
            .collect::<Vec<_>>();
        Ok((page, (end < indices.len()).then(|| end.to_string())))
    }

    fn build_unknown_deleted_listing(
        &self,
        source: &ScanSource,
        deleted_cache: &DeletedBrowseCache,
        results: &[ArtifactRecord],
        request: &BrowseSourceRequest,
    ) -> Result<SourceDirectoryListing> {
        let page_size = request.limit.unwrap_or(256).clamp(1, 1024);
        let deleted_offset = request
            .deleted_cursor
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let indices = deleted_indices_for_request(
            results,
            &deleted_cache.unknown_artifact_indices,
            &deleted_cache.unknown_artifact_indices_by_extension,
            request,
        );
        let (deleted_artifacts, deleted_artifact_next_cursor) =
            self.deleted_artifact_page(results, indices.as_ref(), deleted_offset, page_size)?;
        Ok(SourceDirectoryListing {
            source_id: source.id.clone(),
            root_path: deleted_cache.root_path.clone(),
            path: unknown_bucket_path_for_source(&source.id),
            parent_path: Some(deleted_cache.root_path.clone()),
            entries: Vec::new(),
            deleted_artifacts,
            total_entry_count: 0,
            deleted_artifact_count: indices.len(),
            next_cursor: None,
            deleted_artifact_next_cursor,
            indexing_complete: true,
            indexed_entries: 0,
            total_estimated_entries: Some(0),
            index_generation: 1,
            deleted_subtree_count: indices.len(),
        })
    }

    fn build_probable_deleted_listing(
        &self,
        source: &ScanSource,
        deleted_cache: &DeletedBrowseCache,
        results: &[ArtifactRecord],
        request: &BrowseSourceRequest,
    ) -> Result<SourceDirectoryListing> {
        let page_size = request.limit.unwrap_or(256).clamp(1, 1024);
        let deleted_offset = request
            .deleted_cursor
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let indices = deleted_indices_for_request(
            results,
            &deleted_cache.probable_artifact_indices,
            &deleted_cache.probable_artifact_indices_by_extension,
            request,
        );
        let (deleted_artifacts, deleted_artifact_next_cursor) =
            self.deleted_artifact_page(results, indices.as_ref(), deleted_offset, page_size)?;
        Ok(SourceDirectoryListing {
            source_id: source.id.clone(),
            root_path: deleted_cache.root_path.clone(),
            path: probable_bucket_path_for_source(&source.id),
            parent_path: Some(deleted_cache.root_path.clone()),
            entries: Vec::new(),
            deleted_artifacts,
            total_entry_count: 0,
            deleted_artifact_count: indices.len(),
            next_cursor: None,
            deleted_artifact_next_cursor,
            indexing_complete: true,
            indexed_entries: 0,
            total_estimated_entries: Some(0),
            index_generation: 1,
            deleted_subtree_count: indices.len(),
        })
    }

    fn build_synthetic_deleted_listing(
        &self,
        source: &ScanSource,
        deleted_cache: &DeletedBrowseCache,
        results: &[ArtifactRecord],
        request: &BrowseSourceRequest,
    ) -> Result<SourceDirectoryListing> {
        let requested_path = request
            .path
            .as_deref()
            .ok_or_else(|| anyhow!("Synthetic folder request is missing a path"))?;
        let normalized_path = normalize_browser_path(requested_path);
        let folder = deleted_cache
            .synthetic_folders
            .get(&normalized_path)
            .ok_or_else(|| anyhow!("Synthetic folder {} was not found", requested_path))?;
        let directories_only = request.directories_only.unwrap_or(false);
        let child_entries = deleted_cache
            .route_folders_by_parent
            .get(&normalized_path)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|child| {
                create_deleted_folder_entry(
                    deleted_cache,
                    &child,
                    deleted_cache
                        .subtree_deleted_counts
                        .get(&normalize_browser_path(&child.path))
                        .copied()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let direct_indices = if directories_only {
            &[][..]
        } else {
            deleted_cache.direct_artifact_indices_for_folder(&normalized_path)
        };
        let page_size = request.limit.unwrap_or(256).clamp(1, 1024);
        let deleted_offset = request
            .deleted_cursor
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let empty_extension_index = HashMap::new();
        let filtered_direct_indices =
            deleted_indices_for_request(results, direct_indices, &empty_extension_index, request);
        let (deleted_artifacts, deleted_artifact_next_cursor) = self.deleted_artifact_page(
            results,
            filtered_direct_indices.as_ref(),
            deleted_offset,
            page_size,
        )?;
        let entry_count = child_entries.len();
        Ok(SourceDirectoryListing {
            source_id: source.id.clone(),
            root_path: deleted_cache.root_path.clone(),
            path: folder.path.clone(),
            parent_path: folder.parent_path.clone(),
            entries: child_entries,
            deleted_artifacts,
            total_entry_count: entry_count,
            deleted_artifact_count: filtered_direct_indices.len(),
            next_cursor: None,
            deleted_artifact_next_cursor,
            indexing_complete: true,
            indexed_entries: entry_count as u64,
            total_estimated_entries: Some(entry_count as u64),
            index_generation: 1,
            deleted_subtree_count: deleted_cache
                .subtree_deleted_counts
                .get(&normalized_path)
                .copied()
                .unwrap_or_default(),
        })
    }

    fn augment_listing_with_deleted(
        &self,
        source: &ScanSource,
        deleted_cache: &DeletedBrowseCache,
        results: &[ArtifactRecord],
        request: &BrowseSourceRequest,
        listing: &mut SourceDirectoryListing,
    ) -> Result<()> {
        let normalized_path = normalize_browser_path(&listing.path);
        let page_size = request.limit.unwrap_or(256).clamp(1, 1024);
        let directories_only = request.directories_only.unwrap_or(false);
        let direct_indices = if directories_only {
            &[][..]
        } else {
            deleted_cache.direct_artifact_indices_for_folder(&normalized_path)
        };
        let deleted_offset = request
            .deleted_cursor
            .as_deref()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let empty_extension_index = HashMap::new();
        let filtered_direct_indices =
            deleted_indices_for_request(results, direct_indices, &empty_extension_index, request);
        let (deleted_artifacts, deleted_artifact_next_cursor) = self.deleted_artifact_page(
            results,
            filtered_direct_indices.as_ref(),
            deleted_offset,
            page_size,
        )?;

        for entry in &mut listing.entries {
            apply_deleted_hits_to_entry(entry, deleted_cache, source);
        }

        let mut represented_folder_paths = listing
            .entries
            .iter()
            .filter(|entry| entry_represents_deleted_folder_route(entry))
            .map(|entry| normalize_browser_path(&entry.path))
            .collect::<HashSet<_>>();
        let mut synthetic_entries = deleted_cache
            .route_folders_by_parent
            .get(&normalized_path)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|folder| represented_folder_paths.insert(normalize_browser_path(&folder.path)))
            .map(|folder| {
                create_deleted_folder_entry(
                    deleted_cache,
                    &folder,
                    deleted_cache
                        .subtree_deleted_counts
                        .get(&normalize_browser_path(&folder.path))
                        .copied()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();

        if listing.path == deleted_cache.root_path
            && !deleted_cache.unknown_artifact_indices.is_empty()
        {
            let unknown_entry = create_unknown_bucket_entry(source, deleted_cache);
            if represented_folder_paths.insert(normalize_browser_path(&unknown_entry.path)) {
                synthetic_entries.push(unknown_entry);
            }
        }
        if listing.path == deleted_cache.root_path
            && !deleted_cache.probable_artifact_indices.is_empty()
        {
            let probable_entry = create_probable_bucket_entry(source, deleted_cache);
            if represented_folder_paths.insert(normalize_browser_path(&probable_entry.path)) {
                synthetic_entries.push(probable_entry);
            }
        }

        listing.entries.extend(synthetic_entries);
        listing.deleted_artifacts = deleted_artifacts;
        listing.deleted_artifact_count = filtered_direct_indices.len();
        listing.deleted_artifact_next_cursor = deleted_artifact_next_cursor;
        listing.deleted_subtree_count = deleted_cache
            .subtree_deleted_counts
            .get(&normalized_path)
            .copied()
            .unwrap_or_default()
            + if listing.path == deleted_cache.root_path {
                deleted_cache.unknown_artifact_indices.len()
            } else {
                0
            };
        Ok(())
    }

    fn compute_entry_details(&self, source_id: &str, path: &str) -> Result<SourceEntryDetails> {
        let source = self
            .list_sources()?
            .into_iter()
            .find(|source| source.id == source_id)
            .ok_or_else(|| anyhow!("Unknown source id {}", source_id))?;
        let entry = if source_uses_catalog(&source) {
            let status = self.source_catalog_status(&source.id)?;
            if status.state == SourceCatalogState::Ready {
                self.inner.catalog_store.entry_details(&source, path)?
            } else {
                inspect_source_entry(&source, path)?
            }
        } else {
            inspect_source_entry(&source, path)?
        };
        let mut notes = Vec::new();
        if entry.access_state == rss_core::SourceAccessState::Denied {
            notes.push(
                "This item is visible in metadata, but Windows denied direct enumeration or file reads."
                    .to_string(),
            );
        } else if entry.is_metafile {
            notes.push(
                "This entry originates from NTFS metadata and is shown even when it is not visible through standard Win32 directory enumeration."
                    .to_string(),
            );
        } else {
            notes.push("Live entry metadata loaded from the selected source.".to_string());
        }
        let mut summary = Vec::new();
        if let Some(attr_bits) = entry.attr_bits {
            summary.push(rss_core::PreviewFact {
                label: "ATTR".to_string(),
                value: format!("0x{attr_bits:04x}"),
            });
        }
        if !entry.attributes.is_empty() {
            summary.push(rss_core::PreviewFact {
                label: "Attributes".to_string(),
                value: entry.attributes.join(", "),
            });
        }
        Ok(SourceEntryDetails {
            entry,
            notes,
            summary,
        })
    }

    pub fn entry_details(&self, source_id: &str, path: &str) -> Result<SourceEntryDetails> {
        self.compute_entry_details(source_id, path)
    }

    pub fn start_scan<R: Runtime>(
        &self,
        app: AppHandle<R>,
        options: ScanOptions,
    ) -> Result<String> {
        let source = self
            .list_sources()?
            .into_iter()
            .find(|source| source.id == options.source_id)
            .ok_or_else(|| anyhow!("Unknown source id {}", options.source_id))?;

        let scan_id = new_scan_id();
        let progress = ScanProgress {
            scan_id: scan_id.clone(),
            status: ScanStatus::Running,
            phase: rss_core::ScanPhase::Preparing,
            stage: "queued".to_string(),
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
            target_sla_seconds: if options.mode == rss_core::ScanMode::Fast {
                120
            } else {
                600
            },
            raw_evidence_state: RawEvidenceState::NotStarted,
            message: format!("Queued scan for {}", source.display_name),
            stage_timing_ms: std::collections::BTreeMap::new(),
            started_at: now_iso(),
            last_progress_at: now_iso(),
            updated_at: now_iso(),
        };

        self.inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?
            .insert(
                scan_id.clone(),
                ScanSession {
                    source: source.clone(),
                    options: options.clone(),
                    progress: progress.clone(),
                    results: Vec::new(),
                    deleted_browse_cache: None,
                    result_ids: HashSet::new(),
                    warnings: Vec::new(),
                    summary: None,
                    cancel_requested: false,
                },
            );

        let _ = app.emit(SCAN_PROGRESS_EVENT, &progress);

        let state = self.clone();
        let scan_id_clone = scan_id.clone();
        let app_handle = app.clone();
        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            let result = catch_unwind(AssertUnwindSafe(|| {
                run_scan(
                    &scan_id_clone,
                    &source,
                    &options,
                    |progress| {
                        let _ = state.update_progress(&app_handle, &scan_id_clone, progress);
                    },
                    |results| {
                        let _ = state.update_results(&app_handle, &scan_id_clone, results);
                    },
                    || state.is_cancel_requested(&scan_id_clone).unwrap_or(false),
                )
            }));

            match result {
                Ok(Ok(execution)) => {
                    if let Err(err) = state.complete_scan(&app_handle, &scan_id_clone, execution) {
                        error!("Failed to finalize scan {}: {err}", scan_id_clone);
                    }
                }
                Ok(Err(err)) => {
                    let _ = state.finalize_scan_with_warning(
                        &app_handle,
                        &scan_id_clone,
                        err.to_string(),
                    );
                }
                Err(_) => {
                    let _ = state.finalize_scan_with_warning(
                        &app_handle,
                        &scan_id_clone,
                        "Scan worker panicked while reading disk".to_string(),
                    );
                }
            }
        });

        Ok(scan_id)
    }

    pub fn stop_scan(&self, scan_id: &str) -> Result<()> {
        let mut sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;
        let session = sessions
            .get_mut(scan_id)
            .ok_or_else(|| anyhow!("Scan {} not found", scan_id))?;

        if matches!(
            session.progress.status,
            ScanStatus::Completed
                | ScanStatus::CompletedWithWarnings
                | ScanStatus::Failed
                | ScanStatus::Cancelled
        ) {
            return Ok(());
        }

        session.cancel_requested = true;
        session.progress.message = "Stopping scan after the current read batch".to_string();
        session.progress.updated_at = now_iso();
        Ok(())
    }

    pub fn scan_progress(&self, scan_id: &str) -> Result<ScanProgress> {
        self.inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?
            .get(scan_id)
            .map(|session| session.progress.clone())
            .ok_or_else(|| anyhow!("Scan {} not found", scan_id))
    }

    pub fn start_raw_evidence_refinement<R: Runtime>(
        &self,
        app: AppHandle<R>,
        request: RawEvidenceRefinementRequest,
    ) -> Result<String> {
        let job_id = new_scan_id();
        let started_at = now_iso();
        let (source, mut results) = {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            let session = sessions
                .get_mut(&request.scan_id)
                .ok_or_else(|| anyhow!("Scan {} not found", request.scan_id))?;
            if session.source.id != request.source_id {
                return Err(anyhow!(
                    "Scan {} belongs to source {}, not {}",
                    request.scan_id,
                    session.source.id,
                    request.source_id
                ));
            }
            if !session.progress.status.is_success() {
                return Err(anyhow!("Raw evidence refinement requires a completed scan"));
            }
            if session.source.filesystem != rss_core::FileSystemKind::Ntfs {
                return Err(anyhow!(
                    "Raw evidence refinement is only available for NTFS sources"
                ));
            }
            if matches!(
                session.progress.raw_evidence_state,
                RawEvidenceState::Running
            ) {
                return Err(anyhow!(
                    "Raw evidence refinement is already running for this scan"
                ));
            }
            session.progress.raw_evidence_state = RawEvidenceState::Running;
            session.progress.phase = rss_core::ScanPhase::RefiningRawEvidence;
            session.progress.stage = "refining_raw_evidence".to_string();
            session.progress.message = "Refining paths from NTFS raw evidence".to_string();
            session.progress.updated_at = now_iso();
            session.progress.last_progress_at = session.progress.updated_at.clone();
            let _ = app.emit(SCAN_PROGRESS_EVENT, &session.progress);
            (session.source.clone(), session.results.clone())
        };

        let progress = RawEvidenceRefinementProgress {
            job_id: job_id.clone(),
            scan_id: request.scan_id.clone(),
            source_id: request.source_id.clone(),
            state: AsyncJobState::Running,
            phase: RawEvidenceRefinementPhase::Queued,
            progress_percent: 0.0,
            processed_units: 0,
            total_units: None,
            message: "Queued NTFS raw evidence refinement".to_string(),
            warnings: Vec::new(),
            started_at,
            updated_at: now_iso(),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.inner
            .raw_evidence_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to acquire raw evidence job lock"))?
            .insert(
                job_id.clone(),
                RawEvidenceJob {
                    cancel: cancel.clone(),
                    progress,
                },
            );

        let state = self.clone();
        let app_handle = app.clone();
        let scan_id = request.scan_id.clone();
        let source_id = request.source_id.clone();
        let job_id_for_thread = job_id.clone();
        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            let mut warnings = Vec::new();
            let config = RawEvidenceConfig {
                mode: RawEvidenceMode::FullExhaustive,
                i30_enabled: true,
                usn_enabled: true,
                raw_usn_fallback: true,
                emit_initial_results_before_raw: true,
            };

            let refine_result = catch_unwind(AssertUnwindSafe(|| {
                refine_ntfs_raw_evidence(
                    &scan_id,
                    &source,
                    &mut results,
                    &mut warnings,
                    &config,
                    |stage, percent, processed_units, total_units| {
                        state.update_raw_evidence_progress(
                            &job_id_for_thread,
                            AsyncJobState::Running,
                            raw_evidence_phase_from_stage(stage),
                            percent * 100.0,
                            processed_units,
                            total_units,
                            raw_evidence_stage_message(stage),
                            Vec::new(),
                        );
                        !cancel.load(Ordering::Relaxed)
                    },
                    || cancel.load(Ordering::Relaxed),
                )
            }));

            match refine_result {
                Ok(Ok(completed)) if completed && !cancel.load(Ordering::Relaxed) => {
                    let has_warnings = !warnings.is_empty();
                    let final_state = if has_warnings {
                        RawEvidenceState::CompletedWithWarnings
                    } else {
                        RawEvidenceState::Completed
                    };
                    if let Err(err) = state.complete_raw_evidence_refinement(
                        &app_handle,
                        &job_id_for_thread,
                        &scan_id,
                        &source_id,
                        source,
                        results,
                        final_state,
                        warnings,
                    ) {
                        error!("Failed to complete raw evidence job {job_id_for_thread}: {err}");
                    }
                }
                Ok(Ok(_)) => {
                    state.finish_raw_evidence_job(
                        &app_handle,
                        &job_id_for_thread,
                        &scan_id,
                        RawEvidenceState::NotStarted,
                        AsyncJobState::Cancelled,
                        "Raw evidence refinement cancelled".to_string(),
                        warnings,
                    );
                }
                Ok(Err(err)) => {
                    warnings.push(format!("Raw evidence refinement skipped: {err}"));
                    state.finish_raw_evidence_job(
                        &app_handle,
                        &job_id_for_thread,
                        &scan_id,
                        RawEvidenceState::CompletedWithWarnings,
                        AsyncJobState::Failed,
                        "Raw evidence refinement completed with warnings".to_string(),
                        warnings,
                    );
                }
                Err(_) => {
                    warnings.push(
                        "Raw evidence worker panicked while reading NTFS evidence".to_string(),
                    );
                    state.finish_raw_evidence_job(
                        &app_handle,
                        &job_id_for_thread,
                        &scan_id,
                        RawEvidenceState::CompletedWithWarnings,
                        AsyncJobState::Failed,
                        "Raw evidence refinement completed with warnings".to_string(),
                        warnings,
                    );
                }
            }
        });

        Ok(job_id)
    }

    pub fn raw_evidence_progress(&self, job_id: &str) -> Result<RawEvidenceRefinementProgress> {
        self.inner
            .raw_evidence_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to acquire raw evidence job lock"))?
            .get(job_id)
            .map(|job| job.progress.clone())
            .ok_or_else(|| anyhow!("Raw evidence job {} not found", job_id))
    }

    pub fn cancel_raw_evidence_refinement(&self, job_id: &str) -> Result<()> {
        let mut jobs = self
            .inner
            .raw_evidence_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to acquire raw evidence job lock"))?;
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| anyhow!("Raw evidence job {} not found", job_id))?;
        job.cancel.store(true, Ordering::Relaxed);
        job.progress.state = AsyncJobState::Cancelled;
        job.progress.message = "Cancelling raw evidence refinement".to_string();
        job.progress.updated_at = now_iso();
        Ok(())
    }

    pub fn scan_results(&self, scan_id: &str) -> Result<Vec<ArtifactSummary>> {
        self.inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?
            .get(scan_id)
            .map(|session| {
                session
                    .results
                    .iter()
                    .map(ArtifactRecord::to_summary)
                    .collect()
            })
            .ok_or_else(|| anyhow!("Scan {} not found", scan_id))
    }

    pub fn artifact_details(&self, scan_id: &str, artifact_id: &str) -> Result<ArtifactRecord> {
        self.inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?
            .get(scan_id)
            .and_then(|session| {
                session
                    .results
                    .iter()
                    .find(|artifact| artifact.id == artifact_id)
                    .cloned()
            })
            .ok_or_else(|| anyhow!("Artifact {} was not found in scan {}", artifact_id, scan_id))
    }

    pub fn artifact_signature(
        &self,
        scan_id: &str,
        artifact_id: &str,
    ) -> Result<ArtifactSignatureSummary> {
        let artifact = self.artifact_details(scan_id, artifact_id)?;
        inspect_signature(&artifact)
    }

    pub fn artifact_preview(
        &self,
        request: &ArtifactPreviewRequest,
    ) -> Result<ArtifactPreviewResponse> {
        let artifact = self.artifact_details(&request.scan_id, &request.artifact_id)?;
        build_preview(&artifact, request)
    }

    fn compute_content_signature(
        &self,
        target: &ContentTarget,
    ) -> Result<ArtifactSignatureSummary> {
        match target {
            ContentTarget::Artifact {
                scan_id,
                artifact_id,
            } => self.artifact_signature(scan_id, artifact_id),
            ContentTarget::Entry { source_id, path } => {
                let details = self.compute_entry_details(source_id, path)?;
                let source = self
                    .list_sources()?
                    .into_iter()
                    .find(|source| source.id == *source_id)
                    .ok_or_else(|| anyhow!("Unknown source id {}", source_id))?;
                inspect_entry_signature(&source, &details.entry)
            }
        }
    }

    pub fn content_signature(&self, target: &ContentTarget) -> Result<ArtifactSignatureSummary> {
        self.compute_content_signature(target)
    }

    fn compute_content_preview(
        &self,
        request: &ContentPreviewRequest,
    ) -> Result<ContentPreviewResponse> {
        match &request.target {
            ContentTarget::Artifact {
                scan_id,
                artifact_id,
            } => {
                let artifact = self.artifact_details(scan_id, artifact_id)?;
                let preview = build_preview(
                    &artifact,
                    &ArtifactPreviewRequest {
                        scan_id: scan_id.clone(),
                        artifact_id: artifact_id.clone(),
                        mode: request.mode,
                        offset: request.offset,
                        length: request.length,
                        max_entries: request.max_entries,
                    },
                )?;
                Ok(ContentPreviewResponse {
                    target_key: artifact.id.clone(),
                    requested_mode: preview.requested_mode,
                    resolved_mode: preview.resolved_mode,
                    offset: preview.offset,
                    length: preview.length,
                    total_size: preview.total_size,
                    has_more: preview.has_more,
                    warnings: preview.warnings,
                    summary: preview.summary,
                    text_excerpt: preview.text_excerpt,
                    hex_rows: preview.hex_rows,
                    archive_entry_count: preview.archive_entry_count,
                    archive_entries_truncated: preview.archive_entries_truncated,
                    archive_entries: preview.archive_entries,
                })
            }
            ContentTarget::Entry { source_id, path } => {
                let entry = if let Some(entry) = request.entry_hint.clone() {
                    entry
                } else {
                    self.compute_entry_details(source_id, path)?.entry
                };
                let source = self
                    .list_sources()?
                    .into_iter()
                    .find(|source| source.id == *source_id)
                    .ok_or_else(|| anyhow!("Unknown source id {}", source_id))?;
                build_entry_preview(&source, &entry, request)
            }
        }
    }

    pub fn content_preview(
        &self,
        request: &ContentPreviewRequest,
    ) -> Result<ContentPreviewResponse> {
        self.compute_content_preview(request)
    }

    pub fn open_preview_session(
        &self,
        request: &PreviewSessionOpenRequest,
    ) -> Result<PreviewSessionInfo> {
        let (prepared, target) = open_preview_session_for_target(
            |source_id| {
                self.list_sources()?
                    .into_iter()
                    .find(|source| source.id == source_id)
                    .ok_or_else(|| anyhow!("Unknown source id {}", source_id))
            },
            |source, path| {
                if source_uses_catalog(source) {
                    let status = self.source_catalog_status(&source.id)?;
                    if status.state == SourceCatalogState::Ready {
                        return self.inner.catalog_store.entry_details(source, path);
                    }
                }
                inspect_source_entry(source, path)
            },
            |scan_id, artifact_id| self.artifact_details(scan_id, artifact_id),
            request,
        )?;
        let session_id = new_scan_id();
        let info = session_info(&session_id, &prepared);
        self.inner
            .preview_sessions
            .lock()
            .map_err(|_| anyhow!("Failed to store preview session"))?
            .insert(session_id, PreviewSession { prepared, target });
        Ok(info)
    }

    pub fn read_preview_chunk(
        &self,
        session_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<PreviewChunkResponse> {
        let sessions = self
            .inner
            .preview_sessions
            .lock()
            .map_err(|_| anyhow!("Failed to read preview sessions"))?;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Preview session {} not found", session_id))?;
        read_preview_chunk(
            session_id,
            &session.target,
            &session.prepared,
            offset,
            length,
        )
    }

    pub fn read_archive_page(
        &self,
        session_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<ArchivePreviewPage> {
        let sessions = self
            .inner
            .preview_sessions
            .lock()
            .map_err(|_| anyhow!("Failed to read preview sessions"))?;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Preview session {} not found", session_id))?;
        let listing = session.prepared.archive_listing.as_ref().ok_or_else(|| {
            anyhow!(
                "Preview session {} does not expose archive entries",
                session_id
            )
        })?;
        Ok(read_archive_page(
            session_id,
            &session.prepared.target_key,
            listing,
            offset,
            limit,
            &session.prepared.warnings,
        ))
    }

    pub fn close_preview_session(&self, session_id: &str) -> Result<()> {
        self.inner
            .preview_sessions
            .lock()
            .map_err(|_| anyhow!("Failed to close preview session"))?
            .remove(session_id);
        Ok(())
    }

    pub fn start_entry_details_job(&self, source_id: &str, path: &str) -> Result<String> {
        let job_id = new_scan_id();
        let cancel = Arc::new(AtomicBool::new(false));
        let source_id = source_id.to_string();
        let path = path.to_string();
        let state = self.clone();
        let job_id_clone = job_id.clone();
        self.inner
            .entry_details_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to register entry details job"))?
            .insert(
                job_id.clone(),
                EntryDetailsJob {
                    cancel: Arc::clone(&cancel),
                    status: new_job_status(&job_id),
                    result: None,
                },
            );

        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            state.set_entry_details_job_state(&job_id_clone, AsyncJobState::Running, None);
            let result = catch_unwind(AssertUnwindSafe(|| {
                state.compute_entry_details(&source_id, &path)
            }))
            .map_err(|_| anyhow!("Entry details job panicked while reading metadata"))
            .and_then(|result| result);
            state.finish_entry_details_job(&job_id_clone, result);
        });

        Ok(job_id)
    }

    pub fn entry_details_job_status(&self, job_id: &str) -> Result<AsyncJobStatus> {
        self.inner
            .entry_details_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to read entry details jobs"))?
            .get(job_id)
            .map(|job| job.status.clone())
            .ok_or_else(|| anyhow!("Entry details job {} not found", job_id))
    }

    pub fn entry_details_job_result(&self, job_id: &str) -> Result<SourceEntryDetails> {
        let jobs = self
            .inner
            .entry_details_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to read entry details jobs"))?;
        let job = jobs
            .get(job_id)
            .ok_or_else(|| anyhow!("Entry details job {} not found", job_id))?;
        match job.status.state {
            AsyncJobState::Completed => job
                .result
                .clone()
                .ok_or_else(|| anyhow!("Entry details job {} has no result", job_id)),
            AsyncJobState::Failed => {
                Err(anyhow!(job.status.error.clone().unwrap_or_else(
                    || format!("Entry details job {} failed", job_id)
                )))
            }
            AsyncJobState::Cancelled => Err(anyhow!("Entry details job {} was cancelled", job_id)),
            AsyncJobState::Pending | AsyncJobState::Running => Err(anyhow!("job_not_ready")),
        }
    }

    pub fn cancel_entry_details_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self
            .inner
            .entry_details_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to cancel entry details job"))?;
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| anyhow!("Entry details job {} not found", job_id))?;
        job.cancel.store(true, Ordering::Release);
        if matches!(
            job.status.state,
            AsyncJobState::Pending | AsyncJobState::Running
        ) {
            transition_job_status(&mut job.status, AsyncJobState::Cancelled, None);
            job.result = None;
        }
        Ok(())
    }

    pub fn start_preview_job(&self, request: &ContentPreviewRequest) -> Result<String> {
        let job_id = new_scan_id();
        let cancel = Arc::new(AtomicBool::new(false));
        let request = request.clone();
        let state = self.clone();
        let job_id_clone = job_id.clone();
        self.inner
            .preview_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to register preview job"))?
            .insert(
                job_id.clone(),
                PreviewJob {
                    cancel: Arc::clone(&cancel),
                    status: new_job_status(&job_id),
                    result: None,
                },
            );

        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            state.set_preview_job_state(&job_id_clone, AsyncJobState::Running, None);
            let result = catch_unwind(AssertUnwindSafe(|| state.compute_content_preview(&request)))
                .map_err(|_| anyhow!("Preview job panicked while reading content"))
                .and_then(|result| result);
            state.finish_preview_job(&job_id_clone, result);
        });

        Ok(job_id)
    }

    pub fn preview_job_status(&self, job_id: &str) -> Result<AsyncJobStatus> {
        self.inner
            .preview_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to read preview jobs"))?
            .get(job_id)
            .map(|job| job.status.clone())
            .ok_or_else(|| anyhow!("Preview job {} not found", job_id))
    }

    pub fn preview_job_result(&self, job_id: &str) -> Result<ContentPreviewResponse> {
        let jobs = self
            .inner
            .preview_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to read preview jobs"))?;
        let job = jobs
            .get(job_id)
            .ok_or_else(|| anyhow!("Preview job {} not found", job_id))?;
        match job.status.state {
            AsyncJobState::Completed => job
                .result
                .clone()
                .ok_or_else(|| anyhow!("Preview job {} has no result", job_id)),
            AsyncJobState::Failed => {
                Err(anyhow!(job.status.error.clone().unwrap_or_else(
                    || format!("Preview job {} failed", job_id)
                )))
            }
            AsyncJobState::Cancelled => Err(anyhow!("Preview job {} was cancelled", job_id)),
            AsyncJobState::Pending | AsyncJobState::Running => Err(anyhow!("job_not_ready")),
        }
    }

    pub fn cancel_preview_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self
            .inner
            .preview_jobs
            .lock()
            .map_err(|_| anyhow!("Failed to cancel preview job"))?;
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| anyhow!("Preview job {} not found", job_id))?;
        job.cancel.store(true, Ordering::Release);
        if matches!(
            job.status.state,
            AsyncJobState::Pending | AsyncJobState::Running
        ) {
            transition_job_status(&mut job.status, AsyncJobState::Cancelled, None);
            job.result = None;
        }
        Ok(())
    }

    pub fn scan_snapshot(&self, scan_id: &str) -> Result<ScanSnapshot> {
        let sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;
        let session = sessions
            .get(scan_id)
            .ok_or_else(|| anyhow!("Scan {} not found", scan_id))?;
        let summary = session
            .summary
            .clone()
            .ok_or_else(|| anyhow!("Scan {} has not completed yet", scan_id))?;

        Ok(ScanSnapshot {
            summary,
            source: session.source.clone(),
            progress: session.progress.clone(),
            results: session.results.clone(),
        })
    }

    pub fn recent_scans(&self) -> Result<Vec<ScanSnapshot>> {
        self.inner.case_store.list_snapshots()
    }

    pub fn recover(&self, request: RecoveryRequest) -> Result<RecoverySummary> {
        let sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;
        let session = sessions
            .get(&request.scan_id)
            .ok_or_else(|| anyhow!("Scan {} not found", request.scan_id))?;
        let artifacts = session
            .results
            .iter()
            .filter(|artifact| request.artifact_ids.contains(&artifact.id))
            .cloned()
            .collect::<Vec<_>>();
        if artifacts.is_empty() {
            return Err(anyhow!("No matching artifacts selected for recovery"));
        }
        recover_selected(&artifacts, &request)
    }

    pub fn export(&self, scan_id: &str, destination: &str) -> Result<ReportBundle> {
        let snapshot = self.scan_snapshot(scan_id)?;
        export_reports(&snapshot, destination)
    }

    fn emit_catalog_progress<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        source_id: &str,
        load_id: &str,
        progress: rss_catalog::CatalogProgress,
    ) -> Result<()> {
        let started_at = self
            .inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to read source catalog status"))?
            .get(source_id)
            .and_then(|status| status.started_at.clone());
        let status = SourceCatalogStatus {
            state: SourceCatalogState::Loading,
            source_id: source_id.to_string(),
            load_id: Some(load_id.to_string()),
            phase: Some(map_catalog_phase(progress.phase)),
            progress_percent: progress.progress_percent,
            indexed_entries: progress.indexed_entries,
            total_estimated_entries: progress.total_estimated_entries,
            cache_state: map_catalog_cache_state(progress.cache_state),
            started_at,
            updated_at: now_iso(),
            error: None,
            error_code: None,
            error_detail: None,
        };
        self.inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to update source catalog status"))?
            .insert(source_id.to_string(), status.clone());
        let _ = app.emit(SOURCE_LOAD_PROGRESS_EVENT, &status);
        Ok(())
    }

    fn finish_catalog_load<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        source_id: &str,
        load_id: &str,
        state: SourceCatalogState,
        error: Option<String>,
    ) -> Result<()> {
        self.inner
            .source_catalog_loads
            .lock()
            .map_err(|_| anyhow!("Failed to finalize source load"))?
            .remove(load_id);

        let prior = self
            .inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to read source catalog status"))?
            .get(source_id)
            .cloned();
        let (error_code, error_detail) = classify_catalog_error(error.as_deref());
        let final_status = if state == SourceCatalogState::Ready {
            SourceCatalogStatus {
                state,
                source_id: source_id.to_string(),
                load_id: None,
                phase: None,
                progress_percent: 100.0,
                indexed_entries: prior
                    .as_ref()
                    .map(|status| status.indexed_entries)
                    .unwrap_or(0),
                total_estimated_entries: prior
                    .as_ref()
                    .and_then(|status| status.total_estimated_entries),
                cache_state: prior
                    .as_ref()
                    .map(|status| status.cache_state)
                    .unwrap_or(SourceCatalogCacheState::Warm),
                started_at: prior.as_ref().and_then(|status| status.started_at.clone()),
                updated_at: now_iso(),
                error: None,
                error_code: None,
                error_detail: None,
            }
        } else {
            SourceCatalogStatus {
                state,
                source_id: source_id.to_string(),
                load_id: None,
                phase: None,
                progress_percent: 0.0,
                indexed_entries: 0,
                total_estimated_entries: None,
                cache_state: SourceCatalogCacheState::Cold,
                started_at: None,
                updated_at: now_iso(),
                error,
                error_code,
                error_detail,
            }
        };

        self.inner
            .source_catalog_statuses
            .lock()
            .map_err(|_| anyhow!("Failed to write source catalog status"))?
            .insert(source_id.to_string(), final_status.clone());
        let event = if final_status.state == SourceCatalogState::Ready {
            SOURCE_LOAD_COMPLETE_EVENT
        } else {
            SOURCE_LOAD_PROGRESS_EVENT
        };
        let _ = app.emit(event, &final_status);
        Ok(())
    }

    fn update_progress<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        scan_id: &str,
        progress: ScanProgress,
    ) -> Result<()> {
        {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            if let Some(session) = sessions.get_mut(scan_id) {
                session.progress = progress.clone();
            }
        }
        let _ = app.emit(SCAN_PROGRESS_EVENT, &progress);
        Ok(())
    }

    fn update_results<R: Runtime>(
        &self,
        _app: &AppHandle<R>,
        scan_id: &str,
        results: &[ArtifactRecord],
    ) -> Result<()> {
        let mut sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;
        let Some(session) = sessions.get_mut(scan_id) else {
            return Ok(());
        };
        let new_results = results
            .iter()
            .filter(|artifact| session.result_ids.insert(artifact.id.clone()))
            .cloned()
            .collect::<Vec<_>>();
        if !new_results.is_empty() {
            session.results.extend(new_results);
        }
        Ok(())
    }

    fn update_raw_evidence_progress(
        &self,
        job_id: &str,
        state: AsyncJobState,
        phase: RawEvidenceRefinementPhase,
        progress_percent: f32,
        processed_units: u64,
        total_units: Option<u64>,
        message: String,
        warnings: Vec<String>,
    ) {
        if let Ok(mut jobs) = self.inner.raw_evidence_jobs.lock()
            && let Some(job) = jobs.get_mut(job_id)
        {
            job.progress.state = state;
            job.progress.phase = phase;
            job.progress.progress_percent = progress_percent.clamp(0.0, 100.0);
            job.progress.processed_units = processed_units;
            job.progress.total_units = total_units;
            job.progress.message = message;
            if !warnings.is_empty() {
                job.progress.warnings = warnings;
            }
            job.progress.updated_at = now_iso();
        }
    }

    fn finish_raw_evidence_job<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        job_id: &str,
        scan_id: &str,
        raw_state: RawEvidenceState,
        job_state: AsyncJobState,
        message: String,
        warnings: Vec<String>,
    ) {
        self.update_raw_evidence_progress(
            job_id,
            job_state,
            RawEvidenceRefinementPhase::Done,
            100.0,
            0,
            None,
            message.clone(),
            warnings,
        );

        let final_progress = {
            let mut sessions = match self.inner.sessions.lock() {
                Ok(sessions) => sessions,
                Err(_) => return,
            };
            let Some(session) = sessions.get_mut(scan_id) else {
                return;
            };
            session.progress.raw_evidence_state = raw_state;
            if session.progress.status.is_success() {
                session.progress.phase = rss_core::ScanPhase::Finalizing;
                session.progress.stage = "raw_evidence_done".to_string();
                session.progress.message = message;
                session.progress.updated_at = now_iso();
                session.progress.last_progress_at = session.progress.updated_at.clone();
            }
            session.progress.clone()
        };
        let _ = app.emit(SCAN_PROGRESS_EVENT, &final_progress);
    }

    fn complete_raw_evidence_refinement<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        job_id: &str,
        scan_id: &str,
        source_id: &str,
        source: ScanSource,
        results: Vec<ArtifactRecord>,
        raw_state: RawEvidenceState,
        warnings: Vec<String>,
    ) -> Result<()> {
        let deleted_locators = collect_deleted_artifact_locators(&results);
        let result_ids = results
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect::<HashSet<_>>();
        let message = if raw_state == RawEvidenceState::CompletedWithWarnings {
            "Raw NTFS evidence refined paths with warnings".to_string()
        } else {
            "Raw NTFS evidence refinement complete".to_string()
        };

        let final_progress = {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            let Some(session) = sessions.get_mut(scan_id) else {
                return Err(anyhow!(
                    "Scan {} disappeared during raw evidence completion",
                    scan_id
                ));
            };
            session.results = results;
            session.result_ids = result_ids;
            session.deleted_browse_cache = None;
            session.progress.raw_evidence_state = raw_state;
            session.progress.phase = rss_core::ScanPhase::Finalizing;
            session.progress.stage = "raw_evidence_done".to_string();
            session.progress.message = message.clone();
            session.progress.updated_at = now_iso();
            session.progress.last_progress_at = session.progress.updated_at.clone();
            session.progress.clone()
        };
        let _ = app.emit(SCAN_PROGRESS_EVENT, &final_progress);
        self.update_raw_evidence_progress(
            job_id,
            if raw_state == RawEvidenceState::CompletedWithWarnings {
                AsyncJobState::Completed
            } else {
                AsyncJobState::Completed
            },
            RawEvidenceRefinementPhase::Done,
            100.0,
            deleted_locators.len() as u64,
            Some(deleted_locators.len() as u64),
            message,
            warnings,
        );

        let state = self.clone();
        let app_handle = app.clone();
        let scan_id = scan_id.to_string();
        let source_id = source_id.to_string();
        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            let deleted_total = deleted_locators.len();
            if deleted_total > 0 {
                let _ = app_handle.emit(
                    DELETED_BROWSE_PROGRESS_EVENT,
                    DeletedBrowseProgressEvent {
                        scan_id: scan_id.clone(),
                        source_id: source_id.clone(),
                        processed_artifacts: 0,
                        total_artifacts: deleted_total,
                        progress_percent: 0.0,
                    },
                );
            }
            let deleted_cache = build_deleted_browse_cache_with_progress(
                &source,
                &deleted_locators,
                |processed_artifacts, total_artifacts| {
                    if total_artifacts == 0 {
                        return;
                    }
                    let _ = app_handle.emit(
                        DELETED_BROWSE_PROGRESS_EVENT,
                        DeletedBrowseProgressEvent {
                            scan_id: scan_id.clone(),
                            source_id: source_id.clone(),
                            processed_artifacts,
                            total_artifacts,
                            progress_percent: processed_artifacts as f32 * 100.0
                                / total_artifacts.max(1) as f32,
                        },
                    );
                },
            );
            if let Ok(mut sessions) = state.inner.sessions.lock()
                && let Some(session) = sessions.get_mut(&scan_id)
            {
                session.deleted_browse_cache = deleted_cache.clone();
            }
            if deleted_cache.is_some() {
                let _ = app_handle.emit(
                    DELETED_BROWSE_READY_EVENT,
                    DeletedBrowseReadyEvent { scan_id, source_id },
                );
            }
        });

        Ok(())
    }

    fn is_cancel_requested(&self, scan_id: &str) -> Result<bool> {
        let sessions = self
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("Failed to acquire session lock"))?;
        Ok(sessions
            .get(scan_id)
            .map(|session| session.cancel_requested)
            .unwrap_or(false))
    }

    fn complete_scan<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        scan_id: &str,
        execution: ScanExecution,
    ) -> Result<()> {
        let ScanExecution {
            progress,
            results,
            warnings,
            counters,
        } = execution;
        let deleted_locators = collect_deleted_artifact_locators(&results);
        let result_ids = results
            .iter()
            .map(|artifact| artifact.id.clone())
            .collect::<HashSet<_>>();
        let (snapshot, source, final_progress) = {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            let Some(session) = sessions.get_mut(scan_id) else {
                return Err(anyhow!("Scan {} disappeared during completion", scan_id));
            };

            session.progress = progress;
            session.results = results;
            session.deleted_browse_cache = None;
            session.result_ids = result_ids;
            session.warnings = warnings;
            session.cancel_requested = false;
            let final_status = if session.warnings.is_empty() {
                session.progress.status
            } else {
                ScanStatus::CompletedWithWarnings
            };
            session.progress.status = final_status;
            session.summary = Some(ScanSummary {
                scan_id: scan_id.to_string(),
                source_id: session.source.id.clone(),
                source_name: session.source.display_name.clone(),
                mode: session.options.mode,
                filesystem: session.source.filesystem,
                status: final_status,
                started_at: session.progress.started_at.clone(),
                finished_at: Some(session.progress.updated_at.clone()),
                duration_seconds: duration_seconds(
                    &session.progress.started_at,
                    &session.progress.updated_at,
                ),
                warnings: session.warnings.clone(),
                counters,
            });

            (
                session.summary.clone().map(|summary| ScanSnapshot {
                    summary,
                    source: session.source.clone(),
                    progress: session.progress.clone(),
                    // Persist a lightweight snapshot immediately; the live session
                    // remains the source of truth for full result export/recovery.
                    results: Vec::new(),
                }),
                session.source.clone(),
                session.progress.clone(),
            )
        };

        let _ = app.emit(SCAN_PROGRESS_EVENT, &final_progress);

        if let Some(snapshot) = snapshot {
            let case_store = self.inner.case_store.clone();
            let snapshot_scan_id = snapshot.summary.scan_id.clone();
            thread::spawn(move || {
                let _background_guard = enter_background_mode_current_thread().ok();
                if let Err(err) = case_store.save_snapshot(&snapshot) {
                    error!(
                        "Failed to persist scan snapshot {} in background: {err}",
                        snapshot_scan_id
                    );
                }
            });
        }

        let state = self.clone();
        let app_handle = app.clone();
        let scan_id = scan_id.to_string();
        let deleted_total = deleted_locators.len();
        thread::spawn(move || {
            let _background_guard = enter_background_mode_current_thread().ok();
            if deleted_total > 0 {
                let _ = app_handle.emit(
                    DELETED_BROWSE_PROGRESS_EVENT,
                    DeletedBrowseProgressEvent {
                        scan_id: scan_id.clone(),
                        source_id: source.id.clone(),
                        processed_artifacts: 0,
                        total_artifacts: deleted_total,
                        progress_percent: 0.0,
                    },
                );
            }
            let deleted_cache = build_deleted_browse_cache_with_progress(
                &source,
                &deleted_locators,
                |processed_artifacts, total_artifacts| {
                    if total_artifacts == 0 {
                        return;
                    }
                    let _ = app_handle.emit(
                        DELETED_BROWSE_PROGRESS_EVENT,
                        DeletedBrowseProgressEvent {
                            scan_id: scan_id.clone(),
                            source_id: source.id.clone(),
                            processed_artifacts,
                            total_artifacts,
                            progress_percent: processed_artifacts as f32 * 100.0
                                / total_artifacts.max(1) as f32,
                        },
                    );
                },
            );
            if let Ok(mut sessions) = state.inner.sessions.lock()
                && let Some(session) = sessions.get_mut(&scan_id)
            {
                session.deleted_browse_cache = deleted_cache.clone();
            }
            if deleted_cache.is_some() {
                let _ = app_handle.emit(
                    DELETED_BROWSE_READY_EVENT,
                    DeletedBrowseReadyEvent {
                        scan_id,
                        source_id: source.id.clone(),
                    },
                );
            }
        });

        Ok(())
    }

    fn finalize_scan_with_warning<R: Runtime>(
        &self,
        app: &AppHandle<R>,
        scan_id: &str,
        reason: String,
    ) -> Result<()> {
        let warning_progress = {
            let mut sessions = self
                .inner
                .sessions
                .lock()
                .map_err(|_| anyhow!("Failed to acquire session lock"))?;
            let Some(session) = sessions.get_mut(scan_id) else {
                return Ok(());
            };
            session.progress.status = ScanStatus::CompletedWithWarnings;
            session.progress.message = reason.clone();
            session.progress.phase = rss_core::ScanPhase::Finalizing;
            session.progress.stage = "finalizing".to_string();
            session.progress.progress_percent = 100.0;
            session.progress.eta_seconds = Some(0);
            session.progress.updated_at = now_iso();
            session.deleted_browse_cache = None;
            session.result_ids = session
                .results
                .iter()
                .map(|artifact| artifact.id.clone())
                .collect();
            if !reason.is_empty() && !session.warnings.iter().any(|warning| warning == &reason) {
                session.warnings.push(reason.clone());
            }
            session.cancel_requested = false;
            let counters = Self::summarize_scan_counters(&session.results);
            session.summary = Some(ScanSummary {
                scan_id: scan_id.to_string(),
                source_id: session.source.id.clone(),
                source_name: session.source.display_name.clone(),
                mode: session.options.mode,
                filesystem: session.source.filesystem,
                status: ScanStatus::CompletedWithWarnings,
                started_at: session.progress.started_at.clone(),
                finished_at: Some(session.progress.updated_at.clone()),
                duration_seconds: duration_seconds(
                    &session.progress.started_at,
                    &session.progress.updated_at,
                ),
                warnings: session.warnings.clone(),
                counters,
            });
            session.progress.clone()
        };
        let _ = app.emit(SCAN_PROGRESS_EVENT, &warning_progress);
        Ok(())
    }

    fn summarize_scan_counters(results: &[ArtifactRecord]) -> rss_core::ScanCounters {
        let mut counters = rss_core::ScanCounters {
            total_results: results.len(),
            ..rss_core::ScanCounters::default()
        };
        for artifact in results {
            match artifact.family {
                rss_core::ArtifactFamily::Executable => counters.executable_results += 1,
                rss_core::ArtifactFamily::Archive => counters.archive_results += 1,
                rss_core::ArtifactFamily::Script => counters.script_results += 1,
                _ => {}
            }
            if artifact.origin_type == OriginType::UnallocatedCarved {
                counters.carved_results += 1;
            }
            if matches!(
                artifact.recoverability,
                rss_core::Recoverability::Good | rss_core::Recoverability::Partial
            ) {
                counters.recoverable_results += 1;
            }
            if artifact.origin_type == OriginType::PartialFragment
                || artifact.recoverability == rss_core::Recoverability::Partial
            {
                counters.partial_results += 1;
            }
        }
        counters
    }

    fn set_preview_job_state(&self, job_id: &str, state: AsyncJobState, error: Option<String>) {
        if let Ok(mut jobs) = self.inner.preview_jobs.lock()
            && let Some(job) = jobs.get_mut(job_id)
        {
            if job.cancel.load(Ordering::Acquire)
                && matches!(job.status.state, AsyncJobState::Cancelled)
            {
                return;
            }
            transition_job_status(&mut job.status, state, error);
        }
    }

    fn finish_preview_job(&self, job_id: &str, result: Result<ContentPreviewResponse>) {
        if let Ok(mut jobs) = self.inner.preview_jobs.lock()
            && let Some(job) = jobs.get_mut(job_id)
        {
            if job.cancel.load(Ordering::Acquire)
                || matches!(job.status.state, AsyncJobState::Cancelled)
            {
                transition_job_status(&mut job.status, AsyncJobState::Cancelled, None);
                job.result = None;
                return;
            }
            match result {
                Ok(response) => {
                    transition_job_status(&mut job.status, AsyncJobState::Completed, None);
                    job.result = Some(response);
                }
                Err(error) => {
                    transition_job_status(
                        &mut job.status,
                        AsyncJobState::Failed,
                        Some(error.to_string()),
                    );
                    job.result = None;
                }
            }
        }
    }

    fn set_entry_details_job_state(
        &self,
        job_id: &str,
        state: AsyncJobState,
        error: Option<String>,
    ) {
        if let Ok(mut jobs) = self.inner.entry_details_jobs.lock()
            && let Some(job) = jobs.get_mut(job_id)
        {
            if job.cancel.load(Ordering::Acquire)
                && matches!(job.status.state, AsyncJobState::Cancelled)
            {
                return;
            }
            transition_job_status(&mut job.status, state, error);
        }
    }

    fn finish_entry_details_job(&self, job_id: &str, result: Result<SourceEntryDetails>) {
        if let Ok(mut jobs) = self.inner.entry_details_jobs.lock()
            && let Some(job) = jobs.get_mut(job_id)
        {
            if job.cancel.load(Ordering::Acquire)
                || matches!(job.status.state, AsyncJobState::Cancelled)
            {
                transition_job_status(&mut job.status, AsyncJobState::Cancelled, None);
                job.result = None;
                return;
            }
            match result {
                Ok(response) => {
                    transition_job_status(&mut job.status, AsyncJobState::Completed, None);
                    job.result = Some(response);
                }
                Err(error) => {
                    transition_job_status(
                        &mut job.status,
                        AsyncJobState::Failed,
                        Some(error.to_string()),
                    );
                    job.result = None;
                }
            }
        }
    }
}

fn new_job_status(job_id: &str) -> AsyncJobStatus {
    let now = now_iso();
    AsyncJobStatus {
        job_id: job_id.to_string(),
        state: AsyncJobState::Pending,
        created_at: now.clone(),
        updated_at: now,
        error: None,
    }
}

fn transition_job_status(status: &mut AsyncJobStatus, state: AsyncJobState, error: Option<String>) {
    status.state = state;
    status.updated_at = now_iso();
    status.error = error;
}

fn unloaded_catalog_status(source_id: &str) -> SourceCatalogStatus {
    SourceCatalogStatus {
        state: SourceCatalogState::Unloaded,
        source_id: source_id.to_string(),
        load_id: None,
        phase: None,
        progress_percent: 0.0,
        indexed_entries: 0,
        total_estimated_entries: None,
        cache_state: SourceCatalogCacheState::Cold,
        started_at: None,
        updated_at: now_iso(),
        error: None,
        error_code: None,
        error_detail: None,
    }
}

fn raw_evidence_phase_from_stage(stage: &str) -> RawEvidenceRefinementPhase {
    match stage {
        "building_directory_map" => RawEvidenceRefinementPhase::BuildingDirectoryMap,
        "parsing_i30" => RawEvidenceRefinementPhase::ParsingI30,
        "reading_usn" => RawEvidenceRefinementPhase::ReadingUsn,
        "merging_evidence" => RawEvidenceRefinementPhase::MergingEvidence,
        "done" => RawEvidenceRefinementPhase::Done,
        _ => RawEvidenceRefinementPhase::Queued,
    }
}

fn raw_evidence_stage_message(stage: &str) -> String {
    match stage {
        "building_directory_map" => "Building NTFS directory map".to_string(),
        "parsing_i30" => "Parsing NTFS $I30 directory evidence".to_string(),
        "reading_usn" => "Reading NTFS USN Journal evidence".to_string(),
        "merging_evidence" => "Merging raw evidence into deleted results".to_string(),
        "done" => "Raw NTFS evidence refinement complete".to_string(),
        _ => "Refining paths from NTFS raw evidence".to_string(),
    }
}

#[cfg(test)]
fn build_deleted_browse_cache(
    source: &ScanSource,
    deleted_artifacts: &[DeletedArtifactLocator],
) -> Option<DeletedBrowseCache> {
    build_deleted_browse_cache_with_progress(source, deleted_artifacts, |_, _| {})
}

fn build_deleted_browse_cache_with_progress<F>(
    source: &ScanSource,
    deleted_artifacts: &[DeletedArtifactLocator],
    mut on_progress: F,
) -> Option<DeletedBrowseCache>
where
    F: FnMut(usize, usize),
{
    let root_path = source.mount_point.as_ref()?.replace('/', "\\");
    let mut direct_artifact_indices_by_folder: HashMap<String, Vec<usize>> = HashMap::new();
    let mut synthetic_folders = HashMap::new();
    let mut synthetic_folders_by_parent: HashMap<String, Vec<DeletedFolderNode>> = HashMap::new();
    let mut subtree_deleted_counts = HashMap::new();
    let mut unknown_artifact_indices = Vec::new();
    let mut unknown_artifact_indices_by_extension: HashMap<String, Vec<usize>> = HashMap::new();
    let mut probable_artifact_indices = Vec::new();
    let mut probable_artifact_indices_by_extension: HashMap<String, Vec<usize>> = HashMap::new();
    let total_artifacts = deleted_artifacts.len();

    for (index, artifact) in deleted_artifacts.iter().enumerate() {
        let resolved_path = deleted_artifact_browser_path(artifact, &root_path);
        if let Some(artifact_path) = resolved_path {
            let artifact_path = canonicalize_browser_path(&artifact_path);
            let folder_path = parent_directory_path(&artifact_path, Some(&root_path));
            let folder_key = normalize_browser_path(&folder_path);
            direct_artifact_indices_by_folder
                .entry(folder_key)
                .or_default()
                .push(artifact.result_index);

            let mut subtree_folders = vec![folder_path.clone()];
            subtree_folders.extend(collect_artifact_ancestors(&folder_path, Some(&root_path)));
            for candidate in subtree_folders {
                let candidate_key = normalize_browser_path(&candidate);
                *subtree_deleted_counts
                    .entry(candidate_key.clone())
                    .or_insert(0) += 1;
            }

            register_deleted_folder_hierarchy(
                &folder_path,
                &root_path,
                &mut synthetic_folders,
                &mut synthetic_folders_by_parent,
            );
        } else if artifact.probable_path.is_some() {
            push_indexed_artifact(
                &mut probable_artifact_indices,
                &mut probable_artifact_indices_by_extension,
                artifact,
            );
        } else {
            push_indexed_artifact(
                &mut unknown_artifact_indices,
                &mut unknown_artifact_indices_by_extension,
                artifact,
            );
            let processed = index + 1;
            if should_report_deleted_browse_progress(processed, total_artifacts) {
                on_progress(processed, total_artifacts);
            }
            continue;
        }

        let processed = index + 1;
        if should_report_deleted_browse_progress(processed, total_artifacts) {
            on_progress(processed, total_artifacts);
        }
    }

    if total_artifacts > 0 {
        on_progress(total_artifacts, total_artifacts);
    }

    for siblings in synthetic_folders_by_parent.values_mut() {
        siblings.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
    }
    let route_folders_by_parent =
        build_route_folders_by_parent(&root_path, &synthetic_folders, &synthetic_folders_by_parent);

    Some(DeletedBrowseCache {
        root_path,
        direct_artifact_indices_by_folder,
        synthetic_folders,
        synthetic_folders_by_parent,
        route_folders_by_parent,
        subtree_deleted_counts,
        unknown_artifact_indices,
        unknown_artifact_indices_by_extension,
        probable_artifact_indices,
        probable_artifact_indices_by_extension,
    })
}

fn push_indexed_artifact(
    indices: &mut Vec<usize>,
    by_extension: &mut HashMap<String, Vec<usize>>,
    artifact: &DeletedArtifactLocator,
) {
    indices.push(artifact.result_index);
    let extension = artifact
        .extension
        .clone()
        .or_else(|| extension(&artifact.name))
        .or_else(|| default_extension_for_artifact_kind(artifact.kind).map(str::to_string))
        .map(|value| value.trim_start_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(extension) = extension {
        by_extension
            .entry(extension)
            .or_default()
            .push(artifact.result_index);
    }
}

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty())
}

fn default_extension_for_artifact_kind(kind: ArtifactKind) -> Option<&'static str> {
    match kind {
        ArtifactKind::Exe => Some("exe"),
        ArtifactKind::Dll => Some("dll"),
        ArtifactKind::Sys => Some("sys"),
        ArtifactKind::Scr => Some("scr"),
        ArtifactKind::Ocx => Some("ocx"),
        ArtifactKind::Cpl => Some("cpl"),
        ArtifactKind::Msi => Some("msi"),
        ArtifactKind::Jar => Some("jar"),
        ArtifactKind::Zip => Some("zip"),
        ArtifactKind::Rar => Some("rar"),
        ArtifactKind::SevenZip => Some("7z"),
        ArtifactKind::Cab => Some("cab"),
        ArtifactKind::Iso => Some("iso"),
        ArtifactKind::Tar => Some("tar"),
        ArtifactKind::Gzip => Some("gz"),
        ArtifactKind::Bzip2 => Some("bz2"),
        ArtifactKind::Xz => Some("xz"),
        ArtifactKind::Apk => Some("apk"),
        ArtifactKind::Pdf => Some("pdf"),
        ArtifactKind::Png => Some("png"),
        ArtifactKind::Jpg => Some("jpg"),
        ArtifactKind::Gif => Some("gif"),
        ArtifactKind::Sqlite => Some("sqlite"),
        ArtifactKind::Pak => Some("pak"),
        ArtifactKind::Bin => Some("bin"),
        ArtifactKind::Dat => Some("dat"),
        ArtifactKind::Bat => Some("bat"),
        ArtifactKind::Cmd => Some("cmd"),
        ArtifactKind::Ps1 => Some("ps1"),
        ArtifactKind::Vbs => Some("vbs"),
        ArtifactKind::Js => Some("js"),
        ArtifactKind::Ini => Some("ini"),
        ArtifactKind::Cfg => Some("cfg"),
        ArtifactKind::Json => Some("json"),
        ArtifactKind::Yml => Some("yml"),
        ArtifactKind::Yaml => Some("yaml"),
        ArtifactKind::Txt => Some("txt"),
        ArtifactKind::Log => Some("log"),
        ArtifactKind::OleCompound => Some("ole"),
        ArtifactKind::Pe => Some("pe"),
        ArtifactKind::Unknown => None,
    }
}

fn should_report_deleted_browse_progress(processed: usize, total_artifacts: usize) -> bool {
    processed == total_artifacts
        || processed == 0
        || processed.is_multiple_of(512)
        || (processed as f32 * 100.0 / total_artifacts.max(1) as f32) >= 100.0
}

fn collect_deleted_artifact_locators(results: &[ArtifactRecord]) -> Vec<DeletedArtifactLocator> {
    results
        .iter()
        .enumerate()
        .filter(|(_, artifact)| is_deleted_browse_candidate(artifact))
        .map(|(result_index, artifact)| DeletedArtifactLocator {
            result_index,
            original_path: artifact.original_path.clone(),
            probable_path: artifact.probable_path.clone(),
            name: artifact.name.clone(),
            extension: artifact.extension.clone(),
            kind: artifact.kind,
        })
        .collect()
}

fn is_deleted_browse_candidate(artifact: &ArtifactRecord) -> bool {
    artifact.deleted_entry
        && matches!(
            artifact.origin_type,
            OriginType::FilesystemDeletedEntry | OriginType::FilesystemOrphanedEntry
        )
}

fn deleted_artifact_browser_path(
    artifact: &DeletedArtifactLocator,
    root_path: &str,
) -> Option<String> {
    artifact
        .original_path
        .as_deref()
        .filter(|path| browser_path_is_within_root(path, root_path))
        .or_else(|| {
            artifact
                .probable_path
                .as_deref()
                .filter(|path| browser_path_is_within_root(path, root_path))
        })
        .map(str::to_string)
}

#[cfg(test)]
fn is_unknown_deleted_path(original_path: Option<&str>, root_path: &str) -> bool {
    let Some(original_path) = original_path else {
        return true;
    };
    !browser_path_is_within_root(original_path, root_path)
}

fn browser_path_is_within_root(path: &str, root_path: &str) -> bool {
    let normalized_path = normalize_browser_path(path);
    let normalized_root = normalize_browser_path(root_path);
    if normalized_root.is_empty() {
        return true;
    }
    if normalized_root.ends_with('\\') {
        return normalized_path.starts_with(&normalized_root);
    }
    normalized_path == normalized_root
        || normalized_path.starts_with(&format!("{normalized_root}\\"))
}

fn register_deleted_folder_hierarchy(
    folder_path: &str,
    root_path: &str,
    folders: &mut HashMap<String, DeletedFolderNode>,
    folders_by_parent: &mut HashMap<String, Vec<DeletedFolderNode>>,
) {
    for candidate_path in collect_folder_hierarchy(folder_path, root_path) {
        let candidate_key = normalize_browser_path(&candidate_path);
        if folders.contains_key(&candidate_key) {
            continue;
        }

        let root_key = normalize_browser_path(root_path);
        let parent_path = if candidate_key == root_key {
            None
        } else {
            Some(parent_directory_path(&candidate_path, Some(root_path)))
        };
        let parent_key = parent_path
            .as_ref()
            .map(|path| normalize_browser_path(path));
        let folder = DeletedFolderNode {
            path: candidate_path.clone(),
            parent_path: parent_path.clone(),
            name: folder_name(&candidate_path),
        };
        folders.insert(candidate_key, folder.clone());

        if let Some(parent_key) = parent_key {
            folders_by_parent
                .entry(parent_key)
                .or_default()
                .push(folder);
        }
    }
}

fn build_route_folders_by_parent(
    root_path: &str,
    synthetic_folders: &HashMap<String, DeletedFolderNode>,
    synthetic_folders_by_parent: &HashMap<String, Vec<DeletedFolderNode>>,
) -> HashMap<String, Vec<DeletedFolderNode>> {
    let mut routes: HashMap<String, HashMap<String, DeletedFolderNode>> = HashMap::new();

    for (parent_key, folders) in synthetic_folders_by_parent {
        let bucket = routes.entry(parent_key.clone()).or_default();
        for folder in folders {
            bucket
                .entry(normalize_browser_path(&folder.path))
                .or_insert_with(|| folder.clone());
        }
    }

    for folder in synthetic_folders.values() {
        for ancestor in collect_artifact_ancestors(&folder.path, Some(root_path)) {
            let Some(route_path) = immediate_child_folder_path(&ancestor, &folder.path) else {
                continue;
            };
            let route_key = normalize_browser_path(&route_path);
            let Some(route) = synthetic_folders.get(&route_key) else {
                continue;
            };
            routes
                .entry(normalize_browser_path(&ancestor))
                .or_default()
                .entry(route_key)
                .or_insert_with(|| route.clone());
        }
    }

    routes
        .into_iter()
        .map(|(parent, folders)| {
            let mut folders = folders.into_values().collect::<Vec<_>>();
            folders.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
            (parent, folders)
        })
        .collect()
}

fn immediate_child_folder_path(parent_path: &str, descendant_path: &str) -> Option<String> {
    let parent = canonicalize_browser_path(parent_path);
    let descendant = canonicalize_browser_path(descendant_path);
    let parent_key = normalize_browser_path(&parent);
    let descendant_key = normalize_browser_path(&descendant);

    if parent_key == descendant_key || !browser_path_is_within_root(&descendant, &parent) {
        return None;
    }

    let offset = if parent_key.ends_with('\\') {
        parent.len()
    } else {
        parent.len().saturating_add(1)
    };
    if descendant.len() <= offset {
        return None;
    }

    let remainder = &descendant[offset..];
    let child_len = remainder.find('\\').unwrap_or(remainder.len());
    if child_len == 0 {
        return None;
    }
    Some(descendant[..offset + child_len].to_string())
}

fn collect_folder_hierarchy(folder_path: &str, root_path: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let root_key = normalize_browser_path(root_path);
    let mut cursor = folder_path.to_string();
    while !cursor.is_empty() && normalize_browser_path(&cursor) != root_key {
        chain.push(cursor.clone());
        let next = parent_directory_path(&cursor, Some(root_path));
        if next == cursor {
            break;
        }
        cursor = next;
    }
    chain.reverse();
    chain
}

fn collect_artifact_ancestors(path: &str, root_path: Option<&str>) -> Vec<String> {
    let mut ancestors = Vec::new();
    let normalized_root = root_path.map(normalize_browser_path).unwrap_or_default();
    if !normalized_root.is_empty() && normalize_browser_path(path) == normalized_root {
        return ancestors;
    }

    let mut cursor = parent_directory_path(path, root_path);
    while !cursor.is_empty() {
        ancestors.push(cursor.clone());
        if !normalized_root.is_empty() && normalize_browser_path(&cursor) == normalized_root {
            break;
        }
        let next = parent_directory_path(&cursor, root_path);
        if next == cursor {
            break;
        }
        cursor = next;
    }
    ancestors
}

fn normalize_browser_path(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

fn canonicalize_browser_path(path: &str) -> String {
    path.replace('/', "\\")
}

fn parent_directory_path(path: &str, root_path: Option<&str>) -> String {
    let normalized_path = normalize_browser_path(path);
    let canonical_path = canonicalize_browser_path(path);
    let canonical_root = canonicalize_browser_path(root_path.unwrap_or_default());
    let normalized_root = if canonical_root.is_empty() {
        String::new()
    } else {
        normalize_browser_path(&canonical_root)
    };

    if !normalized_root.is_empty() && normalized_path == normalized_root {
        return canonical_root;
    }

    let Some(last_slash) = canonical_path.rfind('\\') else {
        return if canonical_root.is_empty() {
            canonical_path
        } else {
            canonical_root
        };
    };

    if !normalized_root.is_empty() && last_slash < normalized_root.len() {
        return canonical_root;
    }

    let parent = canonical_path[..last_slash].to_string();
    if parent.len() == 2 && parent.ends_with(':') {
        return if canonical_root.is_empty() {
            format!("{parent}\\")
        } else {
            canonical_root
        };
    }
    if normalized_root.is_empty() {
        return parent;
    }
    if parent.len() < canonical_root.len() {
        canonical_root
    } else {
        parent
    }
}

fn folder_name(path: &str) -> String {
    let trimmed = path.strip_suffix('\\').unwrap_or(path);
    trimmed
        .rsplit_once('\\')
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| trimmed.to_string())
}

fn unknown_bucket_path_for_source(source_id: &str) -> String {
    format!("rss://unknown/{}", source_id.to_lowercase())
}

fn is_unknown_bucket_path_for_source(path: &str, source_id: &str) -> bool {
    normalize_browser_path(path)
        == normalize_browser_path(&unknown_bucket_path_for_source(source_id))
}

fn probable_bucket_path_for_source(source_id: &str) -> String {
    format!("rss://probable/{}", source_id.to_lowercase())
}

fn is_probable_bucket_path_for_source(path: &str, source_id: &str) -> bool {
    normalize_browser_path(path)
        == normalize_browser_path(&probable_bucket_path_for_source(source_id))
}

fn deleted_indices_for_request<'a>(
    results: &[ArtifactRecord],
    indices: &'a [usize],
    by_extension: &'a HashMap<String, Vec<usize>>,
    request: &BrowseSourceRequest,
) -> Cow<'a, [usize]> {
    let mut filtered =
        filtered_deleted_indices(results, indices, by_extension, request.filter.as_deref());
    if request.sort_key.as_deref().is_some_and(is_deleted_sort_key) {
        sort_deleted_indices(
            results,
            filtered.to_mut(),
            request.sort_key.as_deref(),
            request.sort_direction.as_deref(),
        );
    }
    filtered
}

fn filtered_deleted_indices<'a>(
    results: &[ArtifactRecord],
    indices: &'a [usize],
    by_extension: &'a HashMap<String, Vec<usize>>,
    filter: Option<&str>,
) -> Cow<'a, [usize]> {
    let Some(filter) = normalized_filter(filter) else {
        return Cow::Borrowed(indices);
    };
    if let Some(extension) = exact_extension_filter(&filter)
        && let Some(indexed) = by_extension.get(&extension)
    {
        return Cow::Owned(
            indexed
                .iter()
                .copied()
                .filter(|index| indices.binary_search(index).is_ok() || by_extension.len() == 1)
                .collect(),
        );
    }

    Cow::Owned(
        indices
            .iter()
            .copied()
            .filter(|index| {
                results
                    .get(*index)
                    .is_some_and(|artifact| artifact_matches_filter(artifact, &filter))
            })
            .collect(),
    )
}

fn is_deleted_sort_key(key: &str) -> bool {
    matches!(
        key,
        "name" | "type" | "size" | "created_at" | "modified_at" | "accessed_at" | "deleted_hits"
    )
}

fn sort_deleted_indices(
    results: &[ArtifactRecord],
    indices: &mut [usize],
    sort_key: Option<&str>,
    sort_direction: Option<&str>,
) {
    let descending = matches!(sort_direction, Some("desc"));
    let key = sort_key.unwrap_or("name");
    indices.sort_by(|left, right| {
        let ordering = compare_deleted_artifacts(results.get(*left), results.get(*right), key);
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn compare_deleted_artifacts(
    left: Option<&ArtifactRecord>,
    right: Option<&ArtifactRecord>,
    sort_key: &str,
) -> std::cmp::Ordering {
    let Some(left) = left else {
        return std::cmp::Ordering::Greater;
    };
    let Some(right) = right else {
        return std::cmp::Ordering::Less;
    };
    let ordering = match sort_key {
        "type" => format!("{:?}", left.kind)
            .to_ascii_lowercase()
            .cmp(&format!("{:?}", right.kind).to_ascii_lowercase()),
        "size" => left.size.cmp(&right.size),
        "created_at" => left.created_at.cmp(&right.created_at),
        "modified_at" => left.modified_at.cmp(&right.modified_at),
        "accessed_at" => std::cmp::Ordering::Equal,
        "deleted_hits" => std::cmp::Ordering::Equal,
        "name" => left
            .name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase()),
        _ => std::cmp::Ordering::Equal,
    };
    ordering
        .then_with(|| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        })
        .then_with(|| left.id.cmp(&right.id))
}

fn normalized_filter(filter: Option<&str>) -> Option<String> {
    filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn exact_extension_filter(filter: &str) -> Option<String> {
    let trimmed = filter.trim();
    let extension = trimmed.strip_prefix('.').unwrap_or(trimmed);
    if extension.is_empty()
        || extension.len() > 16
        || !extension
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    Some(extension.to_ascii_lowercase())
}

fn artifact_matches_filter(artifact: &ArtifactRecord, filter: &str) -> bool {
    artifact.name.to_ascii_lowercase().contains(filter)
        || artifact
            .extension
            .as_deref()
            .is_some_and(|extension| extension.eq_ignore_ascii_case(filter.trim_start_matches('.')))
        || format!("{:?}", artifact.kind)
            .to_ascii_lowercase()
            .contains(filter)
        || artifact
            .original_path
            .as_deref()
            .is_some_and(|path| path.to_ascii_lowercase().contains(filter))
        || artifact
            .probable_path
            .as_deref()
            .is_some_and(|path| path.to_ascii_lowercase().contains(filter))
        || artifact
            .created_at
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(filter))
        || artifact
            .modified_at
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(filter))
        || artifact
            .deleted_at
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(filter))
        || artifact
            .last_metadata_change_at
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains(filter))
}

fn deleted_hits_for_entry(
    entry: &SourceEntry,
    deleted_cache: &DeletedBrowseCache,
    source: &ScanSource,
) -> usize {
    if is_unknown_bucket_path_for_source(&entry.path, &source.id) {
        return deleted_cache.unknown_artifact_indices.len();
    }
    if !entry.is_directory {
        return 0;
    }

    let normalized_path = normalize_browser_path(&entry.path);
    deleted_cache
        .subtree_deleted_counts
        .get(&normalized_path)
        .copied()
        .unwrap_or_default()
}

fn apply_deleted_hits_to_entry(
    entry: &mut SourceEntry,
    deleted_cache: &DeletedBrowseCache,
    source: &ScanSource,
) {
    entry.deleted_hits = deleted_hits_for_entry(entry, deleted_cache, source);
    if entry.is_directory && deleted_cache.has_deleted_child_folder(&entry.path) {
        entry.has_children = Some(true);
    }
}

fn entry_represents_deleted_folder_route(entry: &SourceEntry) -> bool {
    entry.is_directory
        && entry.access_state == SourceAccessState::Readable
        && !entry
            .attributes
            .iter()
            .any(|value| value == "reparse_point")
}

fn create_unknown_bucket_entry(
    source: &ScanSource,
    deleted_cache: &DeletedBrowseCache,
) -> SourceEntry {
    SourceEntry {
        name: "Unknown".to_string(),
        path: unknown_bucket_path_for_source(&source.id),
        parent_path: deleted_cache.root_path.clone(),
        mft_reference: None,
        parent_reference: None,
        extension: None,
        is_directory: true,
        has_children: Some(false),
        is_metafile: false,
        entry_class: SourceEntryClass::Directory,
        size: 0,
        created_at: None,
        modified_at: None,
        accessed_at: None,
        hidden: false,
        system: false,
        read_only: false,
        attr_bits: None,
        attributes: vec!["Deleted or orphaned".to_string()],
        deleted_hits: deleted_cache.unknown_artifact_indices.len(),
        access_state: SourceAccessState::Unknown,
    }
}

fn create_probable_bucket_entry(
    source: &ScanSource,
    deleted_cache: &DeletedBrowseCache,
) -> SourceEntry {
    SourceEntry {
        name: "Probable locations".to_string(),
        path: probable_bucket_path_for_source(&source.id),
        parent_path: deleted_cache.root_path.clone(),
        mft_reference: None,
        parent_reference: None,
        extension: None,
        is_directory: true,
        has_children: Some(false),
        is_metafile: false,
        entry_class: SourceEntryClass::Directory,
        size: 0,
        created_at: None,
        modified_at: None,
        accessed_at: None,
        hidden: false,
        system: false,
        read_only: false,
        attr_bits: None,
        attributes: vec!["Probable deleted locations".to_string()],
        deleted_hits: deleted_cache.probable_artifact_indices.len(),
        access_state: SourceAccessState::Unknown,
    }
}

fn create_deleted_folder_entry(
    deleted_cache: &DeletedBrowseCache,
    folder: &DeletedFolderNode,
    deleted_hits: usize,
) -> SourceEntry {
    let folder_key = normalize_browser_path(&folder.path);
    let direct_child_folders = deleted_cache
        .synthetic_folders_by_parent
        .get(&folder_key)
        .map(Vec::len)
        .unwrap_or_default();

    SourceEntry {
        name: folder.name.clone(),
        path: folder.path.clone(),
        parent_path: folder.parent_path.clone().unwrap_or_default(),
        mft_reference: None,
        parent_reference: None,
        extension: None,
        is_directory: true,
        has_children: Some(direct_child_folders > 0),
        is_metafile: false,
        entry_class: SourceEntryClass::Directory,
        size: 0,
        created_at: None,
        modified_at: None,
        accessed_at: None,
        hidden: false,
        system: false,
        read_only: false,
        attr_bits: None,
        attributes: vec!["Deleted folder".to_string()],
        deleted_hits,
        access_state: SourceAccessState::Unknown,
    }
}

fn is_path_not_found_error(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_lowercase();
    message.contains("path_not_found")
        || message.contains("not found")
        || message.contains("cannot find the path specified")
        || message.contains("os error 3")
}

fn source_uses_catalog(source: &ScanSource) -> bool {
    source.kind == rss_core::SourceKind::LogicalVolume && source.mount_point.is_some()
}

fn classify_catalog_error(error: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(error) = error else {
        return (None, None);
    };

    let code = if error.contains("UNIQUE constraint failed") {
        "sqlite_unique"
    } else if error.contains("catalog_not_ready") {
        "catalog_not_ready"
    } else if error.contains("cancelled") {
        "cancelled"
    } else if error.contains("mounted logical volumes") || error.contains("Mounted source path") {
        "unsupported_source"
    } else {
        "load_failed"
    };

    (Some(code.to_string()), Some(error.to_string()))
}

fn map_catalog_phase(value: CatalogPhase) -> SourceCatalogPhase {
    match value {
        CatalogPhase::OpeningVolume => SourceCatalogPhase::OpeningVolume,
        CatalogPhase::EnumeratingFiles => SourceCatalogPhase::EnumeratingFiles,
        CatalogPhase::AugmentingNtfsMetadata => SourceCatalogPhase::AugmentingNtfsMetadata,
        CatalogPhase::BuildingIndexes => SourceCatalogPhase::BuildingIndexes,
        CatalogPhase::Finalizing => SourceCatalogPhase::Finalizing,
    }
}

fn map_catalog_cache_state(value: CatalogCacheState) -> SourceCatalogCacheState {
    match value {
        CatalogCacheState::Cold => SourceCatalogCacheState::Cold,
        CatalogCacheState::Warm => SourceCatalogCacheState::Warm,
        CatalogCacheState::DeltaRefresh => SourceCatalogCacheState::DeltaRefresh,
        CatalogCacheState::Rebuild => SourceCatalogCacheState::Rebuild,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{
        ArtifactClass, ContentSourceKind, FileSystemKind, PathConfidence, PlacementKind,
        Recoverability, SourceKind,
    };

    fn test_source() -> ScanSource {
        ScanSource {
            id: "vol-c".to_string(),
            kind: SourceKind::LogicalVolume,
            device_path: "\\\\.\\C:".to_string(),
            mount_point: Some("C:\\".to_string()),
            display_name: "C:".to_string(),
            volume_label: Some("System".to_string()),
            filesystem: FileSystemKind::Ntfs,
            volume_serial: Some(0x1234),
            total_bytes: 1,
            free_bytes: 1,
            cluster_size: Some(4096),
            is_system: true,
            requires_elevation: true,
        }
    }

    fn deleted_record(name: &str, path: Option<&str>) -> ArtifactRecord {
        let mut record = ArtifactRecord::new("scan-1", "vol-c", name);
        record.original_path = path.map(str::to_string);
        record.deleted_entry = true;
        record.origin_type = OriginType::FilesystemDeletedEntry;
        record.placement_kind = if path.is_some() {
            PlacementKind::OriginalPath
        } else {
            PlacementKind::UnknownParent
        };
        record.path_confidence = if path.is_some() {
            PathConfidence::Exact
        } else {
            PathConfidence::Unknown
        };
        record.content_source = ContentSourceKind::ResidentData;
        record.artifact_class = ArtifactClass::NamedMetadataCandidate;
        record.recoverability = Recoverability::Good;
        record
    }

    fn source_entry(path: &str, attributes: Vec<&str>) -> SourceEntry {
        SourceEntry {
            name: path.rsplit('\\').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            parent_path: "C:\\".to_string(),
            mft_reference: None,
            parent_reference: None,
            extension: None,
            is_directory: true,
            has_children: Some(true),
            is_metafile: false,
            entry_class: SourceEntryClass::Directory,
            size: 0,
            created_at: None,
            modified_at: None,
            accessed_at: None,
            hidden: false,
            system: false,
            read_only: false,
            attr_bits: None,
            attributes: attributes.into_iter().map(str::to_string).collect(),
            deleted_hits: 0,
            access_state: SourceAccessState::Readable,
        }
    }

    #[test]
    fn deleted_browse_cache_ignores_non_deleted_records() {
        let mut live_record = ArtifactRecord::new("scan-1", "vol-c", "users");
        live_record.original_path = Some("C:\\Users".to_string());
        live_record.deleted_entry = false;
        live_record.origin_type = OriginType::FilesystemDeletedEntry;
        let deleted_record = deleted_record("vec.dll", Some("C:\\Users\\jumarf\\vec.dll"));

        let locators = collect_deleted_artifact_locators(&[live_record, deleted_record]);
        assert_eq!(locators.len(), 1);

        let cache = build_deleted_browse_cache(&test_source(), &locators).expect("cache");
        assert!(cache.synthetic_folders.contains_key("c:\\users"));
        assert_eq!(
            cache
                .direct_artifact_indices_by_folder
                .get("c:\\users\\jumarf")
                .map(Vec::as_slice),
            Some([1].as_slice())
        );
    }

    #[test]
    fn deleted_browse_cache_marks_missing_paths_unknown() {
        let orphan = deleted_record("orphan.bin", None);
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&[orphan]),
        )
        .expect("cache");
        assert_eq!(cache.unknown_artifact_indices, vec![0]);
    }

    #[test]
    fn probable_paths_inside_root_are_placed_in_deleted_tree() {
        let mut probable = deleted_record("probable.jar", None);
        probable.probable_path = Some("C:\\Users\\Old\\probable.jar".to_string());
        probable.placement_kind = PlacementKind::BrokenParentChain;
        probable.path_confidence = PathConfidence::Partial;
        let exact = deleted_record("exact.jar", Some("C:\\Users\\New\\exact.jar"));
        let records = [probable, exact];
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&records),
        )
        .expect("cache");

        assert_eq!(cache.probable_artifact_indices, Vec::<usize>::new());
        assert_eq!(cache.unknown_artifact_indices, Vec::<usize>::new());
        assert_eq!(
            cache.subtree_deleted_counts.get("c:\\users").copied(),
            Some(2)
        );
        assert_eq!(
            cache
                .direct_artifact_indices_by_folder
                .get("c:\\users\\old")
                .map(Vec::as_slice),
            Some([0].as_slice())
        );
    }

    #[test]
    fn extension_filter_uses_unknown_index_for_large_buckets() {
        let records = [
            deleted_record("library.jar", None),
            deleted_record("payload.exe", None),
            deleted_record("notes.txt", None),
        ];
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&records),
        )
        .expect("cache");

        let filtered = filtered_deleted_indices(
            &records,
            &cache.unknown_artifact_indices,
            &cache.unknown_artifact_indices_by_extension,
            Some(".jar"),
        );

        assert_eq!(filtered.as_ref(), &[0]);
    }

    #[test]
    fn deleted_indices_sort_by_modified_before_paging() {
        let mut older = deleted_record("older.jar", Some("C:\\Users\\Old\\older.jar"));
        older.modified_at = Some("2026-01-01T00:00:00Z".to_string());
        let mut newer = deleted_record("newer.jar", Some("C:\\Users\\Old\\newer.jar"));
        newer.modified_at = Some("2026-05-01T00:00:00Z".to_string());
        let mut middle = deleted_record("middle.jar", Some("C:\\Users\\Old\\middle.jar"));
        middle.modified_at = Some("2026-03-01T00:00:00Z".to_string());
        let records = [older, newer, middle];
        let request = BrowseSourceRequest {
            source_id: "vol-c".to_string(),
            path: Some("C:\\Users\\Old".to_string()),
            cursor: None,
            deleted_cursor: None,
            limit: Some(2),
            directories_only: Some(false),
            filter: None,
            sort_key: Some("modified_at".to_string()),
            sort_direction: Some("desc".to_string()),
        };

        let extension_index = HashMap::new();
        let sorted = deleted_indices_for_request(&records, &[0, 1, 2], &extension_index, &request);

        assert_eq!(sorted.as_ref(), &[1, 2, 0]);
    }

    #[test]
    fn deleted_hits_for_live_folders_use_subtree_hits() {
        let deleted_records = [
            deleted_record("one.bin", Some("C:\\Users\\jumarf\\one.bin")),
            deleted_record("two.bin", Some("C:\\Users\\jumarf\\nested\\two.bin")),
            deleted_record("three.bin", Some("C:\\ProgramData\\App\\Cache\\three.bin")),
        ];
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&deleted_records),
        )
        .expect("cache");

        let live_folder = source_entry("C:\\Users\\jumarf", Vec::new());
        let synthetic_folder = source_entry("C:\\Users\\jumarf\\nested", vec!["Deleted folder"]);
        let program_data = source_entry("C:\\ProgramData", Vec::new());

        assert_eq!(
            deleted_hits_for_entry(&live_folder, &cache, &test_source()),
            2
        );
        assert_eq!(
            deleted_hits_for_entry(&synthetic_folder, &cache, &test_source()),
            1
        );
        assert_eq!(
            deleted_hits_for_entry(&program_data, &cache, &test_source()),
            1
        );
        assert_eq!(
            cache
                .direct_artifact_indices_by_folder
                .get("c:\\users\\jumarf")
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn listing_folder_indices_stay_direct_to_keep_deleted_files_at_their_path() {
        let deleted_records = [
            deleted_record(
                "nested.bin",
                Some("C:\\ProgramData\\App\\Cache\\nested.bin"),
            ),
            deleted_record("direct.bin", Some("C:\\ProgramData\\direct.bin")),
        ];
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&deleted_records),
        )
        .expect("cache");

        assert_eq!(
            cache.direct_artifact_indices_for_folder("c:\\programdata"),
            &[1]
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder("c:\\programdata\\app"),
            &[] as &[usize]
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder("c:\\programdata\\app\\cache"),
            &[0]
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder("c:\\"),
            &[] as &[usize]
        );
    }

    #[test]
    fn probable_path_inside_root_is_listed_only_at_probable_parent() {
        let mut probable = deleted_record(".git", None);
        probable.probable_path =
            Some("C:\\Users\\jumarf\\AppData\\Local\\Temp\\_MEI96042\\rules\\.git".to_string());
        probable.placement_kind = PlacementKind::BrokenParentChain;
        probable.path_confidence = PathConfidence::Partial;

        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&[probable]),
        )
        .expect("cache");

        assert_eq!(cache.probable_artifact_indices, Vec::<usize>::new());
        assert_eq!(
            cache.subtree_deleted_counts.get("c:\\users").copied(),
            Some(1)
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder("c:\\users"),
            &[] as &[usize]
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder(
                "c:\\users\\jumarf\\appdata\\local\\temp\\_mei96042\\rules"
            ),
            &[0]
        );
        assert!(
            cache
                .synthetic_folders_by_parent
                .get("c:\\users")
                .is_some_and(|folders| folders.iter().any(|folder| folder.name == "jumarf"))
        );
    }

    #[test]
    fn nested_probable_deleted_folder_always_has_visible_child_route() {
        let mut probable = deleted_record("rule.yar", None);
        probable.probable_path = Some(
            "C:\\Users\\jumarf\\Downloads\\yara_fp_strict_rules\\private\\rule.yar".to_string(),
        );
        probable.placement_kind = PlacementKind::BrokenParentChain;
        probable.path_confidence = PathConfidence::Partial;

        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&[probable]),
        )
        .expect("cache");

        let folder_key = "c:\\users\\jumarf\\downloads\\yara_fp_strict_rules";
        assert_eq!(
            cache.subtree_deleted_counts.get(folder_key).copied(),
            Some(1)
        );
        assert_eq!(
            cache.direct_artifact_indices_for_folder(folder_key),
            &[] as &[usize]
        );
        assert!(
            cache
                .route_folders_by_parent
                .get(folder_key)
                .is_some_and(|folders| folders.iter().any(|folder| folder.name == "private"))
        );
    }

    #[test]
    fn live_file_name_collision_does_not_hide_deleted_folder_route() {
        let live_file = SourceEntry {
            is_directory: false,
            entry_class: SourceEntryClass::File,
            has_children: Some(false),
            ..source_entry("C:\\Users\\jumarf\\Downloads\\rules", Vec::new())
        };
        let live_folder = source_entry("C:\\Users\\jumarf\\Downloads\\rules", Vec::new());

        assert!(!entry_represents_deleted_folder_route(&live_file));
        assert!(entry_represents_deleted_folder_route(&live_folder));
    }

    #[test]
    fn live_folder_with_deleted_descendants_becomes_expandable() {
        let deleted_record =
            deleted_record("two.bin", Some("C:\\ProgramData\\App\\Cache\\two.bin"));
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&[deleted_record]),
        )
        .expect("cache");
        let mut entry = SourceEntry {
            has_children: Some(false),
            ..source_entry("C:\\ProgramData", Vec::new())
        };

        apply_deleted_hits_to_entry(&mut entry, &cache, &test_source());

        assert_eq!(entry.deleted_hits, 1);
        assert_eq!(entry.has_children, Some(true));
    }

    #[test]
    fn direct_deleted_files_do_not_create_empty_tree_expanders() {
        let deleted_record = deleted_record("two.bin", Some("C:\\ProgramData\\two.bin"));
        let cache = build_deleted_browse_cache(
            &test_source(),
            &collect_deleted_artifact_locators(&[deleted_record]),
        )
        .expect("cache");
        let mut live_entry = SourceEntry {
            has_children: Some(false),
            ..source_entry("C:\\ProgramData", Vec::new())
        };

        apply_deleted_hits_to_entry(&mut live_entry, &cache, &test_source());

        assert_eq!(live_entry.deleted_hits, 1);
        assert_eq!(live_entry.has_children, Some(false));
        let synthetic_folder = cache
            .synthetic_folders
            .get("c:\\programdata")
            .expect("synthetic folder");
        let synthetic_entry = create_deleted_folder_entry(&cache, synthetic_folder, 1);
        assert_eq!(synthetic_entry.deleted_hits, 1);
        assert_eq!(synthetic_entry.has_children, Some(false));
    }

    #[test]
    fn deleted_path_root_check_respects_directory_boundaries() {
        assert!(!is_unknown_deleted_path(
            Some("C:\\ProgramData\\file.bin"),
            "C:\\"
        ));
        assert!(is_unknown_deleted_path(
            Some("C:\\Mountains\\file.bin"),
            "C:\\Mount"
        ));
        assert!(!is_unknown_deleted_path(
            Some("C:\\Mount\\child\\file.bin"),
            "C:\\Mount"
        ));
    }

    #[test]
    fn path_not_found_error_recognizes_common_windows_forms() {
        assert!(is_path_not_found_error(&anyhow!("path_not_found")));
        assert!(is_path_not_found_error(&anyhow!(
            "The system cannot find the path specified. (os error 3)"
        )));
        assert!(!is_path_not_found_error(&anyhow!("access denied")));
    }
}
