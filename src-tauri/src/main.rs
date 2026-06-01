#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use rss_core::{
    ArchivePreviewPage, ArtifactPreviewRequest, ArtifactPreviewResponse, ArtifactRecord,
    ArtifactSignatureSummary, ArtifactSummary, AsyncJobStatus, BootstrapInfo, BrowseSourceRequest,
    ContentPreviewRequest, ContentPreviewResponse, ContentTarget, PreviewChunkResponse,
    PreviewSessionInfo, PreviewSessionOpenRequest, RawEvidenceRefinementProgress,
    RawEvidenceRefinementRequest, RecoveryRequest, RecoverySummary, ScanOptions, ScanProgress,
    ScanSnapshot, ScanSource, SourceCatalogStatus, SourceDirectoryListing, SourceEntryDetails,
};
use rss_security::ensure_elevated;
use rss_ui_bridge::BridgeState;
use tauri::Manager;
#[cfg(target_os = "windows")]
use windows::{
    Win32::UI::{
        Shell::SetCurrentProcessExplicitAppUserModelID,
        WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
    },
    core::PCWSTR,
};

fn err<T>(result: anyhow::Result<T>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

#[tauri::command]
fn bootstrap(state: tauri::State<'_, BridgeState>) -> Result<BootstrapInfo, String> {
    err(state.bootstrap())
}

#[tauri::command]
fn list_sources(state: tauri::State<'_, BridgeState>) -> Result<Vec<ScanSource>, String> {
    err(state.list_sources())
}

#[tauri::command]
fn refresh_sources(state: tauri::State<'_, BridgeState>) -> Result<Vec<ScanSource>, String> {
    err(state.refresh_sources())
}

#[tauri::command]
fn load_source_catalog(
    app: tauri::AppHandle,
    state: tauri::State<'_, BridgeState>,
    source_id: String,
    force_rebuild: Option<bool>,
) -> Result<String, String> {
    err(state.load_source_catalog(app, &source_id, force_rebuild.unwrap_or(false)))
}

#[tauri::command]
fn source_catalog_status(
    state: tauri::State<'_, BridgeState>,
    source_id: String,
) -> Result<SourceCatalogStatus, String> {
    err(state.source_catalog_status(&source_id))
}

#[tauri::command]
fn cancel_source_load(state: tauri::State<'_, BridgeState>, load_id: String) -> Result<(), String> {
    err(state.cancel_source_load(&load_id))
}

#[tauri::command]
fn browse_source(
    state: tauri::State<'_, BridgeState>,
    request: BrowseSourceRequest,
) -> Result<SourceDirectoryListing, String> {
    err(state.browse_source(&request))
}

#[tauri::command]
fn entry_details(
    state: tauri::State<'_, BridgeState>,
    source_id: String,
    path: String,
) -> Result<SourceEntryDetails, String> {
    err(state.entry_details(&source_id, &path))
}

#[tauri::command]
fn start_entry_details_job(
    state: tauri::State<'_, BridgeState>,
    source_id: String,
    path: String,
) -> Result<String, String> {
    err(state.start_entry_details_job(&source_id, &path))
}

#[tauri::command]
fn entry_details_job_status(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<AsyncJobStatus, String> {
    err(state.entry_details_job_status(&job_id))
}

#[tauri::command]
fn entry_details_job_result(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<SourceEntryDetails, String> {
    err(state.entry_details_job_result(&job_id))
}

#[tauri::command]
fn cancel_entry_details_job(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<(), String> {
    err(state.cancel_entry_details_job(&job_id))
}

#[tauri::command]
fn start_scan(
    app: tauri::AppHandle,
    state: tauri::State<'_, BridgeState>,
    options: ScanOptions,
) -> Result<String, String> {
    err(state.start_scan(app, options))
}

#[tauri::command]
fn stop_scan(state: tauri::State<'_, BridgeState>, scan_id: String) -> Result<(), String> {
    err(state.stop_scan(&scan_id))
}

#[tauri::command]
fn scan_progress(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    err(state.scan_progress(&scan_id))
}

#[tauri::command]
fn start_raw_evidence_refinement(
    app: tauri::AppHandle,
    state: tauri::State<'_, BridgeState>,
    request: RawEvidenceRefinementRequest,
) -> Result<String, String> {
    err(state.start_raw_evidence_refinement(app, request))
}

#[tauri::command]
fn raw_evidence_progress(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<RawEvidenceRefinementProgress, String> {
    err(state.raw_evidence_progress(&job_id))
}

#[tauri::command]
fn cancel_raw_evidence_refinement(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<(), String> {
    err(state.cancel_raw_evidence_refinement(&job_id))
}

#[tauri::command]
fn scan_results(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
) -> Result<Vec<ArtifactSummary>, String> {
    err(state.scan_results(&scan_id))
}

#[tauri::command]
fn artifact_details(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
    artifact_id: String,
) -> Result<ArtifactRecord, String> {
    err(state.artifact_details(&scan_id, &artifact_id))
}

#[tauri::command]
fn artifact_signature(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
    artifact_id: String,
) -> Result<ArtifactSignatureSummary, String> {
    err(state.artifact_signature(&scan_id, &artifact_id))
}

#[tauri::command]
fn artifact_preview(
    state: tauri::State<'_, BridgeState>,
    request: ArtifactPreviewRequest,
) -> Result<ArtifactPreviewResponse, String> {
    err(state.artifact_preview(&request))
}

#[tauri::command]
fn content_signature(
    state: tauri::State<'_, BridgeState>,
    target: ContentTarget,
) -> Result<ArtifactSignatureSummary, String> {
    err(state.content_signature(&target))
}

#[tauri::command]
fn content_preview(
    state: tauri::State<'_, BridgeState>,
    request: ContentPreviewRequest,
) -> Result<ContentPreviewResponse, String> {
    err(state.content_preview(&request))
}

#[tauri::command]
fn open_preview_session(
    state: tauri::State<'_, BridgeState>,
    request: PreviewSessionOpenRequest,
) -> Result<PreviewSessionInfo, String> {
    err(state.open_preview_session(&request))
}

#[tauri::command]
fn read_preview_chunk(
    state: tauri::State<'_, BridgeState>,
    session_id: String,
    offset: u64,
    length: u64,
) -> Result<PreviewChunkResponse, String> {
    err(state.read_preview_chunk(&session_id, offset, length))
}

#[tauri::command]
fn read_archive_page(
    state: tauri::State<'_, BridgeState>,
    session_id: String,
    offset: usize,
    limit: usize,
) -> Result<ArchivePreviewPage, String> {
    err(state.read_archive_page(&session_id, offset, limit))
}

#[tauri::command]
fn close_preview_session(
    state: tauri::State<'_, BridgeState>,
    session_id: String,
) -> Result<(), String> {
    err(state.close_preview_session(&session_id))
}

#[tauri::command]
fn start_preview_job(
    state: tauri::State<'_, BridgeState>,
    request: ContentPreviewRequest,
) -> Result<String, String> {
    err(state.start_preview_job(&request))
}

#[tauri::command]
fn preview_job_status(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<AsyncJobStatus, String> {
    err(state.preview_job_status(&job_id))
}

#[tauri::command]
fn preview_job_result(
    state: tauri::State<'_, BridgeState>,
    job_id: String,
) -> Result<ContentPreviewResponse, String> {
    err(state.preview_job_result(&job_id))
}

#[tauri::command]
fn cancel_preview_job(state: tauri::State<'_, BridgeState>, job_id: String) -> Result<(), String> {
    err(state.cancel_preview_job(&job_id))
}

#[tauri::command]
fn scan_snapshot(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
) -> Result<ScanSnapshot, String> {
    err(state.scan_snapshot(&scan_id))
}

#[tauri::command]
fn recent_scans(state: tauri::State<'_, BridgeState>) -> Result<Vec<ScanSnapshot>, String> {
    err(state.recent_scans())
}

#[tauri::command]
fn recover(
    state: tauri::State<'_, BridgeState>,
    request: RecoveryRequest,
) -> Result<RecoverySummary, String> {
    err(state.recover(request))
}

#[tauri::command]
fn export_reports(
    state: tauri::State<'_, BridgeState>,
    scan_id: String,
    destination: String,
) -> Result<rss_report::ReportBundle, String> {
    err(state.export(&scan_id, &destination))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .init();

    set_app_user_model_id();

    if let Err(error) = ensure_elevated() {
        show_fatal_startup_error(&error.to_string());
        std::process::exit(1);
    }

    let state = BridgeState::new(env!("CARGO_PKG_VERSION"), "../legal/EULA.md")
        .expect("failed to initialize application state");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if let Some(icon) = app.default_window_icon().cloned()
                && let Some(window) = app.get_webview_window("main")
            {
                window.set_icon(icon)?;
            }
            Ok(())
        })
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            bootstrap,
            list_sources,
            refresh_sources,
            load_source_catalog,
            source_catalog_status,
            cancel_source_load,
            browse_source,
            entry_details,
            start_entry_details_job,
            entry_details_job_status,
            entry_details_job_result,
            cancel_entry_details_job,
            start_scan,
            stop_scan,
            scan_progress,
            start_raw_evidence_refinement,
            raw_evidence_progress,
            cancel_raw_evidence_refinement,
            scan_results,
            artifact_details,
            artifact_signature,
            artifact_preview,
            content_signature,
            content_preview,
            open_preview_session,
            read_preview_chunk,
            read_archive_page,
            close_preview_session,
            start_preview_job,
            preview_job_status,
            preview_job_result,
            cancel_preview_job,
            scan_snapshot,
            recent_scans,
            recover,
            export_reports
        ])
        .run(tauri::generate_context!())
        .expect("error while running Files");
}

fn show_fatal_startup_error(message: &str) {
    #[cfg(target_os = "windows")]
    unsafe {
        let title = widestring("Files — by Jumarf");
        let body = widestring(message);
        let _ = MessageBoxW(
            None,
            PCWSTR::from_raw(body.as_ptr()),
            PCWSTR::from_raw(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }

    #[cfg(not(target_os = "windows"))]
    eprintln!("{message}");
}

fn set_app_user_model_id() {
    #[cfg(target_os = "windows")]
    unsafe {
        let app_id = widestring("dev.jumarf.files");
        let _ = SetCurrentProcessExplicitAppUserModelID(PCWSTR::from_raw(app_id.as_ptr()));
    }
}

#[cfg(target_os = "windows")]
fn widestring(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
