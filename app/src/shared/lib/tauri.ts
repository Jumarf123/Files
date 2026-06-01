import {
  mockArtifactPreview,
  mockArtifactSignature,
  mockArtifactDetails,
  mockBootstrap,
  mockBrowseSource,
  mockCancelEntryDetailsJob,
  mockCancelPreviewJob,
  mockCancelSourceLoad,
  mockContentPreview,
  mockContentSignature,
  mockEntryDetailsJobResult,
  mockEntryDetailsJobStatus,
  mockEntryDetails,
  mockExport,
  mockListenDeletedBrowseProgress,
  mockListenDeletedBrowseReady,
  mockListenSourceLoadComplete,
  mockListenSourceLoadProgress,
  mockListenScanProgress,
  mockListenScanResultsBatch,
  mockListSources,
  mockLoadSourceCatalog,
  mockRecentScans,
  mockRecover,
  mockCancelRawEvidenceRefinement,
  mockRawEvidenceProgress,
  mockScanProgress,
  mockScanResults,
  mockScanSnapshot,
  mockStartRawEvidenceRefinement,
  mockSourceCatalogStatus,
  mockStartEntryDetailsJob,
  mockStartPreviewJob,
  mockStartScan,
  mockStopScan,
  mockPreviewJobResult,
  mockPreviewJobStatus,
  mockOpenPreviewSession,
  mockReadArchivePage,
  mockReadPreviewChunk,
  mockClosePreviewSession,
} from "@/features/dashboard/mock";
import type {
  ArchivePreviewPage,
  AsyncJobStatus,
  ArtifactPreviewRequest,
  ArtifactPreviewResponse,
  ArtifactSummary,
  ArtifactRecord,
  ArtifactSignatureSummary,
  BrowseSourceRequest,
  BootstrapInfo,
  ContentPreviewRequest,
  ContentPreviewResponse,
  ContentTarget,
  DeletedBrowseProgressEvent,
  DeletedBrowseReadyEvent,
  PreviewChunkResponse,
  PreviewSessionInfo,
  PreviewSessionOpenRequest,
  RecoveryRequest,
  RecoverySummary,
  RawEvidenceRefinementProgress,
  RawEvidenceRefinementRequest,
  ReportBundle,
  ScanOptions,
  ScanProgress,
  ScanResultsBatch,
  ScanSnapshot,
  ScanSource,
  SourceCatalogStatus,
  SourceDirectoryListing,
  SourceEntryDetails,
} from "@/shared/types/api";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

const isTauriRuntime = typeof window !== "undefined" && typeof window.__TAURI_INTERNALS__ !== "undefined";

async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauriRuntime) {
    return invokeMock<T>(command, args);
  }

  const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
  try {
    return await tauriInvoke<T>(command, args);
  } catch (caughtError) {
    throw normalizeInvokeError(caughtError, command);
  }
}

function normalizeInvokeError(caughtError: unknown, command: string) {
  const normalizePreviewMessage = (message: string) => {
    const lower = message.toLowerCase();
    if (lower.includes("access is denied") || lower.includes("access denied") || lower.includes("sharing violation")) {
      return new Error("Access denied or file is locked. Preview bytes are unavailable.");
    }
    return new Error(message);
  };

  if (caughtError instanceof Error) {
    return normalizePreviewMessage(caughtError.message);
  }
  if (typeof caughtError === "string") {
    return normalizePreviewMessage(caughtError);
  }
  if (caughtError && typeof caughtError === "object") {
    const message = [
      "message" in caughtError && typeof caughtError.message === "string" ? caughtError.message : null,
      "error" in caughtError && typeof caughtError.error === "string" ? caughtError.error : null,
      "details" in caughtError && typeof caughtError.details === "string" ? caughtError.details : null,
    ]
      .filter(Boolean)
      .join(" • ");
    if (message) {
      return normalizePreviewMessage(message);
    }
    try {
      return new Error(JSON.stringify(caughtError));
    } catch {
      return new Error(`Command ${command} failed`);
    }
  }
  return new Error(`Command ${command} failed`);
}

function invokeMock<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  switch (command) {
    case "bootstrap":
      return mockBootstrap() as Promise<T>;
    case "list_sources":
    case "refresh_sources":
      return mockListSources() as Promise<T>;
    case "load_source_catalog":
      return mockLoadSourceCatalog(String(args?.sourceId), Boolean(args?.forceRebuild)) as Promise<T>;
    case "source_catalog_status":
      return mockSourceCatalogStatus(String(args?.sourceId)) as Promise<T>;
    case "cancel_source_load":
      return mockCancelSourceLoad(String(args?.loadId)) as Promise<T>;
    case "browse_source":
      return mockBrowseSource(args?.request as BrowseSourceRequest) as Promise<T>;
    case "entry_details":
      return mockEntryDetails(String(args?.sourceId), String(args?.path)) as Promise<T>;
    case "start_entry_details_job":
      return mockStartEntryDetailsJob(String(args?.sourceId), String(args?.path)) as Promise<T>;
    case "entry_details_job_status":
      return mockEntryDetailsJobStatus(String(args?.jobId)) as Promise<T>;
    case "entry_details_job_result":
      return mockEntryDetailsJobResult(String(args?.jobId)) as Promise<T>;
    case "cancel_entry_details_job":
      return mockCancelEntryDetailsJob(String(args?.jobId)) as Promise<T>;
    case "start_scan":
      return mockStartScan(args?.options as ScanOptions) as Promise<T>;
    case "stop_scan":
      return mockStopScan(String(args?.scanId)) as Promise<T>;
    case "scan_progress":
      return mockScanProgress(String(args?.scanId)) as Promise<T>;
    case "start_raw_evidence_refinement":
      return mockStartRawEvidenceRefinement(args?.request as RawEvidenceRefinementRequest) as Promise<T>;
    case "raw_evidence_progress":
      return mockRawEvidenceProgress(String(args?.jobId)) as Promise<T>;
    case "cancel_raw_evidence_refinement":
      return mockCancelRawEvidenceRefinement(String(args?.jobId)) as Promise<T>;
    case "scan_results":
      return mockScanResults(String(args?.scanId)) as Promise<T>;
    case "artifact_details":
      return mockArtifactDetails(String(args?.scanId), String(args?.artifactId)) as Promise<T>;
    case "artifact_signature":
      return mockArtifactSignature(String(args?.scanId), String(args?.artifactId)) as Promise<T>;
    case "artifact_preview":
      return mockArtifactPreview(args?.request as ArtifactPreviewRequest) as Promise<T>;
    case "content_signature":
      return mockContentSignature(args?.target as ContentTarget) as Promise<T>;
    case "content_preview":
      return mockContentPreview(args?.request as ContentPreviewRequest) as Promise<T>;
    case "open_preview_session":
      return mockOpenPreviewSession(args?.request as PreviewSessionOpenRequest) as Promise<T>;
    case "read_preview_chunk":
      return mockReadPreviewChunk(String(args?.sessionId), Number(args?.offset), Number(args?.length)) as Promise<T>;
    case "read_archive_page":
      return mockReadArchivePage(String(args?.sessionId), Number(args?.offset), Number(args?.limit)) as Promise<T>;
    case "close_preview_session":
      return mockClosePreviewSession(String(args?.sessionId)) as Promise<T>;
    case "start_preview_job":
      return mockStartPreviewJob(args?.request as ContentPreviewRequest) as Promise<T>;
    case "preview_job_status":
      return mockPreviewJobStatus(String(args?.jobId)) as Promise<T>;
    case "preview_job_result":
      return mockPreviewJobResult(String(args?.jobId)) as Promise<T>;
    case "cancel_preview_job":
      return mockCancelPreviewJob(String(args?.jobId)) as Promise<T>;
    case "scan_snapshot":
      return mockScanSnapshot(String(args?.scanId)) as Promise<T>;
    case "recent_scans":
      return mockRecentScans() as Promise<T>;
    case "recover":
      return mockRecover(args?.request as RecoveryRequest) as Promise<T>;
    case "export_reports":
      return mockExport(String(args?.scanId), String(args?.destination)) as Promise<T>;
    default:
      return Promise.reject(new Error(`Unknown command: ${command}`));
  }
}

export async function chooseDirectory(title: string) {
  if (isTauriRuntime) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const result = await open({
      directory: true,
      multiple: false,
      title,
    });

    return typeof result === "string" ? result : null;
  }

  return window.prompt(`${title}\n\nEnter a destination path`, "C:\\Recovered") ?? null;
}

export function inTauri() {
  return isTauriRuntime;
}

export function bootstrap() {
  return invoke<BootstrapInfo>("bootstrap");
}

export function listSources() {
  return invoke<ScanSource[]>("list_sources");
}

export function refreshSources() {
  return invoke<ScanSource[]>("refresh_sources");
}

export function loadSourceCatalog(sourceId: string, forceRebuild = false) {
  return invoke<string>("load_source_catalog", { sourceId, forceRebuild });
}

export function sourceCatalogStatus(sourceId: string) {
  return invoke<SourceCatalogStatus>("source_catalog_status", { sourceId });
}

export function cancelSourceLoad(loadId: string) {
  return invoke<void>("cancel_source_load", { loadId });
}

export function browseSource(request: BrowseSourceRequest) {
  return invoke<SourceDirectoryListing>("browse_source", { request });
}

export function entryDetails(sourceId: string, path: string) {
  return invoke<SourceEntryDetails>("entry_details", { sourceId, path });
}

export function startEntryDetailsJob(sourceId: string, path: string) {
  return invoke<string>("start_entry_details_job", { sourceId, path });
}

export function entryDetailsJobStatus(jobId: string) {
  return invoke<AsyncJobStatus>("entry_details_job_status", { jobId });
}

export function entryDetailsJobResult(jobId: string) {
  return invoke<SourceEntryDetails>("entry_details_job_result", { jobId });
}

export function cancelEntryDetailsJob(jobId: string) {
  return invoke<void>("cancel_entry_details_job", { jobId });
}

export function startScan(options: ScanOptions) {
  return invoke<string>("start_scan", { options });
}

export function stopScan(scanId: string) {
  return invoke<void>("stop_scan", { scanId });
}

export function scanProgress(scanId: string) {
  return invoke<ScanProgress>("scan_progress", { scanId });
}

export function startRawEvidenceRefinement(request: RawEvidenceRefinementRequest) {
  return invoke<string>("start_raw_evidence_refinement", { request });
}

export function rawEvidenceProgress(jobId: string) {
  return invoke<RawEvidenceRefinementProgress>("raw_evidence_progress", { jobId });
}

export function cancelRawEvidenceRefinement(jobId: string) {
  return invoke<void>("cancel_raw_evidence_refinement", { jobId });
}

export function scanResults(scanId: string) {
  return invoke<ArtifactSummary[]>("scan_results", { scanId });
}

export function artifactDetails(scanId: string, artifactId: string) {
  return invoke<ArtifactRecord>("artifact_details", { scanId, artifactId });
}

export function artifactSignature(scanId: string, artifactId: string) {
  return invoke<ArtifactSignatureSummary>("artifact_signature", { scanId, artifactId });
}

export function artifactPreview(request: ArtifactPreviewRequest) {
  return invoke<ArtifactPreviewResponse>("artifact_preview", { request });
}

export function contentSignature(target: ContentTarget) {
  return invoke<ArtifactSignatureSummary>("content_signature", { target });
}

export function contentPreview(request: ContentPreviewRequest) {
  return invoke<ContentPreviewResponse>("content_preview", { request });
}

export function openPreviewSession(request: PreviewSessionOpenRequest) {
  return invoke<PreviewSessionInfo>("open_preview_session", { request });
}

export function readPreviewChunk(sessionId: string, offset: number, length: number) {
  return invoke<PreviewChunkResponse>("read_preview_chunk", { sessionId, offset, length });
}

export function readArchivePage(sessionId: string, offset: number, limit: number) {
  return invoke<ArchivePreviewPage>("read_archive_page", { sessionId, offset, limit });
}

export function closePreviewSession(sessionId: string) {
  return invoke<void>("close_preview_session", { sessionId });
}

export function startPreviewJob(request: ContentPreviewRequest) {
  return invoke<string>("start_preview_job", { request });
}

export function previewJobStatus(jobId: string) {
  return invoke<AsyncJobStatus>("preview_job_status", { jobId });
}

export function previewJobResult(jobId: string) {
  return invoke<ContentPreviewResponse>("preview_job_result", { jobId });
}

export function cancelPreviewJob(jobId: string) {
  return invoke<void>("cancel_preview_job", { jobId });
}

export function scanSnapshot(scanId: string) {
  return invoke<ScanSnapshot>("scan_snapshot", { scanId });
}

export function recentScans() {
  return invoke<ScanSnapshot[]>("recent_scans");
}

export function recover(request: RecoveryRequest) {
  return invoke<RecoverySummary>("recover", { request });
}

export function exportReports(scanId: string, destination: string) {
  return invoke<ReportBundle>("export_reports", { scanId, destination });
}

export async function listenScanProgress(listener: (progress: ScanProgress) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<ScanProgress>("scan-progress", (event) => listener(event.payload));
  }

  return mockListenScanProgress(listener);
}

export async function listenScanResultsBatch(listener: (batch: ScanResultsBatch) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<ScanResultsBatch>("scan-results-batch", (event) =>
      listener(event.payload),
    );
  }

  return mockListenScanResultsBatch(listener);
}

export async function listenSourceLoadProgress(listener: (status: SourceCatalogStatus) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<SourceCatalogStatus>("source-load-progress", (event) =>
      listener(event.payload),
    );
  }

  return mockListenSourceLoadProgress(listener);
}

export async function listenSourceLoadComplete(listener: (status: SourceCatalogStatus) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<SourceCatalogStatus>("source-load-complete", (event) =>
      listener(event.payload),
    );
  }

  return mockListenSourceLoadComplete(listener);
}

export async function listenDeletedBrowseReady(listener: (event: DeletedBrowseReadyEvent) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<DeletedBrowseReadyEvent>("deleted-browse-ready", (event) =>
      listener(event.payload),
    );
  }

  return mockListenDeletedBrowseReady(listener);
}

export async function listenDeletedBrowseProgress(listener: (event: DeletedBrowseProgressEvent) => void) {
  if (isTauriRuntime) {
    const { getCurrentWebview } = await import("@tauri-apps/api/webview");
    return getCurrentWebview().listen<DeletedBrowseProgressEvent>("deleted-browse-progress", (event) =>
      listener(event.payload),
    );
  }

  return mockListenDeletedBrowseProgress(listener);
}
