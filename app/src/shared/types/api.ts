export type SourceKind = "logical_volume" | "physical_disk" | "image_file";
export type FileSystemKind = "ntfs" | "fat32" | "ex_fat" | "unknown";
export type SourceAccessState = "readable" | "denied" | "unknown";
export type SourceEntryClass = "file" | "directory" | "metadata_file" | "metadata_directory";
export type SourceCatalogState = "unloaded" | "loading" | "ready" | "stale" | "failed";
export type SourceCatalogPhase =
  | "opening_volume"
  | "enumerating_files"
  | "augmenting_ntfs_metadata"
  | "building_indexes"
  | "finalizing";
export type SourceCatalogCacheState = "cold" | "warm" | "delta_refresh" | "rebuild";
export type ScanMode = "fast" | "deep";
export type RawEvidenceMode = "fast_lazy" | "full_exhaustive" | "manual_deep";
export type RawEvidenceState = "not_started" | "running" | "completed" | "completed_with_warnings";
export type RawEvidenceRefinementPhase =
  | "queued"
  | "building_directory_map"
  | "parsing_i30"
  | "reading_usn"
  | "merging_evidence"
  | "done";
export type ScanStatus = "idle" | "running" | "completed" | "completed_with_warnings" | "failed" | "cancelled";
export type ScanPhase =
  | "preparing"
  | "discovering_metadata"
  | "scanning_deleted_entries"
  | "refining_raw_evidence"
  | "carving_high_priority"
  | "hashing"
  | "finalizing";
export type OriginType =
  | "filesystem_deleted_entry"
  | "filesystem_orphaned_entry"
  | "unallocated_carved"
  | "partial_fragment";
export type Confidence = "high" | "medium" | "low";
export type Recoverability = "good" | "partial" | "poor" | "unknown";
export type PlacementKind =
  | "original_path"
  | "synthetic_deleted_folder"
  | "unknown_parent"
  | "broken_parent_chain"
  | "out_of_selected_root"
  | "path_conflict";
export type PathConfidence = "exact" | "reconstructed" | "partial" | "unknown";
export type PathEvidenceSource =
  | "mft_exact"
  | "mft_deleted_directory"
  | "mft_sequence_mismatch"
  | "partial_mft_chain"
  | "recycle_bin"
  | "i30"
  | "usn_journal";
export interface PathEvidence {
  source: PathEvidenceSource;
  path: string | null;
  confidence: PathConfidence;
  note: string;
}
export type DeletedTimeSource = "recycle_bin" | "usn_journal" | "i30_mft_change" | "mft_metadata";
export type DeletedTimeConfidence = "exact" | "estimated" | "unknown";
export type NameSourceKind = "long_name" | "dos_name" | "reconstructed" | "generated";
export type ContentSourceKind =
  | "resident_data"
  | "raw_runs"
  | "contiguous_carve"
  | "fragment_candidate"
  | "live_file"
  | "unknown";
export type ArtifactClass =
  | "named_metadata_candidate"
  | "validated_hit"
  | "recoverable"
  | "carved_hit"
  | "fragment_candidate";
export type RecoveryStatus =
  | "recovered"
  | "recovered_with_warnings"
  | "partial"
  | "unrecoverable"
  | "skipped";
export type ArtifactFamily =
  | "archive"
  | "executable"
  | "script"
  | "container"
  | "database"
  | "document"
  | "image"
  | "config"
  | "text"
  | "binary"
  | "unknown";
export type ArtifactKind =
  | "exe"
  | "dll"
  | "sys"
  | "scr"
  | "ocx"
  | "cpl"
  | "msi"
  | "jar"
  | "zip"
  | "rar"
  | "seven_zip"
  | "cab"
  | "iso"
  | "tar"
  | "gzip"
  | "bzip2"
  | "xz"
  | "apk"
  | "pdf"
  | "png"
  | "jpg"
  | "gif"
  | "sqlite"
  | "pak"
  | "bin"
  | "dat"
  | "bat"
  | "cmd"
  | "ps1"
  | "vbs"
  | "js"
  | "ini"
  | "cfg"
  | "json"
  | "yml"
  | "yaml"
  | "txt"
  | "log"
  | "ole_compound"
  | "pe"
  | "unknown";

export interface ScanSource {
  id: string;
  kind: SourceKind;
  device_path: string;
  mount_point: string | null;
  display_name: string;
  volume_label: string | null;
  filesystem: FileSystemKind;
  volume_serial: number | null;
  total_bytes: number;
  free_bytes: number;
  cluster_size: number | null;
  is_system: boolean;
  requires_elevation: boolean;
}

export interface SourceCatalogStatus {
  state: SourceCatalogState;
  source_id: string;
  load_id: string | null;
  phase: SourceCatalogPhase | null;
  progress_percent: number;
  indexed_entries: number;
  total_estimated_entries: number | null;
  cache_state: SourceCatalogCacheState;
  started_at: string | null;
  updated_at: string;
  error: string | null;
  error_code: string | null;
  error_detail: string | null;
}

export interface SourceEntry {
  name: string;
  path: string;
  parent_path: string;
  mft_reference: number | null;
  parent_reference: number | null;
  extension: string | null;
  is_directory: boolean;
  has_children: boolean | null;
  is_metafile: boolean;
  entry_class: SourceEntryClass;
  size: number;
  created_at: string | null;
  modified_at: string | null;
  accessed_at: string | null;
  hidden: boolean;
  system: boolean;
  read_only: boolean;
  attr_bits: number | null;
  attributes: string[];
  deleted_hits: number;
  access_state: SourceAccessState;
}

export interface SourceDirectoryListing {
  source_id: string;
  root_path: string;
  path: string;
  parent_path: string | null;
  entries: SourceEntry[];
  deleted_artifacts: ArtifactSummary[];
  total_entry_count: number;
  deleted_artifact_count: number;
  next_cursor: string | null;
  deleted_artifact_next_cursor: string | null;
  indexing_complete: boolean;
  indexed_entries: number;
  total_estimated_entries: number | null;
  index_generation: number;
  deleted_subtree_count: number;
}

export interface BrowseSourceRequest {
  source_id: string;
  path?: string | null;
  cursor?: string | null;
  deleted_cursor?: string | null;
  limit?: number | null;
  directories_only?: boolean | null;
  filter?: string | null;
  sort_key?: string | null;
  sort_direction?: "asc" | "desc" | null;
}

export interface ScanOptions {
  source_id: string;
  mode: ScanMode;
  include_low_confidence: boolean;
  carve_budget_bytes: number | null;
  raw_evidence?: RawEvidenceConfig | null;
}

export interface RawEvidenceConfig {
  mode: RawEvidenceMode;
  i30_enabled: boolean;
  usn_enabled: boolean;
  raw_usn_fallback: boolean;
  emit_initial_results_before_raw: boolean;
}

export interface ScanProgress {
  scan_id: string;
  status: ScanStatus;
  phase: ScanPhase;
  stage: string;
  progress_percent: number;
  files_examined: number;
  artifacts_found: number;
  records_scanned?: number;
  candidates_surfaced?: number;
  validated_hits?: number;
  named_hits?: number;
  carved_hits?: number;
  fragment_hits?: number;
  verified_hits?: number;
  recoverable_hits?: number;
  bytes_scanned: number;
  records_per_second?: number;
  eta_seconds: number | null;
  target_sla_seconds: number;
  raw_evidence_state?: RawEvidenceState;
  message: string;
  stage_timing_ms: Record<string, number>;
  started_at: string;
  last_progress_at?: string;
  updated_at: string;
}

export interface RawEvidenceRefinementRequest {
  scan_id: string;
  source_id: string;
  scope?: string | null;
}

export interface RawEvidenceRefinementProgress {
  job_id: string;
  scan_id: string;
  source_id: string;
  state: AsyncJobState;
  phase: RawEvidenceRefinementPhase;
  progress_percent: number;
  processed_units: number;
  total_units: number | null;
  message: string;
  warnings: string[];
  started_at: string;
  updated_at: string;
}

export interface ScanCounters {
  total_results: number;
  executable_results: number;
  archive_results: number;
  script_results: number;
  carved_results: number;
  partial_results: number;
  recoverable_results: number;
}

export interface PreviewFact {
  label: string;
  value: string;
}

export type ArtifactSignatureStatus = "not_applicable" | "none" | "valid" | "invalid" | "indeterminate";

export interface ArtifactSignatureSummary {
  status: ArtifactSignatureStatus;
  subject: string | null;
  issuer: string | null;
  timestamp: string | null;
  verification_source: string;
  note: string | null;
}

export type ArtifactPreviewMode = "auto" | "text" | "hex" | "archive";
export type ArchivePreviewEntryStatus = "ok" | "partial" | "damaged" | "unsupported";

export interface ArchivePreviewEntry {
  path: string;
  kind: string | null;
  size: number | null;
  compressed_size: number | null;
  status: ArchivePreviewEntryStatus;
  note: string | null;
}

export interface HexPreviewRow {
  offset: number;
  hex: string;
  ascii: string;
}

export interface ArtifactPreviewRequest {
  scan_id: string;
  artifact_id: string;
  mode: ArtifactPreviewMode;
  offset?: number | null;
  length?: number | null;
  max_entries?: number | null;
}

export interface ArtifactPreviewResponse {
  artifact_id: string;
  requested_mode: ArtifactPreviewMode;
  resolved_mode: ArtifactPreviewMode;
  offset: number;
  length: number;
  total_size: number;
  has_more: boolean;
  warnings: string[];
  summary: PreviewFact[];
  text_excerpt: string | null;
  hex_rows: HexPreviewRow[];
  archive_entry_count: number | null;
  archive_entries_truncated: boolean;
  archive_entries: ArchivePreviewEntry[];
}

export type ContentTarget =
  | {
      kind: "artifact";
      scan_id: string;
      artifact_id: string;
    }
  | {
      kind: "entry";
      source_id: string;
      path: string;
    };

export interface ContentPreviewRequest {
  target: ContentTarget;
  entry_hint?: SourceEntry | null;
  mode: ArtifactPreviewMode;
  offset?: number | null;
  length?: number | null;
  max_entries?: number | null;
}

export interface ContentPreviewResponse {
  target_key: string;
  requested_mode: ArtifactPreviewMode;
  resolved_mode: ArtifactPreviewMode;
  offset: number;
  length: number;
  total_size: number;
  has_more: boolean;
  warnings: string[];
  summary: PreviewFact[];
  text_excerpt: string | null;
  hex_rows: HexPreviewRow[];
  archive_entry_count: number | null;
  archive_entries_truncated: boolean;
  archive_entries: ArchivePreviewEntry[];
}

export interface PreviewSessionOpenRequest {
  target: ContentTarget;
  entry_hint?: SourceEntry | null;
  mode: ArtifactPreviewMode;
}

export interface PreviewSessionInfo {
  session_id: string;
  target_key: string;
  requested_mode: ArtifactPreviewMode;
  resolved_mode: ArtifactPreviewMode;
  total_size: number;
  summary: PreviewFact[];
  warnings: string[];
  preview_ready: boolean;
  archive_entry_count: number | null;
  archive_entries_truncated: boolean;
}

export interface PreviewChunkResponse {
  session_id: string;
  target_key: string;
  requested_mode: ArtifactPreviewMode;
  resolved_mode: ArtifactPreviewMode;
  offset: number;
  length: number;
  total_size: number;
  has_more: boolean;
  warnings: string[];
  text_excerpt: string | null;
  hex_rows: HexPreviewRow[];
}

export interface ArchivePreviewPage {
  session_id: string;
  target_key: string;
  offset: number;
  count: number;
  total_entries: number | null;
  has_more: boolean;
  warnings: string[];
  entries: ArchivePreviewEntry[];
}

export type AsyncJobState = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface AsyncJobStatus {
  job_id: string;
  state: AsyncJobState;
  created_at: string;
  updated_at: string;
  error: string | null;
}

export interface SourceEntryDetails {
  entry: SourceEntry;
  notes: string[];
  summary: PreviewFact[];
}

export interface ByteRun {
  offset: number;
  length: number;
  sparse: boolean;
}

export type RecoveryPlan =
  | {
      kind: "resident_base64";
      base64: string;
      logical_size: number;
    }
  | {
      kind: "raw_runs";
      source_path: string;
      runs: ByteRun[];
      logical_size: number;
    }
  | {
      kind: "unrecoverable";
      reason: string;
    };

export interface ArtifactRecord {
  id: string;
  scan_id: string;
  source_id: string;
  name: string;
  original_path: string | null;
  probable_path: string | null;
  placement_kind: PlacementKind;
  path_confidence: PathConfidence;
  path_evidence: PathEvidence[];
  name_source: NameSourceKind;
  content_source: ContentSourceKind;
  artifact_class: ArtifactClass;
  preview_ready: boolean;
  is_fragment: boolean;
  fragment_id: string | null;
  extension: string | null;
  family: ArtifactFamily;
  kind: ArtifactKind;
  origin_type: OriginType;
  confidence: Confidence;
  recoverability: Recoverability;
  deleted_entry: boolean;
  size: number;
  priority_score: number;
  filesystem_record: number | null;
  parent_reference: number | null;
  raw_offset: number | null;
  raw_length: number | null;
  created_at: string | null;
  modified_at: string | null;
  deleted_at: string | null;
  deleted_time_source: DeletedTimeSource | null;
  deleted_time_confidence: DeletedTimeConfidence;
  last_metadata_change_at: string | null;
  notes: string[];
  preview: PreviewFact[];
  recovery_plan: RecoveryPlan;
}

export interface ArtifactSummary {
  id: string;
  scan_id: string;
  source_id: string;
  name: string;
  original_path: string | null;
  probable_path: string | null;
  placement_kind: PlacementKind;
  path_confidence: PathConfidence;
  path_evidence: PathEvidence[];
  name_source: NameSourceKind;
  content_source: ContentSourceKind;
  artifact_class: ArtifactClass;
  preview_ready: boolean;
  is_fragment: boolean;
  fragment_id: string | null;
  extension: string | null;
  family: ArtifactFamily;
  kind: ArtifactKind;
  origin_type: OriginType;
  confidence: Confidence;
  recoverability: Recoverability;
  deleted_entry: boolean;
  size: number;
  priority_score: number;
  filesystem_record: number | null;
  parent_reference: number | null;
  raw_offset: number | null;
  raw_length: number | null;
  created_at: string | null;
  modified_at: string | null;
  deleted_at: string | null;
  deleted_time_source: DeletedTimeSource | null;
  deleted_time_confidence: DeletedTimeConfidence;
  last_metadata_change_at: string | null;
}

export interface ScanResultsBatch {
  scan_id: string;
  offset: number;
  total_known: number;
  results: ArtifactSummary[];
}

export interface ScanSummary {
  scan_id: string;
  source_id: string;
  source_name: string;
  mode: ScanMode;
  filesystem: FileSystemKind;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  duration_seconds: number | null;
  warnings: string[];
  counters: ScanCounters;
}

export interface RecoveryRequest {
  scan_id: string;
  artifact_ids: string[];
  destination: string;
}

export interface RecoveryItemResult {
  artifact_id: string;
  file_path: string | null;
  metadata_path: string | null;
  sha256: string | null;
  blake3: string | null;
  status: RecoveryStatus;
  notes: string[];
}

export interface RecoverySummary {
  scan_id: string;
  destination: string;
  started_at: string;
  finished_at: string;
  items: RecoveryItemResult[];
}

export interface ScanSnapshot {
  summary: ScanSummary;
  source: ScanSource;
  progress: ScanProgress;
  results: ArtifactRecord[];
}

export interface DeletedBrowseReadyEvent {
  scan_id: string;
  source_id: string;
}

export interface DeletedBrowseProgressEvent {
  scan_id: string;
  source_id: string;
  processed_artifacts: number;
  total_artifacts: number;
  progress_percent: number;
}

export interface BootstrapInfo {
  app_name: string;
  app_author: string;
  app_version: string;
  license: string;
  eula_path: string;
  is_elevated: boolean;
  source_count: number;
}

export interface ReportBundle {
  json_path: string;
  csv_path: string;
  html_path: string;
  dfxml_path: string;
}
