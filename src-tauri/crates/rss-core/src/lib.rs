use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub type RssResult<T> = Result<T, RssError>;

#[derive(Debug, Error)]
pub enum RssError {
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    LogicalVolume,
    PhysicalDisk,
    ImageFile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileSystemKind {
    Ntfs,
    Fat32,
    ExFat,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Fast,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawEvidenceMode {
    FastLazy,
    FullExhaustive,
    ManualDeep,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawEvidenceConfig {
    pub mode: RawEvidenceMode,
    pub i30_enabled: bool,
    pub usn_enabled: bool,
    pub raw_usn_fallback: bool,
    pub emit_initial_results_before_raw: bool,
}

impl Default for RawEvidenceConfig {
    fn default() -> Self {
        Self {
            mode: RawEvidenceMode::ManualDeep,
            i30_enabled: false,
            usn_enabled: false,
            raw_usn_fallback: false,
            emit_initial_results_before_raw: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawEvidenceState {
    NotStarted,
    Running,
    Completed,
    CompletedWithWarnings,
}

impl Default for RawEvidenceState {
    fn default() -> Self {
        Self::NotStarted
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Idle,
    Running,
    Completed,
    CompletedWithWarnings,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedWithWarnings | Self::Failed | Self::Cancelled
        )
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Completed | Self::CompletedWithWarnings)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Preparing,
    DiscoveringMetadata,
    ScanningDeletedEntries,
    RefiningRawEvidence,
    CarvingHighPriority,
    Hashing,
    Finalizing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OriginType {
    FilesystemDeletedEntry,
    FilesystemOrphanedEntry,
    UnallocatedCarved,
    PartialFragment,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Recoverability {
    Good,
    Partial,
    Poor,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PlacementKind {
    OriginalPath,
    SyntheticDeletedFolder,
    UnknownParent,
    BrokenParentChain,
    OutOfSelectedRoot,
    PathConflict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PathConfidence {
    Exact,
    Reconstructed,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PathEvidenceSource {
    MftExact,
    MftDeletedDirectory,
    MftSequenceMismatch,
    PartialMftChain,
    RecycleBin,
    I30,
    UsnJournal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEvidence {
    pub source: PathEvidenceSource,
    pub path: Option<String>,
    pub confidence: PathConfidence,
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeletedTimeSource {
    RecycleBin,
    UsnJournal,
    I30MftChange,
    MftMetadata,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeletedTimeConfidence {
    Exact,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NameSourceKind {
    LongName,
    DosName,
    Reconstructed,
    Generated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContentSourceKind {
    ResidentData,
    RawRuns,
    ContiguousCarve,
    FragmentCandidate,
    LiveFile,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    NamedMetadataCandidate,
    ValidatedHit,
    Recoverable,
    CarvedHit,
    FragmentCandidate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Recovered,
    RecoveredWithWarnings,
    Partial,
    Unrecoverable,
    Skipped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFamily {
    Archive,
    Executable,
    Script,
    Container,
    Database,
    Document,
    Image,
    Config,
    Text,
    Binary,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Exe,
    Dll,
    Sys,
    Scr,
    Ocx,
    Cpl,
    Msi,
    Jar,
    Zip,
    Rar,
    SevenZip,
    Cab,
    Iso,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Apk,
    Pdf,
    Png,
    Jpg,
    Gif,
    Sqlite,
    Pak,
    Bin,
    Dat,
    Bat,
    Cmd,
    Ps1,
    Vbs,
    Js,
    Ini,
    Cfg,
    Json,
    Yml,
    Yaml,
    Txt,
    Log,
    OleCompound,
    Pe,
    Unknown,
}

impl ArtifactKind {
    pub fn family(self) -> ArtifactFamily {
        match self {
            Self::Exe
            | Self::Dll
            | Self::Sys
            | Self::Scr
            | Self::Ocx
            | Self::Cpl
            | Self::Msi
            | Self::Jar
            | Self::Pe => ArtifactFamily::Executable,
            Self::Zip
            | Self::Rar
            | Self::SevenZip
            | Self::Cab
            | Self::Iso
            | Self::Tar
            | Self::Gzip
            | Self::Bzip2
            | Self::Xz => ArtifactFamily::Archive,
            Self::Bat | Self::Cmd | Self::Ps1 | Self::Vbs | Self::Js => ArtifactFamily::Script,
            Self::Apk | Self::Pak | Self::Bin | Self::Dat | Self::OleCompound => {
                ArtifactFamily::Container
            }
            Self::Sqlite => ArtifactFamily::Database,
            Self::Pdf => ArtifactFamily::Document,
            Self::Png | Self::Jpg | Self::Gif => ArtifactFamily::Image,
            Self::Ini | Self::Cfg | Self::Json | Self::Yml | Self::Yaml => ArtifactFamily::Config,
            Self::Txt | Self::Log => ArtifactFamily::Text,
            Self::Unknown => ArtifactFamily::Unknown,
        }
    }

    pub fn priority_score(self) -> u16 {
        match self.family() {
            ArtifactFamily::Executable => 100,
            ArtifactFamily::Archive => 90,
            ArtifactFamily::Script => 75,
            ArtifactFamily::Database => 70,
            ArtifactFamily::Container => 60,
            ArtifactFamily::Document => 55,
            ArtifactFamily::Image => 50,
            ArtifactFamily::Config => 40,
            ArtifactFamily::Text => 30,
            ArtifactFamily::Binary => 20,
            ArtifactFamily::Unknown => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSource {
    pub id: String,
    pub kind: SourceKind,
    pub device_path: String,
    pub mount_point: Option<String>,
    pub display_name: String,
    pub volume_label: Option<String>,
    pub filesystem: FileSystemKind,
    pub volume_serial: Option<u32>,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub cluster_size: Option<u64>,
    pub is_system: bool,
    pub requires_elevation: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceCatalogState {
    Unloaded,
    Loading,
    Ready,
    Stale,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceCatalogPhase {
    OpeningVolume,
    EnumeratingFiles,
    AugmentingNtfsMetadata,
    BuildingIndexes,
    Finalizing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceCatalogCacheState {
    Cold,
    Warm,
    DeltaRefresh,
    Rebuild,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCatalogStatus {
    pub state: SourceCatalogState,
    pub source_id: String,
    pub load_id: Option<String>,
    pub phase: Option<SourceCatalogPhase>,
    pub progress_percent: f32,
    pub indexed_entries: u64,
    pub total_estimated_entries: Option<u64>,
    pub cache_state: SourceCatalogCacheState,
    pub started_at: Option<String>,
    pub updated_at: String,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceAccessState {
    Readable,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceEntryClass {
    File,
    Directory,
    MetadataFile,
    MetadataDirectory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    pub name: String,
    pub path: String,
    pub parent_path: String,
    pub mft_reference: Option<u64>,
    pub parent_reference: Option<u64>,
    pub extension: Option<String>,
    pub is_directory: bool,
    pub has_children: Option<bool>,
    pub is_metafile: bool,
    pub entry_class: SourceEntryClass,
    pub size: u64,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub accessed_at: Option<String>,
    pub hidden: bool,
    pub system: bool,
    pub read_only: bool,
    pub attr_bits: Option<u32>,
    pub attributes: Vec<String>,
    pub deleted_hits: usize,
    pub access_state: SourceAccessState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDirectoryListing {
    pub source_id: String,
    pub root_path: String,
    pub path: String,
    pub parent_path: Option<String>,
    pub entries: Vec<SourceEntry>,
    pub deleted_artifacts: Vec<ArtifactSummary>,
    pub total_entry_count: usize,
    pub deleted_artifact_count: usize,
    pub next_cursor: Option<String>,
    pub deleted_artifact_next_cursor: Option<String>,
    pub indexing_complete: bool,
    pub indexed_entries: u64,
    pub total_estimated_entries: Option<u64>,
    pub index_generation: u64,
    pub deleted_subtree_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseSourceRequest {
    pub source_id: String,
    pub path: Option<String>,
    pub cursor: Option<String>,
    pub deleted_cursor: Option<String>,
    pub limit: Option<usize>,
    pub directories_only: Option<bool>,
    pub filter: Option<String>,
    pub sort_key: Option<String>,
    pub sort_direction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub source_id: String,
    pub mode: ScanMode,
    pub include_low_confidence: bool,
    pub carve_budget_bytes: Option<u64>,
    #[serde(default)]
    pub raw_evidence: RawEvidenceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: ScanStatus,
    pub phase: ScanPhase,
    pub stage: String,
    pub progress_percent: f32,
    pub files_examined: u64,
    pub artifacts_found: u64,
    pub records_scanned: u64,
    pub candidates_surfaced: u64,
    pub validated_hits: u64,
    pub named_hits: u64,
    pub carved_hits: u64,
    pub fragment_hits: u64,
    pub verified_hits: u64,
    pub recoverable_hits: u64,
    pub bytes_scanned: u64,
    #[serde(default)]
    pub records_per_second: f32,
    pub eta_seconds: Option<u64>,
    pub target_sla_seconds: u64,
    #[serde(default)]
    pub raw_evidence_state: RawEvidenceState,
    pub message: String,
    pub stage_timing_ms: BTreeMap<String, u64>,
    pub started_at: String,
    #[serde(default)]
    pub last_progress_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvidenceRefinementRequest {
    pub scan_id: String,
    pub source_id: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawEvidenceRefinementPhase {
    Queued,
    BuildingDirectoryMap,
    ParsingI30,
    ReadingUsn,
    MergingEvidence,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvidenceRefinementProgress {
    pub job_id: String,
    pub scan_id: String,
    pub source_id: String,
    pub state: AsyncJobState,
    pub phase: RawEvidenceRefinementPhase,
    pub progress_percent: f32,
    pub processed_units: u64,
    pub total_units: Option<u64>,
    pub message: String,
    pub warnings: Vec<String>,
    pub started_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanCounters {
    pub total_results: usize,
    pub executable_results: usize,
    pub archive_results: usize,
    pub script_results: usize,
    pub carved_results: usize,
    pub partial_results: usize,
    pub recoverable_results: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewFact {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSignatureStatus {
    NotApplicable,
    None,
    Valid,
    Invalid,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSignatureSummary {
    pub status: ArtifactSignatureStatus,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub timestamp: Option<String>,
    pub verification_source: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPreviewMode {
    Auto,
    Text,
    Hex,
    Archive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchivePreviewEntryStatus {
    Ok,
    Partial,
    Damaged,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePreviewEntry {
    pub path: String,
    pub kind: Option<String>,
    pub size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub status: ArchivePreviewEntryStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPreviewRow {
    pub offset: u64,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPreviewRequest {
    pub scan_id: String,
    pub artifact_id: String,
    pub mode: ArtifactPreviewMode,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPreviewResponse {
    pub artifact_id: String,
    pub requested_mode: ArtifactPreviewMode,
    pub resolved_mode: ArtifactPreviewMode,
    pub offset: u64,
    pub length: u64,
    pub total_size: u64,
    pub has_more: bool,
    pub warnings: Vec<String>,
    pub summary: Vec<PreviewFact>,
    pub text_excerpt: Option<String>,
    pub hex_rows: Vec<HexPreviewRow>,
    pub archive_entry_count: Option<usize>,
    pub archive_entries_truncated: bool,
    pub archive_entries: Vec<ArchivePreviewEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentTarget {
    Artifact {
        scan_id: String,
        artifact_id: String,
    },
    Entry {
        source_id: String,
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPreviewRequest {
    pub target: ContentTarget,
    pub entry_hint: Option<SourceEntry>,
    pub mode: ArtifactPreviewMode,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPreviewResponse {
    pub target_key: String,
    pub requested_mode: ArtifactPreviewMode,
    pub resolved_mode: ArtifactPreviewMode,
    pub offset: u64,
    pub length: u64,
    pub total_size: u64,
    pub has_more: bool,
    pub warnings: Vec<String>,
    pub summary: Vec<PreviewFact>,
    pub text_excerpt: Option<String>,
    pub hex_rows: Vec<HexPreviewRow>,
    pub archive_entry_count: Option<usize>,
    pub archive_entries_truncated: bool,
    pub archive_entries: Vec<ArchivePreviewEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewSessionOpenRequest {
    pub target: ContentTarget,
    pub entry_hint: Option<SourceEntry>,
    pub mode: ArtifactPreviewMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewSessionInfo {
    pub session_id: String,
    pub target_key: String,
    pub requested_mode: ArtifactPreviewMode,
    pub resolved_mode: ArtifactPreviewMode,
    pub total_size: u64,
    pub summary: Vec<PreviewFact>,
    pub warnings: Vec<String>,
    pub preview_ready: bool,
    pub archive_entry_count: Option<usize>,
    pub archive_entries_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewChunkResponse {
    pub session_id: String,
    pub target_key: String,
    pub requested_mode: ArtifactPreviewMode,
    pub resolved_mode: ArtifactPreviewMode,
    pub offset: u64,
    pub length: u64,
    pub total_size: u64,
    pub has_more: bool,
    pub warnings: Vec<String>,
    pub text_excerpt: Option<String>,
    pub hex_rows: Vec<HexPreviewRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePreviewPage {
    pub session_id: String,
    pub target_key: String,
    pub offset: usize,
    pub count: usize,
    pub total_entries: Option<usize>,
    pub has_more: bool,
    pub warnings: Vec<String>,
    pub entries: Vec<ArchivePreviewEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AsyncJobState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncJobStatus {
    pub job_id: String,
    pub state: AsyncJobState,
    pub created_at: String,
    pub updated_at: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntryDetails {
    pub entry: SourceEntry,
    pub notes: Vec<String>,
    pub summary: Vec<PreviewFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteRun {
    pub offset: u64,
    pub length: u64,
    pub sparse: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveryPlan {
    ResidentBase64 {
        base64: String,
        logical_size: u64,
    },
    RawRuns {
        source_path: String,
        runs: Vec<ByteRun>,
        logical_size: u64,
    },
    Unrecoverable {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub id: String,
    pub scan_id: String,
    pub source_id: String,
    pub name: String,
    pub original_path: Option<String>,
    pub probable_path: Option<String>,
    pub placement_kind: PlacementKind,
    pub path_confidence: PathConfidence,
    pub path_evidence: Vec<PathEvidence>,
    pub name_source: NameSourceKind,
    pub content_source: ContentSourceKind,
    pub artifact_class: ArtifactClass,
    pub preview_ready: bool,
    pub is_fragment: bool,
    pub fragment_id: Option<String>,
    pub extension: Option<String>,
    pub family: ArtifactFamily,
    pub kind: ArtifactKind,
    pub origin_type: OriginType,
    pub confidence: Confidence,
    pub recoverability: Recoverability,
    pub deleted_entry: bool,
    pub size: u64,
    pub priority_score: u16,
    pub filesystem_record: Option<u64>,
    pub parent_reference: Option<u64>,
    pub raw_offset: Option<u64>,
    pub raw_length: Option<u64>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub deleted_at: Option<String>,
    pub deleted_time_source: Option<DeletedTimeSource>,
    pub deleted_time_confidence: DeletedTimeConfidence,
    pub last_metadata_change_at: Option<String>,
    pub notes: Vec<String>,
    pub preview: Vec<PreviewFact>,
    pub recovery_plan: RecoveryPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: String,
    pub scan_id: String,
    pub source_id: String,
    pub name: String,
    pub original_path: Option<String>,
    pub probable_path: Option<String>,
    pub placement_kind: PlacementKind,
    pub path_confidence: PathConfidence,
    pub path_evidence: Vec<PathEvidence>,
    pub name_source: NameSourceKind,
    pub content_source: ContentSourceKind,
    pub artifact_class: ArtifactClass,
    pub preview_ready: bool,
    pub is_fragment: bool,
    pub fragment_id: Option<String>,
    pub extension: Option<String>,
    pub family: ArtifactFamily,
    pub kind: ArtifactKind,
    pub origin_type: OriginType,
    pub confidence: Confidence,
    pub recoverability: Recoverability,
    pub deleted_entry: bool,
    pub size: u64,
    pub priority_score: u16,
    pub filesystem_record: Option<u64>,
    pub parent_reference: Option<u64>,
    pub raw_offset: Option<u64>,
    pub raw_length: Option<u64>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub deleted_at: Option<String>,
    pub deleted_time_source: Option<DeletedTimeSource>,
    pub deleted_time_confidence: DeletedTimeConfidence,
    pub last_metadata_change_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultsBatch {
    pub scan_id: String,
    pub offset: usize,
    pub total_known: usize,
    pub results: Vec<ArtifactSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub source_id: String,
    pub source_name: String,
    pub mode: ScanMode,
    pub filesystem: FileSystemKind,
    pub status: ScanStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_seconds: Option<u64>,
    pub warnings: Vec<String>,
    pub counters: ScanCounters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub scan_id: String,
    pub artifact_ids: Vec<String>,
    pub destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryItemResult {
    pub artifact_id: String,
    pub file_path: Option<String>,
    pub metadata_path: Option<String>,
    pub sha256: Option<String>,
    pub blake3: Option<String>,
    pub status: RecoveryStatus,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySummary {
    pub scan_id: String,
    pub destination: String,
    pub started_at: String,
    pub finished_at: String,
    pub items: Vec<RecoveryItemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub summary: ScanSummary,
    pub source: ScanSource,
    pub progress: ScanProgress,
    pub results: Vec<ArtifactRecord>,
}

impl ArtifactRecord {
    pub fn to_summary(&self) -> ArtifactSummary {
        ArtifactSummary {
            id: self.id.clone(),
            scan_id: self.scan_id.clone(),
            source_id: self.source_id.clone(),
            name: self.name.clone(),
            original_path: self.original_path.clone(),
            probable_path: self.probable_path.clone(),
            placement_kind: self.placement_kind,
            path_confidence: self.path_confidence,
            path_evidence: self.path_evidence.clone(),
            name_source: self.name_source,
            content_source: self.content_source,
            artifact_class: self.artifact_class,
            preview_ready: self.preview_ready,
            is_fragment: self.is_fragment,
            fragment_id: self.fragment_id.clone(),
            extension: self.extension.clone(),
            family: self.family,
            kind: self.kind,
            origin_type: self.origin_type,
            confidence: self.confidence,
            recoverability: self.recoverability,
            deleted_entry: self.deleted_entry,
            size: self.size,
            priority_score: self.priority_score,
            filesystem_record: self.filesystem_record,
            parent_reference: self.parent_reference,
            raw_offset: self.raw_offset,
            raw_length: self.raw_length,
            created_at: self.created_at.clone(),
            modified_at: self.modified_at.clone(),
            deleted_at: self.deleted_at.clone(),
            deleted_time_source: self.deleted_time_source,
            deleted_time_confidence: self.deleted_time_confidence,
            last_metadata_change_at: self.last_metadata_change_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapInfo {
    pub app_name: String,
    pub app_author: String,
    pub app_version: String,
    pub license: String,
    pub eula_path: String,
    pub is_elevated: bool,
    pub source_count: usize,
}

pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn duration_seconds(started_at: &str, finished_at: &str) -> Option<u64> {
    let start =
        OffsetDateTime::parse(started_at, &time::format_description::well_known::Rfc3339).ok()?;
    let end =
        OffsetDateTime::parse(finished_at, &time::format_description::well_known::Rfc3339).ok()?;
    let seconds = (end - start).whole_seconds();
    u64::try_from(seconds.max(0)).ok()
}

pub fn infer_artifact_kind(name: &str, signature_hint: Option<&[u8]>) -> ArtifactKind {
    let ext = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();

    let by_ext = match ext.as_str() {
        "exe" => Some(ArtifactKind::Exe),
        "dll" => Some(ArtifactKind::Dll),
        "sys" => Some(ArtifactKind::Sys),
        "scr" => Some(ArtifactKind::Scr),
        "ocx" => Some(ArtifactKind::Ocx),
        "cpl" => Some(ArtifactKind::Cpl),
        "msi" => Some(ArtifactKind::Msi),
        "jar" => Some(ArtifactKind::Jar),
        "zip" => Some(ArtifactKind::Zip),
        "rar" => Some(ArtifactKind::Rar),
        "7z" => Some(ArtifactKind::SevenZip),
        "cab" => Some(ArtifactKind::Cab),
        "iso" => Some(ArtifactKind::Iso),
        "tar" => Some(ArtifactKind::Tar),
        "gz" => Some(ArtifactKind::Gzip),
        "bz2" => Some(ArtifactKind::Bzip2),
        "xz" => Some(ArtifactKind::Xz),
        "apk" => Some(ArtifactKind::Apk),
        "pdf" => Some(ArtifactKind::Pdf),
        "png" => Some(ArtifactKind::Png),
        "jpg" | "jpeg" => Some(ArtifactKind::Jpg),
        "gif" => Some(ArtifactKind::Gif),
        "sqlite" | "sqlite3" | "db" | "db3" => Some(ArtifactKind::Sqlite),
        "pak" => Some(ArtifactKind::Pak),
        "bin" => Some(ArtifactKind::Bin),
        "dat" => Some(ArtifactKind::Dat),
        "bat" => Some(ArtifactKind::Bat),
        "cmd" => Some(ArtifactKind::Cmd),
        "ps1" => Some(ArtifactKind::Ps1),
        "vbs" => Some(ArtifactKind::Vbs),
        "js" => Some(ArtifactKind::Js),
        "ini" => Some(ArtifactKind::Ini),
        "cfg" => Some(ArtifactKind::Cfg),
        "json" => Some(ArtifactKind::Json),
        "yml" => Some(ArtifactKind::Yml),
        "yaml" => Some(ArtifactKind::Yaml),
        "txt" => Some(ArtifactKind::Txt),
        "log" => Some(ArtifactKind::Log),
        _ => None,
    };

    if let Some(bytes) = signature_hint
        && let Some(by_signature) = infer_artifact_kind_from_signature(bytes)
    {
        return resolve_kind_conflict(by_ext, by_signature);
    }

    by_ext.unwrap_or(ArtifactKind::Unknown)
}

pub fn infer_artifact_kind_from_bytes(bytes: &[u8]) -> ArtifactKind {
    infer_artifact_kind_from_signature(bytes).unwrap_or(ArtifactKind::Unknown)
}

fn resolve_kind_conflict(by_ext: Option<ArtifactKind>, by_signature: ArtifactKind) -> ArtifactKind {
    match by_ext {
        Some(by_ext)
            if !matches!(
                by_ext,
                ArtifactKind::Bin
                    | ArtifactKind::Dat
                    | ArtifactKind::Pak
                    | ArtifactKind::Txt
                    | ArtifactKind::Log
                    | ArtifactKind::Ini
                    | ArtifactKind::Cfg
                    | ArtifactKind::Json
                    | ArtifactKind::Yml
                    | ArtifactKind::Yaml
            ) =>
        {
            if (by_ext == ArtifactKind::Zip
                && matches!(by_signature, ArtifactKind::Jar | ArtifactKind::Apk))
                || (by_ext == ArtifactKind::OleCompound && by_signature == ArtifactKind::Msi)
            {
                by_signature
            } else {
                by_ext
            }
        }
        Some(_) | None => by_signature,
    }
}

fn infer_artifact_kind_from_signature(bytes: &[u8]) -> Option<ArtifactKind> {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return infer_pe_kind(bytes).or(Some(ArtifactKind::Pe));
    }
    if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        return Some(infer_zip_kind(bytes));
    }
    if is_rar_signature(bytes) {
        return Some(ArtifactKind::Rar);
    }
    if bytes.len() >= 6 && &bytes[..6] == b"7z\xBC\xAF\x27\x1C" {
        return Some(ArtifactKind::SevenZip);
    }
    if bytes.len() >= 4 && &bytes[..4] == b"MSCF" {
        return Some(ArtifactKind::Cab);
    }
    if is_gzip_signature(bytes) {
        return Some(ArtifactKind::Gzip);
    }
    if is_bzip2_signature(bytes) {
        return Some(ArtifactKind::Bzip2);
    }
    if is_xz_signature(bytes) {
        return Some(ArtifactKind::Xz);
    }
    if is_pdf_signature(bytes) {
        return Some(ArtifactKind::Pdf);
    }
    if is_png_signature(bytes) {
        return Some(ArtifactKind::Png);
    }
    if is_jpeg_signature(bytes) {
        return Some(ArtifactKind::Jpg);
    }
    if is_gif_signature(bytes) {
        return Some(ArtifactKind::Gif);
    }
    if is_sqlite_signature(bytes) {
        return Some(ArtifactKind::Sqlite);
    }
    if is_tar_signature(bytes) {
        return Some(ArtifactKind::Tar);
    }
    if is_iso_signature(bytes) {
        return Some(ArtifactKind::Iso);
    }
    if bytes.len() >= 8 && &bytes[..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        return Some(infer_ole_kind(bytes));
    }
    if let Some(textual_kind) = infer_textual_artifact_kind(bytes) {
        return Some(textual_kind);
    }

    None
}

fn infer_textual_artifact_kind(bytes: &[u8]) -> Option<ArtifactKind> {
    let sample = bytes.get(..bytes.len().min(8192)).unwrap_or(bytes);
    if sample.is_empty() || sample.contains(&0) {
        return None;
    }

    let printable_ratio = sample
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(**byte, b' ' | b'\r' | b'\n' | b'\t'))
        .count() as f32
        / sample.len().max(1) as f32;
    if printable_ratio < 0.92 {
        return None;
    }

    let text = String::from_utf8_lossy(sample);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    let lower = trimmed.to_ascii_lowercase();
    let lines = lower.lines().take(24).collect::<Vec<_>>();

    if lines
        .iter()
        .any(|line| line.starts_with('[') && line.contains(']'))
        && lines.iter().filter(|line| line.contains('=')).count() >= 1
    {
        return Some(ArtifactKind::Ini);
    }
    if trimmed.starts_with('{')
        || (trimmed.starts_with('[')
            && !lines
                .iter()
                .any(|line| line.starts_with('[') && line.contains('=')))
    {
        return Some(ArtifactKind::Json);
    }
    if lower.starts_with("#!") {
        if lower.contains("powershell") {
            return Some(ArtifactKind::Ps1);
        }
        if lower.contains("node") || lower.contains("deno") {
            return Some(ArtifactKind::Js);
        }
    }
    if lower.starts_with("@echo off") {
        return Some(ArtifactKind::Cmd);
    }
    if lines.iter().any(|line| {
        line.starts_with("function ") || line.starts_with("const ") || line.starts_with("let ")
    }) {
        return Some(ArtifactKind::Js);
    }
    if lines.iter().filter(|line| line.contains('=')).count() >= 2 {
        return Some(ArtifactKind::Cfg);
    }
    if lines
        .iter()
        .filter(|line| {
            let trimmed_line = line.trim();
            !trimmed_line.is_empty()
                && !trimmed_line.starts_with('#')
                && !trimmed_line.starts_with("//")
                && trimmed_line.contains(':')
        })
        .count()
        >= 2
    {
        return Some(ArtifactKind::Yml);
    }

    Some(ArtifactKind::Txt)
}

fn infer_pe_kind(bytes: &[u8]) -> Option<ArtifactKind> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
    }

    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.len() < pe_offset + 24 || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let characteristics =
        u16::from_le_bytes(bytes[pe_offset + 22..pe_offset + 24].try_into().ok()?);
    if characteristics & 0x2000 != 0 {
        return Some(ArtifactKind::Dll);
    }

    let optional_header_offset = pe_offset + 24;
    if bytes.len() < optional_header_offset + 72 {
        return Some(ArtifactKind::Exe);
    }

    let subsystem = u16::from_le_bytes(
        bytes[optional_header_offset + 68..optional_header_offset + 70]
            .try_into()
            .ok()?,
    );
    if subsystem == 1 {
        Some(ArtifactKind::Sys)
    } else {
        Some(ArtifactKind::Exe)
    }
}

fn infer_zip_kind(bytes: &[u8]) -> ArtifactKind {
    if bytes
        .windows(20)
        .any(|window| window == b"META-INF/MANIFEST.MF")
    {
        ArtifactKind::Jar
    } else if bytes
        .windows(19)
        .any(|window| window == b"AndroidManifest.xml")
    {
        ArtifactKind::Apk
    } else {
        ArtifactKind::Zip
    }
}

fn infer_ole_kind(bytes: &[u8]) -> ArtifactKind {
    if utf16le_contains(bytes, "!_StringPool")
        || utf16le_contains(bytes, "!_StringData")
        || utf16le_contains(bytes, "!_Validation")
        || utf16le_contains(bytes, "MsiDigitalSignatureEx")
    {
        ArtifactKind::Msi
    } else {
        ArtifactKind::OleCompound
    }
}

fn utf16le_contains(haystack: &[u8], needle: &str) -> bool {
    let encoded = needle
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    !encoded.is_empty()
        && haystack
            .windows(encoded.len())
            .any(|window| window == encoded)
}

fn is_rar_signature(bytes: &[u8]) -> bool {
    (bytes.len() >= 8 && &bytes[..8] == b"Rar!\x1A\x07\x00")
        || (bytes.len() >= 8 && &bytes[..8] == b"Rar!\x1A\x07\x01")
}

fn is_gzip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x1F && bytes[1] == 0x8B && bytes[2] == 0x08
}

fn is_bzip2_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && &bytes[..3] == b"BZh"
}

fn is_xz_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && &bytes[..6] == b"\xFD7zXZ\x00"
}

fn is_pdf_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && &bytes[..5] == b"%PDF-"
}

fn is_png_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1A\n"
}

fn is_jpeg_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF
}

fn is_gif_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && matches!(&bytes[..6], b"GIF87a" | b"GIF89a")
}

fn is_sqlite_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 16 && &bytes[..16] == b"SQLite format 3\0"
}

fn is_tar_signature(bytes: &[u8]) -> bool {
    if bytes.len() < 0x200 {
        return false;
    }

    let magic = &bytes[0x101..0x101 + 6];
    if magic != b"ustar\0" && &bytes[0x101..0x101 + 8] != b"ustar  \0" {
        return false;
    }

    let checksum_field = &bytes[148..156];
    if !checksum_field
        .iter()
        .all(|byte| matches!(*byte, b' ' | 0 | b'0'..=b'7'))
    {
        return false;
    }

    true
}

fn is_iso_signature(bytes: &[u8]) -> bool {
    const ISO_PRIMARY_DESCRIPTOR_OFFSET: usize = 0x8000;
    bytes.len() >= ISO_PRIMARY_DESCRIPTOR_OFFSET + 6
        && &bytes[ISO_PRIMARY_DESCRIPTOR_OFFSET + 1..ISO_PRIMARY_DESCRIPTOR_OFFSET + 6] == b"CD001"
}

pub fn new_scan_id() -> String {
    Uuid::now_v7().to_string()
}

impl ArtifactRecord {
    pub fn new(scan_id: &str, source_id: &str, name: impl Into<String>) -> Self {
        let name = name.into();
        let kind = infer_artifact_kind(&name, None);
        let generated_name = name.starts_with("deleted_record_");
        Self {
            id: new_scan_id(),
            scan_id: scan_id.to_string(),
            source_id: source_id.to_string(),
            name,
            original_path: None,
            probable_path: None,
            placement_kind: PlacementKind::UnknownParent,
            path_confidence: PathConfidence::Unknown,
            path_evidence: Vec::new(),
            name_source: if generated_name {
                NameSourceKind::Generated
            } else {
                NameSourceKind::LongName
            },
            content_source: ContentSourceKind::Unknown,
            artifact_class: ArtifactClass::NamedMetadataCandidate,
            preview_ready: false,
            is_fragment: false,
            fragment_id: None,
            extension: None,
            family: kind.family(),
            kind,
            origin_type: OriginType::FilesystemDeletedEntry,
            confidence: Confidence::Medium,
            recoverability: Recoverability::Unknown,
            deleted_entry: true,
            size: 0,
            priority_score: kind.priority_score(),
            filesystem_record: None,
            parent_reference: None,
            raw_offset: None,
            raw_length: None,
            created_at: None,
            modified_at: None,
            deleted_at: None,
            deleted_time_source: None,
            deleted_time_confidence: DeletedTimeConfidence::Unknown,
            last_metadata_change_at: None,
            notes: Vec::new(),
            preview: Vec::new(),
            recovery_plan: RecoveryPlan::Unrecoverable {
                reason: "No recovery plan assigned".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    #[test]
    fn infers_artifact_kind_from_common_signatures() {
        assert_eq!(
            infer_artifact_kind("carved.bin", Some(b"%PDF-1.7\n")),
            ArtifactKind::Pdf
        );
        assert_eq!(
            infer_artifact_kind("carved.bin", Some(b"\x89PNG\r\n\x1A\nrest")),
            ArtifactKind::Png
        );
        assert_eq!(
            infer_artifact_kind("carved.bin", Some(b"\xFF\xD8\xFF\xE0\x00\x10JFIF")),
            ArtifactKind::Jpg
        );
        assert_eq!(
            infer_artifact_kind("carved.bin", Some(b"GIF89a")),
            ArtifactKind::Gif
        );
        assert_eq!(
            infer_artifact_kind("carved.bin", Some(b"SQLite format 3\0")),
            ArtifactKind::Sqlite
        );
    }

    #[test]
    fn prefers_specific_signature_over_generic_extension() {
        assert_eq!(
            infer_artifact_kind("unknown.bin", Some(b"%PDF-1.4\n")),
            ArtifactKind::Pdf
        );
        assert_eq!(
            infer_artifact_kind("unknown.dat", Some(b"\x89PNG\r\n\x1A\n")),
            ArtifactKind::Png
        );
    }
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            scan_id: String::new(),
            status: ScanStatus::Idle,
            phase: ScanPhase::Preparing,
            stage: "prepare".to_string(),
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
            target_sla_seconds: 40,
            raw_evidence_state: RawEvidenceState::NotStarted,
            message: "Waiting for scan".to_string(),
            stage_timing_ms: BTreeMap::new(),
            started_at: now_iso(),
            last_progress_at: now_iso(),
            updated_at: now_iso(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactKind, RawEvidenceConfig, RawEvidenceMode, ScanStatus, duration_seconds,
        infer_artifact_kind, infer_artifact_kind_from_bytes,
    };

    #[test]
    fn infers_kind_from_extension_before_signature() {
        let kind = infer_artifact_kind("payload.dll", Some(b"MZ\x90\x00"));
        assert_eq!(kind, ArtifactKind::Dll);
    }

    #[test]
    fn raw_evidence_default_is_manual_and_disabled() {
        let config = RawEvidenceConfig::default();
        assert_eq!(config.mode, RawEvidenceMode::ManualDeep);
        assert!(!config.i30_enabled);
        assert!(!config.usn_enabled);
        assert!(!config.raw_usn_fallback);
        assert!(config.emit_initial_results_before_raw);
    }

    #[test]
    fn infers_kind_from_signature_when_extension_missing() {
        let kind = infer_artifact_kind("artifact", Some(b"PK\x03\x04\x14\x00\x00\x00"));
        assert_eq!(kind, ArtifactKind::Zip);
    }

    #[test]
    fn infers_dll_from_pe_characteristics_when_extension_missing() {
        let mut bytes = vec![0u8; 256];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x96..0x98].copy_from_slice(&(0x2000u16).to_le_bytes());

        let kind = infer_artifact_kind("payload", Some(&bytes));
        assert_eq!(kind, ArtifactKind::Dll);
    }

    #[test]
    fn infers_msi_from_ole_stream_names() {
        let mut bytes = vec![0u8; 512];
        bytes[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        let encoded = "!_StringPool"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes[128..128 + encoded.len()].copy_from_slice(&encoded);

        let kind = infer_artifact_kind("installer.bin", Some(&bytes));
        assert_eq!(kind, ArtifactKind::Msi);
    }

    #[test]
    fn infers_jar_from_zip_signature_and_manifest() {
        let mut bytes = b"PK\x03\x04".to_vec();
        bytes.extend_from_slice(b"META-INF/MANIFEST.MF");
        let kind = infer_artifact_kind("artifact", Some(&bytes));
        assert_eq!(kind, ArtifactKind::Jar);
    }

    #[test]
    fn infers_iso_from_primary_volume_descriptor() {
        let mut bytes = vec![0u8; 0x8008];
        bytes[0x8000] = 1;
        bytes[0x8001..0x8006].copy_from_slice(b"CD001");

        let kind = infer_artifact_kind("disk_image.bin", Some(&bytes));
        assert_eq!(kind, ArtifactKind::Iso);
    }

    #[test]
    fn infers_gzip_from_signature() {
        let kind = infer_artifact_kind("payload.bin", Some(b"\x1F\x8B\x08\x00"));
        assert_eq!(kind, ArtifactKind::Gzip);
    }

    #[test]
    fn infers_bzip2_from_signature() {
        let kind = infer_artifact_kind("payload.bin", Some(b"BZh91AY&SY"));
        assert_eq!(kind, ArtifactKind::Bzip2);
    }

    #[test]
    fn infers_xz_from_signature() {
        let kind = infer_artifact_kind("payload.bin", Some(b"\xFD7zXZ\x00\x00"));
        assert_eq!(kind, ArtifactKind::Xz);
    }

    #[test]
    fn infers_tar_from_ustar_signature() {
        let mut bytes = vec![0u8; 1024];
        bytes[0x101..0x107].copy_from_slice(b"ustar\0");
        bytes[148..156].copy_from_slice(b"0000000 ");
        let kind = infer_artifact_kind("payload.bin", Some(&bytes));
        assert_eq!(kind, ArtifactKind::Tar);
    }

    #[test]
    fn infers_kind_from_bytes_without_extension_bias() {
        let kind = infer_artifact_kind_from_bytes(b"MZ\x90\x00");
        assert_eq!(kind, ArtifactKind::Pe);
    }

    #[test]
    fn infers_json_from_textual_signature() {
        let kind = infer_artifact_kind("payload.bin", Some(br#"{ "ok": true, "items": [1, 2] }"#));
        assert_eq!(kind, ArtifactKind::Json);
    }

    #[test]
    fn infers_powershell_from_shebang_text() {
        let kind = infer_artifact_kind("payload", Some(b"#!powershell\nWrite-Host 'ok'\n"));
        assert_eq!(kind, ArtifactKind::Ps1);
    }

    #[test]
    fn infers_ini_from_textual_signature() {
        let kind = infer_artifact_kind("payload.bin", Some(b"[general]\nmode=fast\nname=files\n"));
        assert_eq!(kind, ArtifactKind::Ini);
    }

    #[test]
    fn computes_duration_in_seconds() {
        let duration = duration_seconds("2026-03-10T10:00:00Z", "2026-03-10T10:01:45Z");
        assert_eq!(duration, Some(105));
    }

    #[test]
    fn completed_with_warnings_is_terminal_success() {
        assert!(ScanStatus::CompletedWithWarnings.is_terminal());
        assert!(ScanStatus::CompletedWithWarnings.is_success());
        assert!(!ScanStatus::Failed.is_success());
    }
}
