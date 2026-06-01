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
  RecoveryItemResult,
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
  SourceEntry,
  SourceEntryDetails,
} from "@/shared/types/api";

type Session = {
  source: ScanSource;
  options: ScanOptions;
  progress: ScanProgress;
  results: ArtifactRecord[];
  snapshot?: ScanSnapshot;
  cancel_requested?: boolean;
};

type MockSourceEntry = Omit<
  SourceDirectoryListing["entries"][number],
  | "created_at"
  | "accessed_at"
  | "attributes"
  | "deleted_hits"
  | "access_state"
  | "mft_reference"
  | "parent_reference"
  | "is_metafile"
  | "entry_class"
  | "attr_bits"
> &
  Partial<
    Pick<
      SourceDirectoryListing["entries"][number],
      | "created_at"
      | "accessed_at"
      | "attributes"
      | "deleted_hits"
      | "access_state"
      | "mft_reference"
      | "parent_reference"
      | "is_metafile"
      | "entry_class"
      | "attr_bits"
    >
  >;

type MockSourceDirectoryListing = Omit<
  SourceDirectoryListing,
  | "entries"
  | "deleted_artifacts"
  | "total_entry_count"
  | "deleted_artifact_count"
  | "next_cursor"
  | "deleted_artifact_next_cursor"
  | "indexing_complete"
  | "indexed_entries"
  | "total_estimated_entries"
  | "index_generation"
  | "deleted_subtree_count"
> & {
  entries: MockSourceEntry[];
  deleted_artifacts?: ArtifactSummary[];
  total_entry_count?: number;
  deleted_artifact_count?: number;
  next_cursor?: string | null;
  deleted_artifact_next_cursor?: string | null;
  indexing_complete?: boolean;
  indexed_entries?: number;
  total_estimated_entries?: number | null;
  index_generation?: number;
  deleted_subtree_count?: number;
};

const progressListeners = new Set<(progress: ScanProgress) => void>();
const resultsBatchListeners = new Set<(batch: ScanResultsBatch) => void>();
const sourceLoadProgressListeners = new Set<(status: SourceCatalogStatus) => void>();
const sourceLoadCompleteListeners = new Set<(status: SourceCatalogStatus) => void>();
const deletedBrowseProgressListeners = new Set<(event: DeletedBrowseProgressEvent) => void>();
const deletedBrowseReadyListeners = new Set<(event: DeletedBrowseReadyEvent) => void>();
const sourceCatalogStatuses = new Map<string, SourceCatalogStatus>();
const sourceCatalogLoadTimers = new Map<string, number[]>();
const previewJobs = new Map<string, { status: AsyncJobStatus; result?: ContentPreviewResponse }>();
const rawEvidenceJobs = new Map<string, RawEvidenceRefinementProgress>();
const previewSessions = new Map<string, { info: PreviewSessionInfo; preview: ContentPreviewResponse }>();
const entryDetailsJobs = new Map<string, { status: AsyncJobStatus; result?: SourceEntryDetails }>();

const sources: ScanSource[] = [
  {
    id: "vol-c",
    kind: "logical_volume",
    device_path: "\\\\.\\C:",
    mount_point: "C:\\",
    display_name: "System NVMe (C:)",
    volume_label: "Windows",
    filesystem: "ntfs",
    volume_serial: 0x4f2a17c1,
    total_bytes: 1_024_000_000_000,
    free_bytes: 280_000_000_000,
    cluster_size: 4096,
    is_system: true,
    requires_elevation: true,
  },
  {
    id: "vol-d",
    kind: "logical_volume",
    device_path: "\\\\.\\D:",
    mount_point: "D:\\",
    display_name: "Data SSD (D:)",
    volume_label: "Workspace",
    filesystem: "ntfs",
    volume_serial: 0x9a18bc40,
    total_bytes: 512_000_000_000,
    free_bytes: 164_000_000_000,
    cluster_size: 4096,
    is_system: false,
    requires_elevation: true,
  },
  {
    id: "vol-e",
    kind: "logical_volume",
    device_path: "\\\\.\\E:",
    mount_point: "E:\\",
    display_name: "Acquisition FAT32 (E:)",
    volume_label: "Acquisition",
    filesystem: "fat32",
    volume_serial: 0x2ab14f90,
    total_bytes: 128_000_000_000,
    free_bytes: 44_000_000_000,
    cluster_size: 32768,
    is_system: false,
    requires_elevation: true,
  },
  {
    id: "vol-f",
    kind: "logical_volume",
    device_path: "\\\\.\\F:",
    mount_point: "F:\\",
    display_name: "Camera exFAT (F:)",
    volume_label: "Media",
    filesystem: "ex_fat",
    volume_serial: 0x71aa44c2,
    total_bytes: 256_000_000_000,
    free_bytes: 180_000_000_000,
    cluster_size: 131072,
    is_system: false,
    requires_elevation: true,
  },
];

const sessions = new Map<string, Session>();

const sourceListings = new Map<string, MockSourceDirectoryListing>([
  [
    "vol-c:C:\\",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\",
      parent_path: null,
      entries: [
        {
          name: "$Extend",
          path: "C:\\$Extend",
          parent_path: "C:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:00:00Z",
          hidden: true,
          system: true,
          read_only: false,
          is_metafile: true,
          entry_class: "metadata_directory",
          attr_bits: 0x0006,
        },
        {
          name: "Windows",
          path: "C:\\Windows",
          parent_path: "C:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:00:00Z",
          hidden: false,
          system: true,
          read_only: false,
        },
        {
          name: "Users",
          path: "C:\\Users",
          parent_path: "C:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:00:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "Program Files",
          path: "C:\\Program Files",
          parent_path: "C:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:00:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "pagefile.sys",
          path: "C:\\pagefile.sys",
          parent_path: "C:\\",
          extension: "sys",
          is_directory: false,
          has_children: false,
          size: 17_179_869_184,
          modified_at: "2026-03-10T09:55:00Z",
          hidden: true,
          system: true,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-c:C:\\$Extend",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\$Extend",
      parent_path: "C:\\",
      entries: [
        {
          name: "$UsnJrnl",
          path: "C:\\$Extend\\$UsnJrnl",
          parent_path: "C:\\$Extend",
          extension: null,
          is_directory: false,
          has_children: false,
          size: 0,
          modified_at: "2026-03-10T08:00:00Z",
          hidden: true,
          system: true,
          read_only: false,
          is_metafile: true,
          entry_class: "metadata_file",
          attr_bits: 0x0006,
        },
      ],
    },
  ],
  [
    "vol-c:C:\\Users",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\Users",
      parent_path: "C:\\",
      entries: [
        {
          name: "jumarf",
          path: "C:\\Users\\jumarf",
          parent_path: "C:\\Users",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:10:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "Public",
          path: "C:\\Users\\Public",
          parent_path: "C:\\Users",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-09T17:10:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-c:C:\\Users\\jumarf",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\Users\\jumarf",
      parent_path: "C:\\Users",
      entries: [
        {
          name: "Downloads",
          path: "C:\\Users\\jumarf\\Downloads",
          parent_path: "C:\\Users\\jumarf",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T08:20:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "AppData",
          path: "C:\\Users\\jumarf\\AppData",
          parent_path: "C:\\Users\\jumarf",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T06:10:00Z",
          hidden: true,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-c:C:\\Users\\jumarf\\Downloads",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\Users\\jumarf\\Downloads",
      parent_path: "C:\\Users\\jumarf",
      entries: [
        {
          name: "desktop.ini",
          path: "C:\\Users\\jumarf\\Downloads\\desktop.ini",
          parent_path: "C:\\Users\\jumarf\\Downloads",
          extension: "ini",
          is_directory: false,
          has_children: false,
          size: 282,
          modified_at: "2026-03-10T08:40:00Z",
          hidden: true,
          system: true,
          read_only: true,
        },
        {
          name: "stager_bundle.zip",
          path: "C:\\Users\\jumarf\\Downloads\\stager_bundle.zip",
          parent_path: "C:\\Users\\jumarf\\Downloads",
          extension: "zip",
          is_directory: false,
          has_children: false,
          size: 87_444_512,
          modified_at: "2026-03-07T20:59:54Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-c:C:\\Windows",
    {
      source_id: "vol-c",
      root_path: "C:\\",
      path: "C:\\Windows",
      parent_path: "C:\\",
      entries: [
        {
          name: "System32",
          path: "C:\\Windows\\System32",
          parent_path: "C:\\Windows",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T07:45:00Z",
          hidden: false,
          system: true,
          read_only: false,
        },
        {
          name: "WinSxS",
          path: "C:\\Windows\\WinSxS",
          parent_path: "C:\\Windows",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T07:45:00Z",
          hidden: false,
          system: true,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-d:D:\\",
    {
      source_id: "vol-d",
      root_path: "D:\\",
      path: "D:\\",
      parent_path: null,
      entries: [
        {
          name: "cache",
          path: "D:\\cache",
          parent_path: "D:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T05:40:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "evidence",
          path: "D:\\evidence",
          parent_path: "D:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-09T10:15:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-e:E:\\",
    {
      source_id: "vol-e",
      root_path: "E:\\",
      path: "E:\\",
      parent_path: null,
      entries: [
        {
          name: "DCIM",
          path: "E:\\DCIM",
          parent_path: "E:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T05:15:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "Recovered",
          path: "E:\\Recovered",
          parent_path: "E:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-09T14:15:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-f:F:\\",
    {
      source_id: "vol-f",
      root_path: "F:\\",
      path: "F:\\",
      parent_path: null,
      entries: [
        {
          name: "MISC",
          path: "F:\\MISC",
          parent_path: "F:\\",
          extension: null,
          is_directory: true,
          has_children: true,
          size: 0,
          modified_at: "2026-03-10T05:15:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
        {
          name: "VID_0001.MP4",
          path: "F:\\VID_0001.MP4",
          parent_path: "F:\\",
          extension: "mp4",
          is_directory: false,
          has_children: false,
          size: 402_103_552,
          modified_at: "2026-03-10T05:16:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-e:E:\\DCIM",
    {
      source_id: "vol-e",
      root_path: "E:\\",
      path: "E:\\DCIM",
      parent_path: "E:\\",
      entries: [
        {
          name: "100MEDIA",
          path: "E:\\DCIM\\100MEDIA",
          parent_path: "E:\\DCIM",
          extension: null,
          is_directory: true,
          has_children: false,
          size: 0,
          modified_at: "2026-03-10T05:15:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
  [
    "vol-f:F:\\MISC",
    {
      source_id: "vol-f",
      root_path: "F:\\",
      path: "F:\\MISC",
      parent_path: "F:\\",
      entries: [
        {
          name: "notes.txt",
          path: "F:\\MISC\\notes.txt",
          parent_path: "F:\\MISC",
          extension: "txt",
          is_directory: false,
          has_children: false,
          size: 2048,
          modified_at: "2026-03-10T05:20:00Z",
          hidden: false,
          system: false,
          read_only: false,
        },
      ],
    },
  ],
]);

sourceListings.set("vol-d:D:\\evidence", {
  source_id: "vol-d",
  root_path: "D:\\",
  path: "D:\\evidence",
  parent_path: "D:\\",
  entries: buildLargeEvidenceEntries(),
  total_entry_count: 0,
  next_cursor: null,
});

const DEFAULT_ARTIFACT_PROVENANCE = {
  probable_path: null,
  placement_kind: "original_path",
  path_confidence: "exact",
  path_evidence: [] as ArtifactRecord["path_evidence"],
  name_source: "long_name",
  content_source: "raw_runs",
  artifact_class: "validated_hit",
  preview_ready: true,
  is_fragment: false,
  fragment_id: null,
  parent_reference: null,
  deleted_at: null,
  deleted_time_source: null,
  deleted_time_confidence: "unknown",
  last_metadata_change_at: null,
} as const;

const artifacts: ArtifactRecord[] = [
  {
    ...DEFAULT_ARTIFACT_PROVENANCE,
    id: "artifact-1",
    scan_id: "mock",
    source_id: "vol-c",
    name: "payload_loader.dll",
    original_path: "C:\\Users\\Public\\Libraries\\payload_loader.dll",
    extension: "dll",
    family: "executable",
    kind: "dll",
    origin_type: "filesystem_deleted_entry",
    confidence: "high",
    recoverability: "good",
    deleted_entry: true,
    size: 1_842_176,
    priority_score: 100,
    filesystem_record: 417844,
    raw_offset: 2_148_401_152,
    raw_length: 1_851_392,
    created_at: "2026-03-07T21:03:12Z",
    modified_at: "2026-03-08T01:11:43Z",
    notes: [
      "PE header and section table validated.",
      "Import table preview suggests network and process injection APIs.",
    ],
    preview: [
      { label: "Machine", value: "x64" },
      { label: "Entry Point", value: "0x0004A250" },
      { label: "Imports", value: "kernel32, advapi32, ws2_32" },
    ],
    recovery_plan: {
      kind: "raw_runs",
      source_path: "\\\\.\\C:",
      runs: [{ offset: 2_148_401_152, length: 1_851_392, sparse: false }],
      logical_size: 1_842_176,
    },
  },
  {
    ...DEFAULT_ARTIFACT_PROVENANCE,
    id: "artifact-2",
    scan_id: "mock",
    source_id: "vol-c",
    name: "stager_bundle.zip",
    original_path: "C:\\Users\\jumarf\\Downloads\\stager_bundle.zip",
    extension: "zip",
    family: "archive",
    kind: "zip",
    origin_type: "filesystem_deleted_entry",
    confidence: "high",
    recoverability: "good",
    deleted_entry: true,
    size: 87_444_512,
    priority_score: 90,
    filesystem_record: 417851,
    raw_offset: 2_180_874_240,
    raw_length: 87_461_888,
    created_at: "2026-03-07T20:58:01Z",
    modified_at: "2026-03-07T20:59:54Z",
    notes: ["ZIP central directory validated.", "Contains 14 entries including executable payloads."],
    preview: [
      { label: "Entries", value: "14" },
      { label: "Contains", value: "loader.exe, config.json, stage2/" },
      { label: "Comment", value: "Empty" },
    ],
    recovery_plan: {
      kind: "raw_runs",
      source_path: "\\\\.\\C:",
      runs: [{ offset: 2_180_874_240, length: 87_461_888, sparse: false }],
      logical_size: 87_444_512,
    },
  },
  {
    ...DEFAULT_ARTIFACT_PROVENANCE,
    id: "artifact-3",
    scan_id: "mock",
    source_id: "vol-d",
    name: "tools.7z",
    original_path: "D:\\cache\\temp\\tools.7z",
    extension: "7z",
    family: "archive",
    kind: "seven_zip",
    origin_type: "unallocated_carved",
    placement_kind: "unknown_parent",
    path_confidence: "unknown",
    name_source: "generated",
    content_source: "contiguous_carve",
    artifact_class: "carved_hit",
    confidence: "medium",
    recoverability: "partial",
    deleted_entry: false,
    size: 23_404_611,
    priority_score: 90,
    filesystem_record: null,
    raw_offset: 34_188_288,
    raw_length: 23_412_736,
    created_at: null,
    modified_at: null,
    notes: ["Carved from unallocated extent.", "Header and stream map validated; footer truncated by later writes."],
    preview: [
      { label: "Signature", value: "7z BC AF 27 1C" },
      { label: "Status", value: "Partial footer" },
      { label: "Method", value: "LZMA2" },
    ],
    recovery_plan: {
      kind: "raw_runs",
      source_path: "\\\\.\\D:",
      runs: [{ offset: 34_188_288, length: 23_412_736, sparse: false }],
      logical_size: 23_404_611,
    },
  },
];

function nowIso() {
  return new Date().toISOString();
}

function buildLargeEvidenceEntries(): MockSourceEntry[] {
  const directories = Array.from({ length: 340 }, (_, index) => {
    const name = `cluster-${String(index + 1).padStart(3, "0")}`;
    return {
      name,
      path: `D:\\evidence\\${name}`,
      parent_path: "D:\\evidence",
      extension: null,
      is_directory: true,
      has_children: false,
      size: 0,
      modified_at: "2026-03-10T06:45:00Z",
      hidden: false,
      system: false,
      read_only: false,
      deleted_hits: index % 17 === 0 ? 2 : 0,
    } satisfies MockSourceEntry;
  });

  const files = Array.from({ length: 280 }, (_, index) => {
    const padded = String(index + 1).padStart(3, "0");
    const extension = index % 5 === 0 ? "zip" : index % 7 === 0 ? "dll" : "log";
    return {
      name: `triage-${padded}.${extension}`,
      path: `D:\\evidence\\triage-${padded}.${extension}`,
      parent_path: "D:\\evidence",
      extension,
      is_directory: false,
      has_children: false,
      size: 4_096 + index * 128,
      modified_at: "2026-03-10T06:50:00Z",
      hidden: false,
      system: false,
      read_only: false,
      deleted_hits: index % 11 === 0 ? 1 : 0,
    } satisfies MockSourceEntry;
  });

  return [...directories, ...files];
}

function sleep(milliseconds: number) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function toSummary(artifact: ArtifactRecord): ArtifactSummary {
  return {
    id: artifact.id,
    scan_id: artifact.scan_id,
    source_id: artifact.source_id,
    name: artifact.name,
    original_path: artifact.original_path,
    probable_path: artifact.probable_path,
    placement_kind: artifact.placement_kind,
    path_confidence: artifact.path_confidence,
    path_evidence: artifact.path_evidence,
    name_source: artifact.name_source,
    content_source: artifact.content_source,
    artifact_class: artifact.artifact_class,
    preview_ready: artifact.preview_ready,
    is_fragment: artifact.is_fragment,
    fragment_id: artifact.fragment_id,
    extension: artifact.extension,
    family: artifact.family,
    kind: artifact.kind,
    origin_type: artifact.origin_type,
    confidence: artifact.confidence,
    recoverability: artifact.recoverability,
    deleted_entry: artifact.deleted_entry,
    size: artifact.size,
    priority_score: artifact.priority_score,
    filesystem_record: artifact.filesystem_record,
    parent_reference: artifact.parent_reference,
    raw_offset: artifact.raw_offset,
    raw_length: artifact.raw_length,
    created_at: artifact.created_at,
    modified_at: artifact.modified_at,
    deleted_at: artifact.deleted_at,
    deleted_time_source: artifact.deleted_time_source,
    deleted_time_confidence: artifact.deleted_time_confidence,
    last_metadata_change_at: artifact.last_metadata_change_at,
  };
}

function emitProgress(progress: ScanProgress) {
  progressListeners.forEach((listener) => listener(progress));
}

function emitResultsBatch(batch: ScanResultsBatch) {
  resultsBatchListeners.forEach((listener) => listener(batch));
}

function emitSourceLoadProgress(status: SourceCatalogStatus) {
  sourceLoadProgressListeners.forEach((listener) => listener(status));
}

function emitSourceLoadComplete(status: SourceCatalogStatus) {
  sourceLoadCompleteListeners.forEach((listener) => listener(status));
}

function emitDeletedBrowseProgress(event: DeletedBrowseProgressEvent) {
  deletedBrowseProgressListeners.forEach((listener) => listener(event));
}

function unloadedCatalogStatus(sourceId: string): SourceCatalogStatus {
  return {
    state: "unloaded",
    source_id: sourceId,
    load_id: null,
    phase: null,
    progress_percent: 0,
    indexed_entries: 0,
    total_estimated_entries: null,
    cache_state: "cold",
    started_at: null,
    updated_at: nowIso(),
    error: null,
    error_code: null,
    error_detail: null,
  };
}

function newAsyncJobStatus(jobId: string): AsyncJobStatus {
  const now = nowIso();
  return {
    job_id: jobId,
    state: "pending",
    created_at: now,
    updated_at: now,
    error: null,
  };
}

function buildSnapshot(session: Session): ScanSnapshot {
  return {
    summary: {
      scan_id: session.progress.scan_id,
      source_id: session.source.id,
      source_name: session.source.display_name,
      mode: session.options.mode,
      filesystem: session.source.filesystem,
      status: session.progress.status,
      started_at: session.progress.started_at,
      finished_at: nowIso(),
      duration_seconds: session.options.mode === "fast" ? 18 : 92,
      warnings:
        session.progress.status === "cancelled"
          ? ["Mock scan cancelled by operator."]
          : session.options.mode === "deep"
            ? ["Deep mode extends carving and validation for high-priority signatures."]
            : [],
      counters: {
        total_results: session.results.length,
        executable_results: session.results.filter((item) => item.family === "executable").length,
        archive_results: session.results.filter((item) => item.family === "archive").length,
        script_results: session.results.filter((item) => item.family === "script").length,
        carved_results: session.results.filter((item) => item.origin_type === "unallocated_carved").length,
        partial_results: session.results.filter((item) => item.recoverability === "partial").length,
        recoverable_results: session.results.filter((item) => item.recoverability === "good").length,
      },
    },
    source: session.source,
    progress: session.progress,
    results: session.results,
  };
}

async function simulateScan(scanId: string) {
  const session = sessions.get(scanId);
  if (!session) {
    return;
  }

  const phases: Array<[ScanProgress["phase"], number, string]> = [
    ["preparing", 6, "Opening source in read-only forensic mode"],
    ["discovering_metadata", 24, "Enumerating deleted MFT and directory entries"],
    ["scanning_deleted_entries", 58, "Validating deleted executable and archive candidates"],
    [
      session.options.mode === "deep" ? "carving_high_priority" : "hashing",
      session.options.mode === "deep" ? 82 : 88,
      session.options.mode === "deep"
        ? "Carving high-priority signatures from unallocated space"
        : "Hashing validated candidates",
    ],
    ["finalizing", 100, "Persisting scan snapshot and evidence metadata"],
  ];

  for (const [phase, progressPercent, message] of phases) {
    await sleep(session.options.mode === "deep" ? 750 : 420);
    if (session.cancel_requested) {
      session.progress = {
        ...session.progress,
        phase: "finalizing",
        stage: "finalize",
        progress_percent: Math.min(session.progress.progress_percent, 99),
        artifacts_found: session.results.length,
        message: "Scan cancelled",
        updated_at: nowIso(),
        last_progress_at: nowIso(),
        status: "cancelled",
      };
      emitProgress(session.progress);
      session.snapshot = buildSnapshot(session);
      return;
    }

    const results =
      progressPercent >= 58
        ? artifacts
            .filter((artifact) => artifact.source_id === session.source.id || artifact.origin_type === "unallocated_carved")
            .filter((artifact) => session.options.include_low_confidence || artifact.confidence !== "low")
            .map((artifact) => ({ ...artifact, scan_id: scanId, source_id: session.source.id }))
        : [];

    const previousIds = new Set(session.results.map((artifact) => artifact.id));
    session.results = results;
    const batch = results.filter((artifact) => !previousIds.has(artifact.id)).map(toSummary);
    session.progress = {
      ...session.progress,
      phase,
      stage: phase,
      progress_percent: progressPercent,
      artifacts_found: results.length,
      candidates_surfaced: results.length,
      validated_hits: countArtifactsByClass(results, "validated_hit") + countArtifactsByClass(results, "recoverable"),
      named_hits: results.filter((artifact) => artifact.name_source !== "generated").length,
      carved_hits: countArtifactsByClass(results, "carved_hit"),
      fragment_hits: countArtifactsByClass(results, "fragment_candidate"),
      recoverable_hits: results.filter((artifact) => artifact.recoverability !== "unknown").length,
      verified_hits: countArtifactsByClass(results, "validated_hit") + countArtifactsByClass(results, "recoverable"),
      bytes_scanned: Math.round((session.source.total_bytes * progressPercent) / 100),
      files_examined: 2200 + progressPercent * 37,
      records_scanned: Math.round(2200 + progressPercent * 37),
      records_per_second: phase === "scanning_deleted_entries" ? 145_000 : 0,
      eta_seconds: progressPercent >= 100 ? 0 : Math.max(2, Math.round((100 - progressPercent) / 3)),
      message,
      stage_timing_ms: {
        preparing: 420,
        metadata: progressPercent >= 24 ? 900 : 0,
        validation: progressPercent >= 58 ? 650 : 0,
        finalize: progressPercent >= 100 ? 220 : 0,
      },
      updated_at: nowIso(),
      last_progress_at: nowIso(),
      status: progressPercent >= 100 ? "completed" : "running",
    };
    if (batch.length > 0) {
      emitResultsBatch({
        scan_id: scanId,
        offset: previousIds.size,
        total_known: results.length,
        results: batch,
      });
    }
    emitProgress(session.progress);
  }

  emitDeletedBrowseProgress({
    scan_id: scanId,
    source_id: session.source.id,
    processed_artifacts: session.results.length,
    total_artifacts: session.results.length,
    progress_percent: 100,
  });
  deletedBrowseReadyListeners.forEach((listener) =>
    listener({
      scan_id: scanId,
      source_id: session.source.id,
    }),
  );
  session.snapshot = buildSnapshot(session);
}

export async function mockBootstrap(): Promise<BootstrapInfo> {
  await sleep(150);
  return {
    app_name: "Files",
    app_author: "Jumarf",
    app_version: "0.8.3",
    license: "GPL-3.0-or-later",
    eula_path: "../legal/EULA.md",
    is_elevated: true,
    source_count: sources.length,
  };
}

export async function mockListSources(): Promise<ScanSource[]> {
  await sleep(200);
  for (const source of sources) {
    if (!sourceCatalogStatuses.has(source.id)) {
      sourceCatalogStatuses.set(source.id, unloadedCatalogStatus(source.id));
    }
  }
  return sources;
}

export async function mockLoadSourceCatalog(sourceId: string, forceRebuild: boolean): Promise<string> {
  await sleep(60);
  const source = sources.find((candidate) => candidate.id === sourceId);
  if (!source) {
    throw new Error(`Source ${sourceId} not found`);
  }

  const loadId = `load-${crypto.randomUUID()}`;
  const start = nowIso();
  const phases: Array<SourceCatalogStatus["phase"]> = [
    "opening_volume",
    "enumerating_files",
    "augmenting_ntfs_metadata",
    "building_indexes",
    "finalizing",
  ];
  const timers: number[] = [];

  sourceCatalogStatuses.set(sourceId, {
    state: "loading",
    source_id: sourceId,
    load_id: loadId,
    phase: phases[0],
    progress_percent: 0,
    indexed_entries: 0,
    total_estimated_entries: 120_000,
    cache_state: forceRebuild ? "rebuild" : "cold",
    started_at: start,
    updated_at: start,
    error: null,
    error_code: null,
    error_detail: null,
  });
  emitSourceLoadProgress(sourceCatalogStatuses.get(sourceId)!);

  phases.forEach((phase, index) => {
    const timer = window.setTimeout(() => {
      const status = sourceCatalogStatuses.get(sourceId);
      if (!status || status.load_id !== loadId || status.state !== "loading") {
        return;
      }
      const nextStatus: SourceCatalogStatus = {
        ...status,
        phase,
        progress_percent: Math.min(100, (index + 1) * 20),
        indexed_entries: Math.min(120_000, (index + 1) * 24_000),
        updated_at: nowIso(),
      };
      sourceCatalogStatuses.set(sourceId, nextStatus);
      if (index === phases.length - 1) {
        const readyStatus: SourceCatalogStatus = {
          ...nextStatus,
          state: "ready",
          load_id: null,
          progress_percent: 100,
          phase: null,
          cache_state: forceRebuild ? "rebuild" : "warm",
          updated_at: nowIso(),
        };
        sourceCatalogStatuses.set(sourceId, readyStatus);
        emitSourceLoadComplete(readyStatus);
      } else {
        emitSourceLoadProgress(nextStatus);
      }
    }, 220 * (index + 1));
    timers.push(timer);
  });

  sourceCatalogLoadTimers.set(loadId, timers);
  return loadId;
}

export async function mockSourceCatalogStatus(sourceId: string): Promise<SourceCatalogStatus> {
  await sleep(40);
  return sourceCatalogStatuses.get(sourceId) ?? unloadedCatalogStatus(sourceId);
}

export async function mockCancelSourceLoad(loadId: string): Promise<void> {
  await sleep(40);
  const timers = sourceCatalogLoadTimers.get(loadId) ?? [];
  for (const timer of timers) {
    window.clearTimeout(timer);
  }
  sourceCatalogLoadTimers.delete(loadId);
  for (const [sourceId, status] of sourceCatalogStatuses) {
    if (status.load_id === loadId) {
      const unloaded = unloadedCatalogStatus(sourceId);
      sourceCatalogStatuses.set(sourceId, unloaded);
      emitSourceLoadProgress(unloaded);
      return;
    }
  }
}

export async function mockBrowseSource(request: BrowseSourceRequest): Promise<SourceDirectoryListing> {
  await sleep(120);
  const source = sources.find((candidate) => candidate.id === request.source_id);
  if (!source?.mount_point) {
    throw new Error(`Source ${request.source_id} is not mounted`);
  }
  if ((sourceCatalogStatuses.get(request.source_id) ?? unloadedCatalogStatus(request.source_id)).state !== "ready") {
    throw new Error("catalog_not_ready");
  }

  const resolvedPath = request.path && request.path.trim().length > 0 ? request.path : source.mount_point;
  const listing = sourceListings.get(`${request.source_id}:${resolvedPath}`);
  if (!listing) {
    throw new Error(`Path ${resolvedPath} is unavailable in mock mode`);
  }

  const entries = listing.entries
    .map((entry) => ({
      ...entry,
      created_at: entry.created_at ?? entry.modified_at,
      accessed_at: entry.accessed_at ?? entry.modified_at,
      mft_reference: entry.mft_reference ?? null,
      parent_reference: entry.parent_reference ?? null,
      is_metafile: entry.is_metafile ?? entry.name.startsWith("$"),
      entry_class:
        entry.entry_class ??
        (entry.is_directory
          ? entry.name.startsWith("$")
            ? "metadata_directory"
            : "directory"
          : entry.name.startsWith("$")
            ? "metadata_file"
            : "file"),
      attr_bits: entry.attr_bits ?? null,
      attributes: entry.attributes ?? [
        ...(entry.hidden ? ["hidden"] : []),
        ...(entry.system ? ["system"] : []),
        ...(entry.read_only ? ["read_only"] : []),
      ],
      deleted_hits: entry.deleted_hits ?? 0,
      access_state: entry.access_state ?? "readable",
    }))
    .filter((entry) => (request.directories_only ? entry.is_directory : true));

  const total_entry_count = entries.length;
  const pageSize = Math.min(Math.max(request.limit ?? 256, 1), 1024);
  const start = Number.parseInt(request.cursor ?? "0", 10) || 0;
  const pagedEntries = entries.slice(start, start + pageSize);

  return {
    ...listing,
    entries: pagedEntries,
    deleted_artifacts: listing.deleted_artifacts ?? [],
    total_entry_count,
    deleted_artifact_count: listing.deleted_artifact_count ?? 0,
    next_cursor: start + pagedEntries.length < total_entry_count ? String(start + pagedEntries.length) : null,
    deleted_artifact_next_cursor: listing.deleted_artifact_next_cursor ?? null,
    indexing_complete: listing.indexing_complete ?? true,
    indexed_entries: listing.indexed_entries ?? total_entry_count,
    total_estimated_entries: listing.total_estimated_entries ?? total_entry_count,
    index_generation: listing.index_generation ?? 1,
    deleted_subtree_count: listing.deleted_subtree_count ?? 0,
  };
}

export async function mockStartScan(options: ScanOptions): Promise<string> {
  const source = sources.find((candidate) => candidate.id === options.source_id) ?? sources[0];
  const scanId = `mock-${crypto.randomUUID()}`;

  sessions.set(scanId, {
    source,
    options,
    results: [],
    cancel_requested: false,
    progress: {
      scan_id: scanId,
      status: "running",
      phase: "preparing",
      stage: "prepare",
      progress_percent: 0,
      files_examined: 0,
      artifacts_found: 0,
      candidates_surfaced: 0,
      validated_hits: 0,
      named_hits: 0,
      carved_hits: 0,
      fragment_hits: 0,
      recoverable_hits: 0,
      verified_hits: 0,
      bytes_scanned: 0,
      records_scanned: 0,
      records_per_second: 0,
      eta_seconds: options.mode === "fast" ? 180 : 600,
      target_sla_seconds: options.mode === "fast" ? 180 : 600,
      raw_evidence_state: "not_started",
      message: `Queued ${options.mode} scan for ${source.display_name}`,
      stage_timing_ms: {},
      started_at: nowIso(),
      last_progress_at: nowIso(),
      updated_at: nowIso(),
    },
  });

  emitProgress(sessions.get(scanId)!.progress);
  void simulateScan(scanId);
  return scanId;
}

export async function mockStopScan(scanId: string): Promise<void> {
  await sleep(80);
  const session = sessions.get(scanId);
  if (!session) {
    throw new Error(`Scan ${scanId} not found`);
  }
  session.cancel_requested = true;
  session.progress = {
    ...session.progress,
    message: "Stopping scan after the current batch",
    updated_at: nowIso(),
  };
  emitProgress(session.progress);
}

export async function mockScanProgress(scanId: string): Promise<ScanProgress> {
  await sleep(80);
  const session = sessions.get(scanId);
  if (!session) {
    throw new Error(`Scan ${scanId} not found`);
  }
  return session.progress;
}

export async function mockStartRawEvidenceRefinement(request: RawEvidenceRefinementRequest): Promise<string> {
  await sleep(80);
  const session = sessions.get(request.scan_id);
  if (!session) {
    throw new Error(`Scan ${request.scan_id} not found`);
  }
  const jobId = `raw-${crypto.randomUUID()}`;
  const startedAt = nowIso();
  const initial: RawEvidenceRefinementProgress = {
    job_id: jobId,
    scan_id: request.scan_id,
    source_id: request.source_id,
    state: "running",
    phase: "queued",
    progress_percent: 0,
    processed_units: 0,
    total_units: null,
    message: "Queued NTFS raw evidence refinement",
    warnings: [],
    started_at: startedAt,
    updated_at: startedAt,
  };
  rawEvidenceJobs.set(jobId, initial);
  session.progress = {
    ...session.progress,
    raw_evidence_state: "running",
    phase: "refining_raw_evidence",
    stage: "refining_raw_evidence",
    message: "Refining paths from NTFS raw evidence",
    updated_at: nowIso(),
    last_progress_at: nowIso(),
  };
  emitProgress(session.progress);
  void simulateRawEvidenceJob(jobId, request.scan_id);
  return jobId;
}

async function simulateRawEvidenceJob(jobId: string, scanId: string) {
  const phases: Array<[RawEvidenceRefinementProgress["phase"], number, string]> = [
    ["building_directory_map", 18, "Building NTFS directory map"],
    ["parsing_i30", 55, "Parsing NTFS $I30 directory evidence"],
    ["reading_usn", 82, "Reading NTFS USN Journal evidence"],
    ["merging_evidence", 94, "Merging raw evidence into deleted results"],
    ["done", 100, "Raw NTFS evidence refinement complete"],
  ];
  for (const [phase, progressPercent, message] of phases) {
    await sleep(420);
    const job = rawEvidenceJobs.get(jobId);
    if (!job || job.state === "cancelled") {
      return;
    }
    rawEvidenceJobs.set(jobId, {
      ...job,
      phase,
      progress_percent: progressPercent,
      processed_units: Math.round(progressPercent * 1000),
      total_units: phase === "done" ? Math.round(progressPercent * 1000) : null,
      message,
      state: phase === "done" ? "completed" : "running",
      updated_at: nowIso(),
    });
  }
  const session = sessions.get(scanId);
  if (session) {
    session.progress = {
      ...session.progress,
      raw_evidence_state: "completed",
      phase: "finalizing",
      stage: "raw_evidence_done",
      message: "Raw NTFS evidence refinement complete",
      updated_at: nowIso(),
      last_progress_at: nowIso(),
    };
    emitProgress(session.progress);
  }
}

export async function mockRawEvidenceProgress(jobId: string): Promise<RawEvidenceRefinementProgress> {
  await sleep(80);
  const job = rawEvidenceJobs.get(jobId);
  if (!job) {
    throw new Error(`Raw evidence job ${jobId} not found`);
  }
  return job;
}

export async function mockCancelRawEvidenceRefinement(jobId: string): Promise<void> {
  await sleep(80);
  const job = rawEvidenceJobs.get(jobId);
  if (!job) {
    throw new Error(`Raw evidence job ${jobId} not found`);
  }
  rawEvidenceJobs.set(jobId, {
    ...job,
    state: "cancelled",
    phase: "done",
    progress_percent: Math.min(job.progress_percent, 99),
    message: "Raw evidence refinement cancelled",
    updated_at: nowIso(),
  });
  const session = sessions.get(job.scan_id);
  if (session) {
    session.progress = {
      ...session.progress,
      raw_evidence_state: "not_started",
      phase: "finalizing",
      stage: "raw_evidence_cancelled",
      message: "Raw evidence refinement cancelled",
      updated_at: nowIso(),
      last_progress_at: nowIso(),
    };
    emitProgress(session.progress);
  }
}

export async function mockScanResults(scanId: string): Promise<ArtifactSummary[]> {
  await sleep(80);
  const session = sessions.get(scanId);
  if (!session) {
    throw new Error(`Scan ${scanId} not found`);
  }
  return session.results.map(toSummary);
}

export async function mockArtifactDetails(scanId: string, artifactId: string): Promise<ArtifactRecord> {
  await sleep(60);
  const session = sessions.get(scanId);
  const artifact = session?.results.find((item) => item.id === artifactId);
  if (!artifact) {
    throw new Error(`Artifact ${artifactId} not found`);
  }
  return artifact;
}

export async function mockEntryDetails(sourceId: string, path: string): Promise<SourceEntryDetails> {
  await sleep(60);
  if ((sourceCatalogStatuses.get(sourceId) ?? unloadedCatalogStatus(sourceId)).state !== "ready") {
    throw new Error("catalog_not_ready");
  }
  for (const listing of sourceListings.values()) {
    if (listing.source_id !== sourceId) {
      continue;
    }
    const match = listing.entries.find((entry) => entry.path === path);
    if (!match) {
      continue;
    }
    const entry: SourceEntry = {
      ...match,
      created_at: match.created_at ?? match.modified_at ?? null,
      accessed_at: match.accessed_at ?? match.modified_at ?? null,
      mft_reference: match.mft_reference ?? null,
      parent_reference: match.parent_reference ?? null,
      is_metafile: match.is_metafile ?? match.name.startsWith("$"),
      entry_class:
        match.entry_class ??
        (match.is_directory
          ? match.name.startsWith("$")
            ? "metadata_directory"
            : "directory"
          : match.name.startsWith("$")
            ? "metadata_file"
            : "file"),
      attr_bits: match.attr_bits ?? null,
      attributes: match.attributes ?? [],
      deleted_hits: match.deleted_hits ?? 0,
      access_state: match.access_state ?? "readable",
    };
    return {
      entry,
      notes: [
        entry.is_metafile
          ? "This entry originates from NTFS metadata and is available in the tree."
          : "Live entry metadata loaded from mock source.",
      ],
      summary: [
        { label: "ATTR", value: entry.attr_bits != null ? `0x${entry.attr_bits.toString(16)}` : "n/a" },
        { label: "Attributes", value: entry.attributes.length > 0 ? entry.attributes.join(", ") : "-" },
      ],
    };
  }

  throw new Error(`Entry ${path} not found`);
}

export async function mockStartEntryDetailsJob(sourceId: string, path: string): Promise<string> {
  const jobId = `entry-job-${crypto.randomUUID()}`;
  entryDetailsJobs.set(jobId, { status: newAsyncJobStatus(jobId) });
  window.setTimeout(async () => {
    const current = entryDetailsJobs.get(jobId);
    if (!current || current.status.state === "cancelled") {
      return;
    }
    current.status = { ...current.status, state: "running", updated_at: nowIso() };
    try {
      const result = await mockEntryDetails(sourceId, path);
      const latest = entryDetailsJobs.get(jobId);
      if (!latest || latest.status.state === "cancelled") {
        return;
      }
      entryDetailsJobs.set(jobId, {
        status: { ...latest.status, state: "completed", updated_at: nowIso(), error: null },
        result,
      });
    } catch (error) {
      const latest = entryDetailsJobs.get(jobId);
      if (!latest || latest.status.state === "cancelled") {
        return;
      }
      entryDetailsJobs.set(jobId, {
        status: {
          ...latest.status,
          state: "failed",
          updated_at: nowIso(),
          error: error instanceof Error ? error.message : "Entry details job failed",
        },
      });
    }
  }, 0);
  return jobId;
}

export async function mockEntryDetailsJobStatus(jobId: string): Promise<AsyncJobStatus> {
  const job = entryDetailsJobs.get(jobId);
  if (!job) {
    throw new Error(`Entry details job ${jobId} not found`);
  }
  return job.status;
}

export async function mockEntryDetailsJobResult(jobId: string): Promise<SourceEntryDetails> {
  const job = entryDetailsJobs.get(jobId);
  if (!job) {
    throw new Error(`Entry details job ${jobId} not found`);
  }
  if (job.status.state === "completed" && job.result) {
    return job.result;
  }
  if (job.status.state === "failed") {
    throw new Error(job.status.error ?? `Entry details job ${jobId} failed`);
  }
  throw new Error("job_not_ready");
}

export async function mockCancelEntryDetailsJob(jobId: string): Promise<void> {
  const job = entryDetailsJobs.get(jobId);
  if (!job) {
    return;
  }
  job.status = { ...job.status, state: "cancelled", updated_at: nowIso(), error: null };
  delete job.result;
}

export async function mockArtifactSignature(scanId: string, artifactId: string): Promise<ArtifactSignatureSummary> {
  await sleep(80);
  const artifact = await mockArtifactDetails(scanId, artifactId);
  if (["exe", "dll", "sys", "msi"].includes(artifact.kind)) {
    return {
      status: artifact.name.includes("payload") ? "invalid" : "valid",
      subject: artifact.name.includes("payload") ? null : "CN=Mock Publisher",
      issuer: artifact.name.includes("payload") ? null : "CN=Mock Issuing CA",
      timestamp: null,
      verification_source: "mock",
      note: artifact.name.includes("payload") ? "Recovered image hash no longer matches the original signed payload." : null,
    };
  }

  return {
    status: "not_applicable",
    subject: null,
    issuer: null,
    timestamp: null,
    verification_source: "mock",
    note: "Authenticode verification is not applicable for this artifact family.",
  };
}

export async function mockArtifactPreview(request: ArtifactPreviewRequest): Promise<ArtifactPreviewResponse> {
  await sleep(70);
  const artifact = await mockArtifactDetails(request.scan_id, request.artifact_id);
  if (artifact.kind === "zip" || artifact.kind === "jar" || artifact.kind === "apk" || artifact.kind === "seven_zip") {
    return {
      artifact_id: artifact.id,
      requested_mode: request.mode,
      resolved_mode: "archive",
      offset: 0,
      length: Math.min(artifact.size, 32768),
      total_size: artifact.size,
      has_more: false,
      warnings: artifact.kind === "seven_zip" ? ["Structured entry listing is mocked for this archive family."] : [],
      summary: artifact.preview,
      text_excerpt: null,
      hex_rows: [],
      archive_entry_count: 2,
      archive_entries_truncated: false,
      archive_entries: [
        {
          path: artifact.kind === "zip" ? "loader.exe" : "META-INF/MANIFEST.MF",
          kind: "file",
          size: 1842176,
          compressed_size: 721488,
          status: "ok",
          note: null,
        },
        {
          path: artifact.kind === "zip" ? "config/config.json" : "com/example/Main.class",
          kind: "file",
          size: 2480,
          compressed_size: 944,
          status: artifact.kind === "seven_zip" ? "partial" : "ok",
          note: artifact.kind === "seven_zip" ? "Recovered from mocked partial metadata." : null,
        },
      ],
    };
  }

  return {
    artifact_id: artifact.id,
    requested_mode: request.mode,
    resolved_mode: artifact.family === "text" || artifact.family === "script" || artifact.kind === "json" ? "text" : "hex",
    offset: request.offset ?? 0,
    length: request.length ?? 4096,
    total_size: artifact.size,
    has_more: artifact.size > (request.length ?? 4096),
    warnings: [],
    summary: artifact.preview,
    text_excerpt:
      artifact.family === "text" || artifact.family === "script" || artifact.kind === "json"
        ? "Mock preview content\nSelect a real artifact in the desktop runtime to inspect bytes or archive entries."
        : null,
    hex_rows:
      artifact.family === "text" || artifact.family === "script" || artifact.kind === "json"
        ? []
        : [
            { offset: 0, hex: "4D 5A 90 00 03 00 00 00", ascii: "MZ......" },
            { offset: 8, hex: "04 00 00 00 FF FF 00 00", ascii: "........" },
          ],
    archive_entry_count: null,
    archive_entries_truncated: false,
    archive_entries: [],
  };
}

export async function mockContentSignature(target: ContentTarget): Promise<ArtifactSignatureSummary> {
  await sleep(80);
  if (target.kind === "artifact") {
    return mockArtifactSignature(target.scan_id, target.artifact_id);
  }

  const details = await mockEntryDetails(target.source_id, target.path);
  const extension = details.entry.extension?.toLowerCase();
  if (extension && ["exe", "dll", "sys", "msi"].includes(extension)) {
    return {
      status: "valid",
      subject: "CN=Mock Publisher",
      issuer: "CN=Mock Issuing CA",
      timestamp: null,
      verification_source: "mock",
      note: null,
    };
  }

  return {
    status: "not_applicable",
    subject: null,
    issuer: null,
    timestamp: null,
    verification_source: "mock",
    note: "Authenticode is not applicable for this item.",
  };
}

export async function mockContentPreview(request: ContentPreviewRequest): Promise<ContentPreviewResponse> {
  await sleep(70);
  if (request.target.kind === "artifact") {
    const preview = await mockArtifactPreview({
      scan_id: request.target.scan_id,
      artifact_id: request.target.artifact_id,
      mode: request.mode,
      offset: request.offset,
      length: request.length,
      max_entries: request.max_entries,
    });
    return {
      target_key: preview.artifact_id,
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
    };
  }

  const details = await mockEntryDetails(request.target.source_id, request.target.path);
  const extension = details.entry.extension?.toLowerCase();
  const archive = extension && ["zip", "jar", "apk", "7z", "rar", "cab", "iso"].includes(extension);
  return {
    target_key: details.entry.path,
    requested_mode: request.mode,
    resolved_mode: archive ? "archive" : request.mode === "archive" ? "hex" : request.mode === "auto" ? "text" : request.mode,
    offset: request.offset ?? 0,
    length: Math.min(details.entry.size, 4096),
    total_size: details.entry.size,
    has_more: details.entry.size > 4096,
    warnings: archive && extension === "7z" ? ["Structured entry listing is mocked for this archive family."] : [],
    summary: details.summary,
    text_excerpt: archive ? null : `Mock preview for ${details.entry.name}\n\nPath: ${details.entry.path}`,
    hex_rows: archive
      ? []
      : [
          {
            offset: 0,
            hex: "4D 6F 63 6B 20 70 72 65 76 69 65 77",
            ascii: "Mock preview",
          },
        ],
    archive_entry_count: archive ? 1 : null,
    archive_entries_truncated: false,
    archive_entries: archive
      ? [
          {
            path: `${details.entry.name}/entry1.txt`,
            kind: "file",
            size: 1024,
            compressed_size: 512,
            status: "ok",
            note: null,
          },
        ]
      : [],
  };
}

export async function mockOpenPreviewSession(
  request: PreviewSessionOpenRequest,
): Promise<PreviewSessionInfo> {
  const preview = await mockContentPreview({
    target: request.target,
    entry_hint: request.entry_hint ?? null,
    mode: request.mode,
    offset: 0,
    length: 4096,
    max_entries: 65536,
  });
  const sessionId = `preview-session-${crypto.randomUUID()}`;
  const info: PreviewSessionInfo = {
    session_id: sessionId,
    target_key: preview.target_key,
    requested_mode: preview.requested_mode,
    resolved_mode: preview.resolved_mode,
    total_size: preview.total_size,
    summary: preview.summary,
    warnings: preview.warnings,
    preview_ready: true,
    archive_entry_count: preview.archive_entry_count,
    archive_entries_truncated: preview.archive_entries_truncated,
  };
  previewSessions.set(sessionId, { info, preview });
  return info;
}

export async function mockReadPreviewChunk(
  sessionId: string,
  offset: number,
  length: number,
): Promise<PreviewChunkResponse> {
  const session = previewSessions.get(sessionId);
  if (!session) {
    throw new Error(`Preview session ${sessionId} not found`);
  }
  if (session.preview.resolved_mode === "archive") {
    return {
      session_id: sessionId,
      target_key: session.preview.target_key,
      requested_mode: session.preview.requested_mode,
      resolved_mode: session.preview.resolved_mode,
      offset: 0,
      length: 0,
      total_size: session.preview.total_size,
      has_more: false,
      warnings: session.preview.warnings,
      text_excerpt: null,
      hex_rows: [],
    };
  }
  const boundedLength = Math.max(0, length);
  return {
    session_id: sessionId,
    target_key: session.preview.target_key,
    requested_mode: session.preview.requested_mode,
    resolved_mode: session.preview.resolved_mode,
    offset,
    length: boundedLength || session.preview.length,
    total_size: session.preview.total_size,
    has_more: session.preview.has_more,
    warnings: session.preview.warnings,
    text_excerpt: session.preview.text_excerpt,
    hex_rows: session.preview.hex_rows,
  };
}

export async function mockReadArchivePage(
  sessionId: string,
  offset: number,
  limit: number,
): Promise<ArchivePreviewPage> {
  const session = previewSessions.get(sessionId);
  if (!session) {
    throw new Error(`Preview session ${sessionId} not found`);
  }
  const entries = session.preview.archive_entries;
  const safeOffset = Math.max(0, Math.min(offset, entries.length));
  const safeLimit = Math.max(1, Math.min(limit, 2048));
  const slice = entries.slice(safeOffset, safeOffset + safeLimit);
  return {
    session_id: sessionId,
    target_key: session.preview.target_key,
    offset: safeOffset,
    count: slice.length,
    total_entries: session.preview.archive_entry_count,
    has_more:
      safeOffset + slice.length < entries.length ||
      (session.preview.archive_entry_count != null &&
        safeOffset + slice.length < session.preview.archive_entry_count),
    warnings: session.preview.warnings,
    entries: slice,
  };
}

export async function mockClosePreviewSession(sessionId: string): Promise<void> {
  previewSessions.delete(sessionId);
}

function countArtifactsByClass(artifacts: ArtifactRecord[], artifactClass: ArtifactRecord["artifact_class"]) {
  return artifacts.filter((artifact) => artifact.artifact_class === artifactClass).length;
}

export async function mockStartPreviewJob(request: ContentPreviewRequest): Promise<string> {
  const jobId = `preview-job-${crypto.randomUUID()}`;
  previewJobs.set(jobId, { status: newAsyncJobStatus(jobId) });
  window.setTimeout(async () => {
    const current = previewJobs.get(jobId);
    if (!current || current.status.state === "cancelled") {
      return;
    }
    current.status = { ...current.status, state: "running", updated_at: nowIso() };
    try {
      const result = await mockContentPreview(request);
      const latest = previewJobs.get(jobId);
      if (!latest || latest.status.state === "cancelled") {
        return;
      }
      previewJobs.set(jobId, {
        status: { ...latest.status, state: "completed", updated_at: nowIso(), error: null },
        result,
      });
    } catch (error) {
      const latest = previewJobs.get(jobId);
      if (!latest || latest.status.state === "cancelled") {
        return;
      }
      previewJobs.set(jobId, {
        status: {
          ...latest.status,
          state: "failed",
          updated_at: nowIso(),
          error: error instanceof Error ? error.message : "Preview job failed",
        },
      });
    }
  }, 0);
  return jobId;
}

export async function mockPreviewJobStatus(jobId: string): Promise<AsyncJobStatus> {
  const job = previewJobs.get(jobId);
  if (!job) {
    throw new Error(`Preview job ${jobId} not found`);
  }
  return job.status;
}

export async function mockPreviewJobResult(jobId: string): Promise<ContentPreviewResponse> {
  const job = previewJobs.get(jobId);
  if (!job) {
    throw new Error(`Preview job ${jobId} not found`);
  }
  if (job.status.state === "completed" && job.result) {
    return job.result;
  }
  if (job.status.state === "failed") {
    throw new Error(job.status.error ?? `Preview job ${jobId} failed`);
  }
  throw new Error("job_not_ready");
}

export async function mockCancelPreviewJob(jobId: string): Promise<void> {
  const job = previewJobs.get(jobId);
  if (!job) {
    return;
  }
  job.status = { ...job.status, state: "cancelled", updated_at: nowIso(), error: null };
  delete job.result;
}

export async function mockScanSnapshot(scanId: string): Promise<ScanSnapshot> {
  await sleep(100);
  const session = sessions.get(scanId);
  if (!session?.snapshot) {
    throw new Error(`Scan ${scanId} has not completed yet`);
  }
  return session.snapshot;
}

export async function mockRecentScans(): Promise<ScanSnapshot[]> {
  await sleep(120);
  return [...sessions.values()]
    .map((session) => session.snapshot)
    .filter((snapshot): snapshot is ScanSnapshot => Boolean(snapshot))
    .slice(-4)
    .reverse();
}

export async function mockRecover(request: RecoveryRequest): Promise<RecoverySummary> {
  await sleep(350);
  const session = sessions.get(request.scan_id);
  if (!session) {
    throw new Error(`Scan ${request.scan_id} not found`);
  }

  const items: RecoveryItemResult[] = session.results
    .filter((artifact) => request.artifact_ids.includes(artifact.id))
    .map((artifact) => ({
      artifact_id: artifact.id,
      file_path: `${request.destination}\\${artifact.name}`,
      metadata_path: `${request.destination}\\${artifact.name}.metadata.json`,
      sha256: `sha256-${artifact.id.slice(-8)}`,
      blake3: `blake3-${artifact.id.slice(-8)}`,
      status: artifact.recoverability === "good" ? ("recovered" as const) : ("recovered_with_warnings" as const),
      notes: artifact.notes,
    }));

  return {
    scan_id: request.scan_id,
    destination: request.destination,
    started_at: nowIso(),
    finished_at: nowIso(),
    items,
  };
}

export async function mockExport(scanId: string, destination: string): Promise<ReportBundle> {
  await sleep(220);
  return {
    json_path: `${destination}\\files-${scanId}.json`,
    csv_path: `${destination}\\files-${scanId}.csv`,
    html_path: `${destination}\\files-${scanId}.html`,
    dfxml_path: `${destination}\\files-${scanId}.dfxml.xml`,
  };
}

export async function mockListenScanProgress(listener: (progress: ScanProgress) => void) {
  progressListeners.add(listener);
  return () => progressListeners.delete(listener);
}

export async function mockListenScanResultsBatch(listener: (batch: ScanResultsBatch) => void) {
  resultsBatchListeners.add(listener);
  return () => resultsBatchListeners.delete(listener);
}

export async function mockListenSourceLoadProgress(listener: (status: SourceCatalogStatus) => void) {
  sourceLoadProgressListeners.add(listener);
  return () => sourceLoadProgressListeners.delete(listener);
}

export async function mockListenSourceLoadComplete(listener: (status: SourceCatalogStatus) => void) {
  sourceLoadCompleteListeners.add(listener);
  return () => sourceLoadCompleteListeners.delete(listener);
}

export async function mockListenDeletedBrowseReady(listener: (event: DeletedBrowseReadyEvent) => void) {
  deletedBrowseReadyListeners.add(listener);
  return () => deletedBrowseReadyListeners.delete(listener);
}

export async function mockListenDeletedBrowseProgress(listener: (event: DeletedBrowseProgressEvent) => void) {
  deletedBrowseProgressListeners.add(listener);
  return () => deletedBrowseProgressListeners.delete(listener);
}
