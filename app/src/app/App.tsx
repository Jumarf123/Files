import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSearch, FolderOutput, LoaderCircle, Play, RefreshCcw, Search, ShieldAlert, ShieldCheck, Square } from "lucide-react";
import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";

import { SourceBrowser } from "@/features/browser/source-browser";
import { RecoveryPanel } from "@/features/recovery/recovery-panel";
import { Inspector, PreviewPane } from "@/features/results/inspector";
import { usePreviewSession } from "@/features/results/use-preview-session";
import {
  LoadingState,
  ModeToggle,
  Splitter,
  StatFact,
  TabButton,
  TabErrorState,
  TabViewport,
  ZoomControls,
  type SplitterKind,
} from "@/features/workbench/chrome";
import { formatBytes, formatPercent, titleCase } from "@/shared/lib/format";
import {
  clampWorkbenchLayout,
  DEFAULT_WORKBENCH_LAYOUT,
  parseWorkbenchLayout,
  serializeWorkbenchLayout,
  WORKBENCH_LAYOUT_KEY,
  type WorkbenchLayout,
} from "@/shared/lib/workbench-layout";
import {
  artifactDetails,
  bootstrap,
  browseSource,
  cancelRawEvidenceRefinement,
  cancelEntryDetailsJob,
  chooseDirectory,
  contentSignature,
  cancelSourceLoad,
  entryDetailsJobResult,
  entryDetailsJobStatus,
  exportReports,
  inTauri,
  listenDeletedBrowseProgress,
  listenDeletedBrowseReady,
  listenSourceLoadComplete,
  listenSourceLoadProgress,
  listenScanProgress,
  listSources,
  loadSourceCatalog,
  rawEvidenceProgress,
  recover,
  refreshSources,
  scanProgress,
  sourceCatalogStatus,
  startEntryDetailsJob,
  startRawEvidenceRefinement,
  startScan,
  stopScan,
} from "@/shared/lib/tauri";
import type {
  AsyncJobStatus,
  ArtifactSummary,
  ArtifactPreviewMode,
  ContentPreviewResponse,
  ContentTarget,
  ReportBundle,
  RecoverySummary,
  RawEvidenceRefinementProgress,
  ScanMode,
  ScanProgress,
  ScanSource,
  DeletedBrowseReadyEvent,
  DeletedBrowseProgressEvent,
  SourceCatalogStatus,
  SourceEntry,
  SourceEntryDetails,
} from "@/shared/types/api";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Progress } from "@/shared/ui/progress";

type BottomTab = "details" | "preview" | "recovery";

const WORKBENCH_ZOOM_KEY = "files.workbench.zoom.v1";
const MIN_ZOOM = 0.8;
const MAX_ZOOM = 1.5;
const ZOOM_STEP = 0.1;
const FAST_SCAN_CARVE_BUDGET = 512 * 1024 * 1024;
const DEEP_SCAN_CARVE_BUDGET = 2 * 1024 * 1024 * 1024;
const PREVIEW_REQUEST_LENGTH = 4096;
const ARCHIVE_PREVIEW_PAGE_SIZE = 256;

export default function App() {
  const queryClient = useQueryClient();
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [catalogStatuses, setCatalogStatuses] = useState<Record<string, SourceCatalogStatus>>({});
  const [scanMode, setScanMode] = useState<ScanMode>("fast");
  const [includeLowConfidence, setIncludeLowConfidence] = useState(true);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [progressState, setProgressState] = useState<ScanProgress | null>(null);
  const [rawEvidenceJobId, setRawEvidenceJobId] = useState<string | null>(null);
  const [rawEvidenceState, setRawEvidenceState] = useState<RawEvidenceRefinementProgress | null>(null);
  const [rawEvidenceError, setRawEvidenceError] = useState<string | null>(null);
  const [selectedArtifactSummary, setSelectedArtifactSummary] = useState<ArtifactSummary | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectedEntry, setSelectedEntry] = useState<SourceEntry | null>(null);
  const [selectedEntryDetails, setSelectedEntryDetails] = useState<SourceEntryDetails | null>(null);
  const [selectedEntryDetailsStatus, setSelectedEntryDetailsStatus] = useState<AsyncJobStatus | null>(null);
  const [selectedEntryDetailsError, setSelectedEntryDetailsError] = useState<string | null>(null);
  const [signatureRequested, setSignatureRequested] = useState(false);
  const [destination, setDestination] = useState("C:\\Recovered");
  const [reportDestination, setReportDestination] = useState("C:\\Recovered\\Reports");
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<BottomTab>("details");
  const [lastRecovery, setLastRecovery] = useState<RecoverySummary | null>(null);
  const [lastReportBundle, setLastReportBundle] = useState<ReportBundle | null>(null);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [previewMode, setPreviewMode] = useState<ArtifactPreviewMode>("auto");
  const [previewOffset, setPreviewOffset] = useState(0);
  const [previewArchiveOffset, setPreviewArchiveOffset] = useState(0);
  const [browseSelection, setBrowseSelection] = useState<{ sourceId: string | null; path: string | null }>({
    sourceId: null,
    path: null,
  });
  const [deletedBrowseProgress, setDeletedBrowseProgress] = useState<DeletedBrowseProgressEvent | null>(null);
  const [browserRefreshToken, setBrowserRefreshToken] = useState(0);
  const [viewport, setViewport] = useState(() => ({
    width: typeof window === "undefined" ? 1440 : window.innerWidth,
    height: typeof window === "undefined" ? 900 : window.innerHeight,
  }));
  const [layout, setLayout] = useState<WorkbenchLayout>(() =>
    clampWorkbenchLayout(
      typeof window === "undefined"
        ? DEFAULT_WORKBENCH_LAYOUT
        : parseWorkbenchLayout(window.localStorage.getItem(WORKBENCH_LAYOUT_KEY)),
      {
        width: typeof window === "undefined" ? 1440 : window.innerWidth,
        height: typeof window === "undefined" ? 900 : window.innerHeight,
      },
    ),
  );
  const [zoom, setZoom] = useState(() => readInitialZoom());
  const dragStateRef = useRef<{ kind: SplitterKind; origin: number; startValue: number } | null>(null);
  const entryDetailsJobRef = useRef<string | null>(null);
  const activeScanSourceIdRef = useRef<string | null>(null);
  const completionTimerRef = useRef<number | null>(null);
  const progressFrameRef = useRef<number | null>(null);
  const pendingProgressRef = useRef<ScanProgress | null>(null);
  const deferredSearch = useDeferredValue(search);

  const bootstrapQuery = useQuery({ queryKey: ["bootstrap"], queryFn: bootstrap, staleTime: Infinity });
  const sourcesQuery = useQuery({ queryKey: ["sources"], queryFn: listSources });

  useEffect(() => {
    if (!selectedSourceId && sourcesQuery.data?.[0]) {
      setSelectedSourceId(sourcesQuery.data[0].id);
    }
  }, [selectedSourceId, sourcesQuery.data]);

  useEffect(() => {
    function handleResize() {
      const nextViewport = { width: window.innerWidth, height: window.innerHeight };
      setViewport(nextViewport);
      setLayout((current) => clampWorkbenchLayout(current, nextViewport));
    }

    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  useEffect(() => {
    window.localStorage.setItem(WORKBENCH_LAYOUT_KEY, serializeWorkbenchLayout(layout));
  }, [layout]);

  useEffect(() => {
    return () => {
      if (completionTimerRef.current != null) {
        window.clearTimeout(completionTimerRef.current);
      }
      if (progressFrameRef.current != null) {
        window.cancelAnimationFrame(progressFrameRef.current);
      }
    };
  }, []);

  const scheduleProgressCommit = useEffectEvent((progress: ScanProgress) => {
    pendingProgressRef.current = progress;
    if (progressFrameRef.current != null) {
      return;
    }
    progressFrameRef.current = window.requestAnimationFrame(() => {
      progressFrameRef.current = null;
      const nextProgress = pendingProgressRef.current;
      if (nextProgress) {
        setProgressState(nextProgress);
      }
    });
  });

  useEffect(() => {
    window.localStorage.setItem(WORKBENCH_ZOOM_KEY, zoom.toFixed(2));
    if (inTauri()) {
      let cancelled = false;
      void import("@tauri-apps/api/webview").then(async ({ getCurrentWebview }) => {
        if (!cancelled) {
          try {
            await getCurrentWebview().setZoom(zoom);
          } catch {
            return;
          }
        }
      });
      return () => {
        cancelled = true;
      };
    }
  }, [zoom]);

  useEffect(() => {
    function handlePointerMove(event: PointerEvent) {
      if (!dragStateRef.current) {
        return;
      }

      const draft =
        dragStateRef.current.kind === "vertical"
          ? { ...layout, leftWidth: dragStateRef.current.startValue + (event.clientX - dragStateRef.current.origin) }
          : { ...layout, bottomHeight: dragStateRef.current.startValue - (event.clientY - dragStateRef.current.origin) };

      setLayout(clampWorkbenchLayout(draft, viewport));
    }

    function handlePointerUp() {
      dragStateRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", handlePointerUp);
    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", handlePointerUp);
    };
  }, [layout, viewport]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (!(event.ctrlKey || event.metaKey)) {
        return;
      }

      if (event.key === "=" || event.key === "+" || event.key === "Add") {
        event.preventDefault();
        setZoom((current) => clampZoom(current + ZOOM_STEP));
      } else if (event.key === "-" || event.key === "_" || event.key === "Subtract") {
        event.preventDefault();
        setZoom((current) => clampZoom(current - ZOOM_STEP));
      } else if (event.key === "0") {
        event.preventDefault();
        setZoom(1);
      }
    }

    function handleWheel(event: WheelEvent) {
      if (!(event.ctrlKey || event.metaKey)) {
        return;
      }

      event.preventDefault();
      setZoom((current) => clampZoom(current + (event.deltaY < 0 ? ZOOM_STEP : -ZOOM_STEP)));
    }

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("wheel", handleWheel);
    };
  }, []);

  const effectiveSourceId = selectedSourceId ?? sourcesQuery.data?.[0]?.id ?? "";
  const selectedSource = sourcesQuery.data?.find((source) => source.id === effectiveSourceId) ?? null;
  const selectedCatalogStatus = selectedSource ? catalogStatuses[selectedSource.id] ?? null : null;
  const sourceLoadActive = selectedCatalogStatus?.state === "loading";
  const currentBrowsePath =
    browseSelection.sourceId === effectiveSourceId
      ? browseSelection.path ?? selectedSource?.mount_point ?? null
      : selectedSource?.mount_point ?? null;

  const startScanMutation = useMutation({
    mutationFn: startScan,
    onSuccess: (scanId) => {
      activeScanSourceIdRef.current = effectiveSourceId || null;
      startTransition(() => {
        setActiveScanId(scanId);
        setProgressState(null);
        setRawEvidenceJobId(null);
        setRawEvidenceState(null);
        setRawEvidenceError(null);
        setDeletedBrowseProgress(null);
        setSelectedArtifactSummary(null);
        setSelectedIds(new Set());
        setSelectedEntry(null);
        setRuntimeError(null);
        setLastRecovery(null);
        setLastReportBundle(null);
        setActiveTab("details");
      });
    },
  });

  const stopScanMutation = useMutation({ mutationFn: stopScan });
  const startRawEvidenceMutation = useMutation({
    mutationFn: startRawEvidenceRefinement,
    onSuccess: (jobId) => {
      setRawEvidenceJobId(jobId);
      setRawEvidenceError(null);
      setRawEvidenceState(null);
    },
    onError: (caughtError) => {
      setRawEvidenceError(caughtError instanceof Error ? caughtError.message : "Unable to start raw evidence refinement");
    },
  });
  const cancelRawEvidenceMutation = useMutation({ mutationFn: cancelRawEvidenceRefinement });
  const refreshMutation = useMutation({
    mutationFn: refreshSources,
    onSuccess: (sources) => {
      queryClient.setQueryData(["sources"], sources);
      if (!sources.some((source) => source.id === selectedSourceId)) {
        setSelectedSourceId(sources[0]?.id ?? null);
      }
      setCatalogStatuses((current) => {
        const next = { ...current };
        for (const key of Object.keys(next)) {
          if (!sources.some((source) => source.id === key)) {
            delete next[key];
          }
        }
        return next;
      });
    },
  });
  const loadCatalogMutation = useMutation({
    mutationFn: ({ sourceId, forceRebuild }: { sourceId: string; forceRebuild: boolean }) =>
      loadSourceCatalog(sourceId, forceRebuild),
  });
  const cancelLoadMutation = useMutation({ mutationFn: cancelSourceLoad });
  const recoverMutation = useMutation({
    mutationFn: recover,
    onSuccess: (summary) => {
      setLastRecovery(summary);
      setActiveTab("recovery");
    },
  });
  const exportMutation = useMutation({
    mutationFn: ({ scanId, path }: { scanId: string; path: string }) => exportReports(scanId, path),
    onSuccess: (bundle) => {
      setLastReportBundle(bundle);
      setActiveTab("recovery");
    },
  });

  const handleProgressEvent = useEffectEvent((progress: ScanProgress) => {
    if (progress.scan_id !== activeScanId) {
      return;
    }

    scheduleProgressCommit(progress);
    if (
      progress.status === "completed" ||
      progress.status === "completed_with_warnings" ||
      progress.status === "failed" ||
      progress.status === "cancelled"
    ) {
      const scanSourceId = activeScanSourceIdRef.current;
      if ((progress.status === "completed" || progress.status === "completed_with_warnings") && scanSourceId) {
        startTransition(() => {
          setBrowserRefreshToken((current) => current + 1);
        });
      }

      if (completionTimerRef.current != null) {
        window.clearTimeout(completionTimerRef.current);
      }
      completionTimerRef.current = window.setTimeout(() => {
        startTransition(() => {
          setActiveScanId((current) => (current === progress.scan_id ? null : current));
        });
      }, 250);
    }
  });

  const handleDeletedBrowseReady = useEffectEvent((event: DeletedBrowseReadyEvent) => {
    if (event.source_id !== effectiveSourceId) {
      return;
    }
    startTransition(() => {
      setDeletedBrowseProgress((current) =>
        current?.scan_id === event.scan_id ? null : current,
      );
      setBrowserRefreshToken((current) => current + 1);
    });
  });

  const handleDeletedBrowseProgress = useEffectEvent((event: DeletedBrowseProgressEvent) => {
    if (event.source_id !== effectiveSourceId) {
      return;
    }
    startTransition(() => {
      setDeletedBrowseProgress(event);
    });
  });

  const handleSourceLoadComplete = useEffectEvent((status: SourceCatalogStatus) => {
    setCatalogStatuses((current) => ({ ...current, [status.source_id]: status }));
    if (status.state === "ready" && status.source_id === effectiveSourceId) {
      startTransition(() => {
        setBrowserRefreshToken((current) => current + 1);
      });
    }
  });

  useEffect(() => {
    if (!activeScanId) {
      return;
    }

    let disposed = false;
    let unlistenProgress: (() => void) | undefined;

    void (async () => {
      try {
        const [progress, progressUnlisten] = await Promise.all([
          scanProgress(activeScanId).catch(() => null),
          listenScanProgress(handleProgressEvent),
        ]);

        if (disposed) {
          progressUnlisten();
          return;
        }

        unlistenProgress = progressUnlisten;

        if (progress) {
          setProgressState(progress);
        }
      } catch (caughtError) {
        setRuntimeError(caughtError instanceof Error ? caughtError.message : "Unable to attach scan listeners");
        setActiveScanId(null);
      }
    })();

    return () => {
      disposed = true;
      unlistenProgress?.();
    };
  }, [activeScanId]);

  useEffect(() => {
    if (!rawEvidenceJobId) {
      return;
    }

    let disposed = false;
    let timer: number | undefined;

    const poll = async () => {
      try {
        const progress = await rawEvidenceProgress(rawEvidenceJobId);
        if (disposed) {
          return;
        }
        setRawEvidenceState(progress);
        setRawEvidenceError(null);
        if (progress.state === "completed" || progress.state === "failed" || progress.state === "cancelled") {
          setRawEvidenceJobId(null);
          if (progress.state === "completed") {
            setBrowserRefreshToken((current) => current + 1);
            if (progress.scan_id) {
              void queryClient.invalidateQueries({ queryKey: ["artifact-details", progress.scan_id] });
            }
          }
          return;
        }
      } catch (caughtError) {
        if (!disposed) {
          setRawEvidenceError(caughtError instanceof Error ? caughtError.message : "Unable to read raw evidence progress");
          setRawEvidenceJobId(null);
        }
        return;
      }
      timer = window.setTimeout(poll, 750);
    };

    void poll();

    return () => {
      disposed = true;
      if (timer != null) {
        window.clearTimeout(timer);
      }
    };
  }, [queryClient, rawEvidenceJobId]);

  useEffect(() => {
    let disposed = false;
    let unlistenDeletedBrowseReady: (() => void) | undefined;
    let unlistenDeletedBrowseProgress: (() => void) | undefined;

    void Promise.all([
      listenDeletedBrowseReady(handleDeletedBrowseReady),
      listenDeletedBrowseProgress(handleDeletedBrowseProgress),
    ])
      .then(([readyUnlisten, progressUnlisten]) => {
        if (disposed) {
          readyUnlisten();
          progressUnlisten();
          return;
        }
        unlistenDeletedBrowseReady = readyUnlisten;
        unlistenDeletedBrowseProgress = progressUnlisten;
      })
      .catch(() => undefined);

    return () => {
      disposed = true;
      unlistenDeletedBrowseReady?.();
      unlistenDeletedBrowseProgress?.();
    };
  }, []);

  useEffect(() => {
    if (!selectedSourceId) {
      return;
    }

    let disposed = false;
    void sourceCatalogStatus(selectedSourceId)
      .then((status) => {
        if (!disposed) {
          setCatalogStatuses((current) => ({ ...current, [status.source_id]: status }));
        }
      })
      .catch(() => undefined);

    return () => {
      disposed = true;
    };
  }, [selectedSourceId]);

  useEffect(() => {
    let disposed = false;
    let unlistenProgress: (() => void) | undefined;
    let unlistenComplete: (() => void) | undefined;

    void (async () => {
      try {
        const [progressUnlisten, completeUnlisten] = await Promise.all([
          listenSourceLoadProgress((status) => {
            setCatalogStatuses((current) => ({ ...current, [status.source_id]: status }));
          }),
          listenSourceLoadComplete(handleSourceLoadComplete),
        ]);

        if (disposed) {
          progressUnlisten();
          completeUnlisten();
          return;
        }

        unlistenProgress = progressUnlisten;
        unlistenComplete = completeUnlisten;
      } catch {
        return;
      }
    })();

    return () => {
      disposed = true;
      unlistenProgress?.();
      unlistenComplete?.();
    };
  }, []);

  useEffect(() => {
    setPreviewOffset(0);
    setPreviewArchiveOffset(0);
    setPreviewMode("auto");
  }, [selectedArtifactSummary?.id, selectedEntry?.path]);

  const selectedArtifactQuery = useQuery({
    queryKey: ["artifact-details", selectedArtifactSummary?.scan_id ?? null, selectedArtifactSummary?.id ?? null],
    queryFn: () => artifactDetails(selectedArtifactSummary!.scan_id, selectedArtifactSummary!.id),
    enabled:
      Boolean(selectedArtifactSummary?.scan_id && selectedArtifactSummary?.id) &&
      (activeTab === "details" || activeTab === "preview"),
    staleTime: Infinity,
  });
  const selectedContentTarget = useMemo<ContentTarget | null>(
    () =>
      selectedArtifactSummary
        ? {
            kind: "artifact",
            scan_id: selectedArtifactSummary.scan_id,
            artifact_id: selectedArtifactSummary.id,
          }
        : selectedEntry
          ? {
              kind: "entry",
              source_id: effectiveSourceId,
              path: selectedEntry.path,
            }
          : null,
    [effectiveSourceId, selectedArtifactSummary, selectedEntry],
  );
  const signatureQuery = useQuery({
    queryKey: ["content-signature", selectedContentTarget ?? null],
    queryFn: () => contentSignature(selectedContentTarget!),
    enabled: activeTab === "details" && signatureRequested && Boolean(selectedContentTarget),
    staleTime: Infinity,
  });

  const selectedArtifact = selectedArtifactQuery.data ?? null;
  const resolvedSelectedEntry = selectedEntryDetails?.entry ?? selectedEntry;
  const selectedEntryPath = selectedEntry?.path ?? null;
  const hasSelectedArtifact = Boolean(selectedArtifactSummary?.id);
  const selectedContentTargetKey = selectedArtifactSummary
    ? `artifact:${selectedArtifactSummary.scan_id}:${selectedArtifactSummary.id}`
    : selectedEntry
      ? `entry:${effectiveSourceId}:${selectedEntry.path}`
      : null;
  const selectedPreviewRequest = useMemo(
    () =>
      activeTab === "preview" && selectedContentTarget
        ? {
            target: selectedContentTarget,
            entry_hint: selectedEntry ?? resolvedSelectedEntry ?? undefined,
            mode: previewMode,
          }
        : null,
    [activeTab, previewMode, resolvedSelectedEntry, selectedContentTarget, selectedEntry],
  );
  const {
    session: previewSession,
    chunk: previewChunk,
    archivePage: previewArchivePage,
    loading: previewLoading,
    error: previewError,
  } = usePreviewSession({
    active: activeTab === "preview" && Boolean(selectedPreviewRequest),
    request: selectedPreviewRequest,
    chunkOffset: previewOffset,
    chunkLength: PREVIEW_REQUEST_LENGTH,
    archiveOffset: previewArchiveOffset,
    archivePageSize: ARCHIVE_PREVIEW_PAGE_SIZE,
  });
  const previewData = useMemo(
    () => buildPreviewResponse(previewSession, previewChunk, previewArchivePage),
    [previewArchivePage, previewChunk, previewSession],
  );
  const selectedCount = selectedIds.size;
  const deletedBrowseProgressActive =
    deletedBrowseProgress != null &&
    deletedBrowseProgress.source_id === effectiveSourceId &&
    deletedBrowseProgress.progress_percent < 100;
  const rawEvidenceActive = rawEvidenceState?.state === "running" || Boolean(rawEvidenceJobId);
  const canRefineRawEvidence =
    Boolean(progressState?.scan_id) &&
    !activeScanId &&
    selectedSource?.filesystem === "ntfs" &&
    (progressState?.status === "completed" || progressState?.status === "completed_with_warnings") &&
    progressState?.raw_evidence_state !== "running";
  const effectiveBottomHeight =
    !selectedArtifactSummary && !selectedEntry && activeTab !== "recovery"
      ? Math.min(layout.bottomHeight, 180)
      : layout.bottomHeight;
  const selectedProgress = sourceLoadActive
    ? selectedCatalogStatus?.progress_percent ?? 0
    : rawEvidenceActive
      ? rawEvidenceState?.progress_percent ?? 0
    : deletedBrowseProgressActive
      ? deletedBrowseProgress?.progress_percent ?? 0
    : progressState?.progress_percent ?? 0;
  const displayedFacts = sourceLoadActive
    ? [
        { label: "Indexed", value: String(selectedCatalogStatus?.indexed_entries ?? 0) },
        { label: "Selected", value: String(selectedCount) },
      ]
    : rawEvidenceActive
    ? [
        { label: "Raw phase", value: titleCase(rawEvidenceState?.phase ?? "queued") },
        { label: "Progress", value: formatPercent(rawEvidenceState?.progress_percent ?? 0) },
        { label: "Selected", value: String(selectedCount) },
      ]
    : activeScanId
    ? [
        { label: "Candidates", value: String(progressState?.candidates_surfaced ?? 0) },
        { label: "Validated", value: String(progressState?.validated_hits ?? progressState?.recoverable_hits ?? 0) },
        { label: "Named", value: String(progressState?.named_hits ?? 0) },
        { label: "Selected", value: String(selectedCount) },
      ]
    : deletedBrowseProgressActive
      ? [
          {
            label: "Deleted indexed",
            value: `${deletedBrowseProgress?.processed_artifacts ?? 0}/${deletedBrowseProgress?.total_artifacts ?? 0}`,
          },
          { label: "Hits", value: String(progressState?.validated_hits ?? progressState?.recoverable_hits ?? 0) },
          { label: "Selected", value: String(selectedCount) },
        ]
    : [
        { label: "Hits", value: String(progressState?.validated_hits ?? progressState?.recoverable_hits ?? 0) },
        { label: "Selected", value: String(selectedCount) },
        { label: "Source", value: selectedSource ? formatBytes(selectedSource.total_bytes) : "-" },
      ];
  const progressText = runtimeError
    ? runtimeError
    : rawEvidenceError
      ? rawEvidenceError
    : sourceLoadActive
      ? formatCatalogProgressText(selectedCatalogStatus)
      : rawEvidenceActive
        ? formatRawEvidenceProgressText(rawEvidenceState)
      : deletedBrowseProgressActive
        ? formatDeletedBrowseProgressText(progressState, deletedBrowseProgress)
      : progressState
      ? formatScanProgressText(progressState)
      : "Ready";
  const appScaleStyle = !inTauri() && Math.abs(zoom - 1) > 0.01 ? browserScaleStyle(zoom) : undefined;
  const immediateEntryDetails = useMemo(
    () =>
      selectedEntry
        ? buildImmediateEntryDetails(
            selectedEntry,
            Boolean(selectedEntryDetailsStatus) &&
              (selectedEntryDetailsStatus?.state === "pending" || selectedEntryDetailsStatus?.state === "running"),
          )
        : null,
    [selectedEntry, selectedEntryDetailsStatus],
  );

  useEffect(() => {
    setSignatureRequested(false);
  }, [selectedContentTargetKey]);

  useEffect(() => {
    if (!selectedEntryPath || activeTab !== "details" || hasSelectedArtifact) {
      if (entryDetailsJobRef.current) {
        void cancelEntryDetailsJob(entryDetailsJobRef.current).catch(() => undefined);
      }
      entryDetailsJobRef.current = null;
      if (activeTab !== "details" || !selectedEntryPath) {
        setSelectedEntryDetails(null);
        setSelectedEntryDetailsStatus(null);
        setSelectedEntryDetailsError(null);
      }
      return;
    }

    let disposed = false;
    let localJobId: string | null = null;
    setSelectedEntryDetails(null);
    setSelectedEntryDetailsStatus(null);
    setSelectedEntryDetailsError(null);

    const poll = async (jobId: string) => {
      while (!disposed) {
        const status = await entryDetailsJobStatus(jobId).catch((error) => {
          throw error instanceof Error ? error : new Error("Unable to read entry details job status");
        });
        if (disposed) {
          return;
        }
        setSelectedEntryDetailsStatus(status);
        if (status.state === "completed") {
          const result = await entryDetailsJobResult(jobId);
          if (!disposed) {
            setSelectedEntryDetails(result);
          }
          return;
        }
        if (status.state === "failed" || status.state === "cancelled") {
          if (!disposed) {
            setSelectedEntryDetailsError(status.error ?? "Entry details job did not complete.");
          }
          return;
        }
        await delay(60);
      }
    };

    void startEntryDetailsJob(effectiveSourceId, selectedEntryPath)
      .then((jobId) => {
        if (disposed) {
          void cancelEntryDetailsJob(jobId).catch(() => undefined);
          return;
        }
        localJobId = jobId;
        entryDetailsJobRef.current = jobId;
        return poll(jobId);
      })
      .catch((error) => {
        if (!disposed) {
          setSelectedEntryDetailsError(error instanceof Error ? error.message : "Unable to start entry details job");
        }
      });

    return () => {
      disposed = true;
      if (localJobId) {
        void cancelEntryDetailsJob(localJobId).catch(() => undefined);
      }
    };
  }, [activeTab, effectiveSourceId, hasSelectedArtifact, selectedEntryPath]);

  function beginResize(kind: SplitterKind, event: ReactPointerEvent<HTMLDivElement>) {
    dragStateRef.current = {
      kind,
      origin: kind === "vertical" ? event.clientX : event.clientY,
      startValue: kind === "vertical" ? layout.leftWidth : layout.bottomHeight,
    };
    document.body.style.cursor = kind === "vertical" ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
  }

  async function handleSelectRecoveryDirectory(target: "destination" | "reports") {
    const chosen = await chooseDirectory(target === "destination" ? "Choose recovery destination" : "Choose report destination");
    if (!chosen) {
      return;
    }

    if (target === "destination") {
      setDestination(chosen);
    } else {
      setReportDestination(chosen);
    }
  }

  function handleSelectSource(sourceId: string) {
    startTransition(() => {
      setSelectedSourceId(sourceId);
      setBrowseSelection({ sourceId, path: null });
      setSelectedEntry(null);
      setSelectedArtifactSummary(null);
      setSelectedIds(new Set());
    });
  }

  function handleSelectPath(path: string) {
    startTransition(() => {
      setBrowseSelection({ sourceId: effectiveSourceId, path });
      setSelectedEntry(null);
      setSelectedArtifactSummary(null);
      setSelectedIds(new Set());
    });
  }

  function handleInspectArtifact(artifact: ArtifactSummary) {
    startTransition(() => {
      setSelectedEntry(null);
      setSelectedArtifactSummary(artifact);
      setSelectedIds(new Set([artifact.id]));
    });
  }

  function handleSelectEntry(entry: SourceEntry | null) {
    startTransition(() => {
      setSelectedArtifactSummary(null);
      setSelectedEntry(entry);
      setSelectedIds(new Set());
    });
  }

  async function handleLoadSource(forceRebuild = false) {
    if (!selectedSource || !selectedSource.mount_point || loadCatalogMutation.isPending) {
      return;
    }

    const loadId = await loadCatalogMutation.mutateAsync({
      sourceId: selectedSource.id,
      forceRebuild,
    });
    startTransition(() => {
      setCatalogStatuses((current) => ({
        ...current,
        [selectedSource.id]: {
          state: "loading",
          source_id: selectedSource.id,
          load_id: loadId,
          phase: "opening_volume",
          progress_percent: 0,
          indexed_entries: 0,
          total_estimated_entries: null,
          cache_state: forceRebuild ? "rebuild" : "cold",
          started_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          error: null,
          error_code: null,
          error_detail: null,
        },
      }));
      setBrowseSelection({ sourceId: selectedSource.id, path: null });
      setSelectedEntry(null);
      setSelectedArtifactSummary(null);
      setSelectedIds(new Set());
    });
  }

  async function handleCancelSourceLoad() {
    const loadId = selectedCatalogStatus?.load_id;
    if (!loadId || cancelLoadMutation.isPending) {
      return;
    }
    await cancelLoadMutation.mutateAsync(loadId);
  }

  async function handleStartScan() {
    if (!effectiveSourceId || startScanMutation.isPending) {
      return;
    }

    await startScanMutation.mutateAsync({
      source_id: effectiveSourceId,
      mode: scanMode,
      include_low_confidence: includeLowConfidence,
      carve_budget_bytes: scanMode === "deep" ? DEEP_SCAN_CARVE_BUDGET : FAST_SCAN_CARVE_BUDGET,
      raw_evidence: {
        mode: "manual_deep",
        i30_enabled: false,
        usn_enabled: false,
        raw_usn_fallback: false,
        emit_initial_results_before_raw: true,
      },
    });
  }

  async function handleStopScan() {
    if (!activeScanId || stopScanMutation.isPending) {
      return;
    }
    await stopScanMutation.mutateAsync(activeScanId);
  }

  async function handleStartRawEvidenceRefinement() {
    const scanId = progressState?.scan_id;
    if (!scanId || !effectiveSourceId || startRawEvidenceMutation.isPending || rawEvidenceActive) {
      return;
    }
    await startRawEvidenceMutation.mutateAsync({
      scan_id: scanId,
      source_id: effectiveSourceId,
      scope: currentBrowsePath,
    });
  }

  async function handleCancelRawEvidenceRefinement() {
    if (!rawEvidenceJobId || cancelRawEvidenceMutation.isPending) {
      return;
    }
    await cancelRawEvidenceMutation.mutateAsync(rawEvidenceJobId);
  }

  async function handleRecoverSelected() {
    const scanId = selectedArtifactSummary?.scan_id ?? progressState?.scan_id ?? activeScanId;
    if (!scanId || selectedIds.size === 0 || recoverMutation.isPending) {
      return;
    }

    await recoverMutation.mutateAsync({
      scan_id: scanId,
      artifact_ids: [...selectedIds],
      destination,
    });
  }

  async function handleExportReports() {
    const scanId = selectedArtifactSummary?.scan_id ?? progressState?.scan_id ?? activeScanId;
    if (!scanId || exportMutation.isPending) {
      return;
    }

    await exportMutation.mutateAsync({
      scanId,
      path: reportDestination,
    });
  }

  return (
    <div className="h-full w-full overflow-hidden bg-[#0d0f13]" style={appScaleStyle}>
      <main className="flex h-screen min-w-0 flex-col overflow-hidden bg-[#0d0f13] text-slate-100">
        <header className="border-b border-white/8 bg-[#121419]" data-testid="workbench-toolbar">
          <div className="flex min-w-0 flex-wrap items-center gap-2 px-3 py-2">
            <div className="flex min-w-0 flex-1 items-center gap-2">
              <div className="hidden min-w-0 max-w-36 lg:block">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-semibold text-white">
                    {bootstrapQuery.data?.app_name ?? "Files"}
                  </span>
                  {bootstrapQuery.data?.is_elevated ? (
                    <ShieldCheck className="size-4 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="size-4 text-amber-300" />
                  )}
                </div>
                <div className="truncate text-[11px] text-slate-500">
                  {selectedSource?.display_name ?? "No source"} • {selectedSource?.filesystem.toUpperCase() ?? "N/A"}
                </div>
              </div>

              <SourceSelect
                sources={sourcesQuery.data ?? []}
                value={effectiveSourceId}
                onChange={handleSelectSource}
              />

              <ModeToggle value={scanMode} onChange={setScanMode} />

              <label className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap text-xs text-slate-400">
                <input
                  checked={includeLowConfidence}
                  className="size-3.5 accent-[#5865f2]"
                  onChange={(event) => setIncludeLowConfidence(event.target.checked)}
                  type="checkbox"
                />
                Low confidence
              </label>
            </div>

            <div className="flex min-w-0 flex-1 flex-wrap items-center justify-end gap-2">
              <div className="relative min-w-48 max-w-[420px] flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-500" />
                <Input
                  className="h-9 rounded-md border-white/8 bg-[#101217] pl-9 pr-3 text-sm"
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Filter folders and deleted files"
                  value={search}
                />
              </div>

              <ZoomControls
                zoom={zoom}
                onDecrease={() => setZoom((current) => clampZoom(current - ZOOM_STEP))}
                onIncrease={() => setZoom((current) => clampZoom(current + ZOOM_STEP))}
                onReset={() => setZoom(1)}
              />

              <Button
                aria-label="Refresh sources"
                className="size-9 shrink-0 rounded-md p-0"
                onClick={() => refreshMutation.mutate()}
                size="icon"
                data-testid="refresh-sources"
                title="Refresh sources"
                type="button"
                variant="secondary"
              >
                {refreshMutation.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <RefreshCcw className="size-4" />}
              </Button>

              {sourceLoadActive ? (
                <Button
                  className="h-9 rounded-md px-3"
                  onClick={() => void handleCancelSourceLoad()}
                  size="sm"
                  data-testid="cancel-source-load"
                  type="button"
                  variant="secondary"
                >
                  {cancelLoadMutation.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <Square className="size-4" />}
                  Cancel
                </Button>
              ) : (
                <>
                  <Button
                    className="h-9 rounded-md px-3"
                    disabled={!selectedSource?.mount_point || loadCatalogMutation.isPending}
                    onClick={() => void handleLoadSource(false)}
                    size="sm"
                    data-testid="load-source"
                    type="button"
                    variant="secondary"
                  >
                    {loadCatalogMutation.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <FolderOutput className="size-4" />}
                    Load
                  </Button>
                  <Button
                    className="h-9 rounded-md px-3"
                    disabled={!selectedSource?.mount_point || loadCatalogMutation.isPending}
                    onClick={() => void handleLoadSource(true)}
                    size="sm"
                    data-testid="rebuild-source"
                    type="button"
                    variant="secondary"
                  >
                    Rebuild
                  </Button>
                </>
              )}

              {activeScanId ? (
                <Button
                  aria-label="Stop scan"
                  className="size-9 shrink-0 rounded-md p-0"
                  onClick={() => void handleStopScan()}
                  size="icon"
                  title="Stop scan"
                  type="button"
                  variant="danger"
                >
                  {stopScanMutation.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <Square className="size-4" />}
                </Button>
              ) : (
                <Button
                  aria-label="Start scan"
                  className="size-9 shrink-0 rounded-md p-0"
                  disabled={
                    !effectiveSourceId ||
                    startScanMutation.isPending ||
                    sourcesQuery.isLoading ||
                    sourceLoadActive ||
                    rawEvidenceActive
                  }
                  onClick={() => void handleStartScan()}
                  size="icon"
                  title="Start scan"
                  type="button"
                >
                  {startScanMutation.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
                </Button>
              )}

              {!activeScanId && (rawEvidenceActive || canRefineRawEvidence) ? (
                <Button
                  aria-label={rawEvidenceActive ? "Cancel path refinement" : "Refine paths"}
                  className="h-9 rounded-md px-3"
                  disabled={startRawEvidenceMutation.isPending || cancelRawEvidenceMutation.isPending}
                  onClick={() =>
                    void (rawEvidenceActive ? handleCancelRawEvidenceRefinement() : handleStartRawEvidenceRefinement())
                  }
                  size="sm"
                  title={rawEvidenceActive ? "Cancel path refinement" : "Refine paths"}
                  type="button"
                  variant={rawEvidenceActive ? "secondary" : "ghost"}
                >
                  {rawEvidenceActive ? (
                    cancelRawEvidenceMutation.isPending ? (
                      <LoaderCircle className="size-4 animate-spin" />
                    ) : (
                      <Square className="size-4" />
                    )
                  ) : startRawEvidenceMutation.isPending ? (
                    <LoaderCircle className="size-4 animate-spin" />
                  ) : (
                    <FileSearch className="size-4" />
                  )}
                  <span className="hidden xl:inline">{rawEvidenceActive ? "Cancel refine" : "Refine paths"}</span>
                </Button>
              ) : null}
            </div>
          </div>

          <div className="flex items-center gap-4 border-t border-white/6 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-3 text-xs text-slate-400">
                <span className="truncate">{progressText}</span>
                <span className="shrink-0 font-mono text-[11px] text-slate-500">{formatPercent(selectedProgress)}</span>
              </div>
              <Progress className="mt-2 h-2 rounded-sm bg-white/6" value={selectedProgress} />
            </div>

            <div className="flex shrink-0 items-center gap-4 text-xs text-slate-400">
              {displayedFacts.map((fact) => (
                <StatFact key={fact.label} label={fact.label} value={fact.value} />
              ))}
            </div>
          </div>
        </header>

        <div
          className="grid min-h-0 flex-1"
          style={{
            gridTemplateRows: `minmax(0, 1fr) 6px ${effectiveBottomHeight}px`,
          }}
        >
          {selectedSource?.mount_point ? (
            <SourceBrowser
              activePath={currentBrowsePath}
              filterText={deferredSearch}
              leftPaneWidth={layout.leftWidth}
              loadDirectory={browseSource}
              onInspectArtifact={handleInspectArtifact}
              onResizePointerDown={(event) => beginResize("vertical", event)}
              onSelectEntry={handleSelectEntry}
              onSelectPath={handleSelectPath}
              refreshToken={browserRefreshToken}
              selectedArtifactId={selectedArtifactSummary?.id ?? null}
              selectedEntryPath={resolvedSelectedEntry?.path ?? null}
              source={selectedSource}
            />
          ) : (
            <SourceLoadPanel
              leftPaneWidth={layout.leftWidth}
              onResizePointerDown={(event) => beginResize("vertical", event)}
              status={selectedCatalogStatus}
            />
          )}

          <Splitter kind="horizontal" onPointerDown={(event) => beginResize("horizontal", event)} />

          <section className="flex min-h-0 flex-col border-t border-white/8 bg-[#101114]">
            <div className="flex items-center justify-between gap-3 border-b border-white/8 px-4 py-2.5">
              <div className="flex items-center gap-1">
                <TabButton active={activeTab === "details"} label="Details" onClick={() => setActiveTab("details")} />
                <TabButton active={activeTab === "preview"} label="Preview" onClick={() => setActiveTab("preview")} />
                <TabButton active={activeTab === "recovery"} label="Recovery" onClick={() => setActiveTab("recovery")} />
              </div>

              <div className="text-xs text-slate-400">
                {selectedArtifactSummary
                  ? "Deleted file selected"
                  : selectedEntry
                    ? "Live file selected"
                    : "Select a file or deleted entry"}
              </div>
            </div>

            <div className="min-h-0 flex-1 overflow-hidden">
              {activeTab === "details" ? (
                <TabViewport>
                  {selectedArtifactSummary ? (
                    selectedArtifactQuery.isFetching && !selectedArtifact ? (
                    <LoadingState label="Loading details" />
                    ) : (
                      <Inspector
                        artifact={selectedArtifact}
                        entry={null}
                        onRequestSignature={() => setSignatureRequested(true)}
                        signature={signatureQuery.data ?? null}
                        signaturePending={signatureRequested && signatureQuery.isFetching}
                        signatureRequested={signatureRequested}
                      />
                    )
                  ) : selectedEntryDetailsError && !selectedEntry && !selectedEntryDetails ? (
                    <TabErrorState message={selectedEntryDetailsError} />
                  ) : (
                    <Inspector
                      artifact={null}
                      entry={selectedEntryDetails ?? immediateEntryDetails}
                      onRequestSignature={() => setSignatureRequested(true)}
                      signature={signatureQuery.data ?? null}
                      signaturePending={signatureRequested && signatureQuery.isFetching}
                      signatureRequested={signatureRequested}
                    />
                  )}
                </TabViewport>
              ) : null}

              {activeTab === "preview" ? (
                <TabViewport>
                  {(selectedArtifactSummary ? selectedArtifactQuery.isFetching && !selectedArtifact : false) ? (
                    <LoadingState label="Loading preview" />
                  ) : (
                    <PreviewPane
                      artifact={selectedArtifact}
                      entry={resolvedSelectedEntry}
                      error={previewError}
                      loading={activeTab === "preview" && Boolean(selectedContentTarget) && previewLoading}
                      mode={previewMode}
                      onChangeMode={(nextMode) => {
                        setPreviewMode(nextMode);
                        setPreviewOffset(0);
                        setPreviewArchiveOffset(0);
                      }}
                      onNavigate={(direction) => {
                        if ((previewSession?.resolved_mode ?? previewData?.resolved_mode) === "archive") {
                          setPreviewArchiveOffset((current) =>
                            Math.max(0, current + direction * ARCHIVE_PREVIEW_PAGE_SIZE),
                          );
                          return;
                        }
                        setPreviewOffset((current) => Math.max(0, current + direction * PREVIEW_REQUEST_LENGTH));
                      }}
                      preview={previewData}
                    />
                  )}
                </TabViewport>
              ) : null}

              {activeTab === "recovery" ? (
                <TabViewport>
                  <RecoveryPanel
                    destination={destination}
                    exportPending={exportMutation.isPending}
                    lastReportBundle={lastReportBundle}
                    lastRecovery={lastRecovery}
                    onBrowseDestination={() => void handleSelectRecoveryDirectory("destination")}
                    onBrowseReports={() => void handleSelectRecoveryDirectory("reports")}
                    onExport={() => void handleExportReports()}
                    onRecover={() => void handleRecoverSelected()}
                    recoverPending={recoverMutation.isPending}
                    reportDestination={reportDestination}
                    selectedCount={selectedCount}
                  />
                </TabViewport>
              ) : null}
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}

function SourceSelect({
  onChange,
  sources,
  value,
}: {
  onChange: (sourceId: string) => void;
  sources: ScanSource[];
  value: string;
}) {
  return (
    <select
      className="h-9 w-36 shrink-0 rounded-md border border-white/8 bg-[#101217] px-3 text-sm text-slate-100 outline-none transition focus:border-[#5865f2]"
      data-testid="source-select"
      onChange={(event) => onChange(event.target.value)}
      value={value}
    >
      {sources.map((source) => (
        <option key={source.id} value={source.id}>
          {source.mount_point ?? source.display_name}
        </option>
      ))}
    </select>
  );
}

function SourceLoadPanel({
  leftPaneWidth,
  onResizePointerDown,
  status,
}: {
  leftPaneWidth: number;
  onResizePointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
  status: SourceCatalogStatus | null;
}) {
  const isLoading = status?.state === "loading";
  const isFailed = status?.state === "failed";
  const statusLabel = formatCatalogPhase(status?.phase, status?.state);

  return (
    <section
      className="grid min-h-0 border-b border-white/8 bg-[#0f1116]"
      data-testid="browser-workbench"
      style={{ gridTemplateColumns: `${leftPaneWidth}px 6px minmax(0, 1fr)` }}
    >
      <div className="min-h-0 border-r border-white/8 bg-[#0d1015] p-4">
        <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Tree</div>
        <div className="mt-3 flex h-[calc(100%-2rem)] items-center justify-center rounded-md border border-dashed border-white/8 bg-[#111318] px-4 text-center text-sm text-slate-500">
          Tree will appear after loading.
        </div>
      </div>
      <Splitter kind="vertical" onPointerDown={onResizePointerDown} />
      <div className="flex min-h-0 items-center justify-center bg-[#101217] p-8">
        <div className="w-full max-w-xl">
          {isLoading || isFailed ? (
            <div className="rounded-xl border border-white/8 bg-[#111318] p-5" data-testid="source-load-panel">
              <div className="flex items-center justify-between gap-3 text-sm text-slate-300">
                <span>{statusLabel}</span>
                <span className="font-mono text-slate-400">{formatPercent(status?.progress_percent ?? 0)}</span>
              </div>
              <Progress className="mt-3 h-2 rounded-md bg-white/6" value={status?.progress_percent ?? 0} />
              <div className="mt-3 flex items-center justify-between gap-4 text-xs text-slate-500">
                <span>{(status?.indexed_entries ?? 0).toLocaleString()} indexed</span>
                <span>{titleCase(status?.cache_state?.replaceAll("_", " ") ?? "cold")}</span>
              </div>
              {status?.error ? (
                <div className="mt-3 text-sm text-rose-300">{status.error_detail ?? status.error}</div>
              ) : null}
            </div>
          ) : (
            <div className="text-center text-lg text-slate-400">Select a disk and press Load to load all files.</div>
          )}
        </div>
      </div>
    </section>
  );
}

function delay(milliseconds: number) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function formatCatalogProgressText(status: SourceCatalogStatus | null) {
  if (!status) {
    return "Load a mounted source to build the browser catalog";
  }

  const phase = formatCatalogPhase(status.phase, status.state);
  const totals = status.total_estimated_entries
    ? `${status.indexed_entries.toLocaleString()} / ${status.total_estimated_entries.toLocaleString()}`
    : `${status.indexed_entries.toLocaleString()} indexed`;
  return `${phase} • ${totals}`;
}

function formatScanProgressText(progress: ScanProgress) {
  const status =
    progress.status === "completed_with_warnings"
      ? "Completed with warnings"
      : titleCase(progress.status);
  if (progress.phase === "scanning_deleted_entries") {
    const records = (progress.records_scanned ?? progress.files_examined).toLocaleString();
    const candidates = (progress.candidates_surfaced ?? progress.artifacts_found).toLocaleString();
    const validated = (progress.validated_hits ?? progress.recoverable_hits ?? 0).toLocaleString();
    const named = (progress.named_hits ?? 0).toLocaleString();
    const speed = progress.records_per_second ? ` • ${Math.round(progress.records_per_second).toLocaleString()} rec/s` : "";
    return `${status} • ${progress.stage} • ${records} records${speed} • ${candidates} candidates • ${validated} validated • ${named} named`;
  }
  if (progress.status === "completed" || progress.status === "completed_with_warnings") {
    const hits = (progress.validated_hits ?? progress.verified_hits ?? progress.artifacts_found).toLocaleString();
    const carved = (progress.carved_hits ?? 0).toLocaleString();
    const completionLabel = progress.status === "completed_with_warnings" ? "Scan complete with warnings" : "Scan complete";
    return `${status} • ${completionLabel} • ${hits} stable hits • ${carved} carved`;
  }
  return `${status} • ${progress.message}`;
}

function formatRawEvidenceProgressText(progress: RawEvidenceRefinementProgress | null) {
  if (!progress) {
    return "Refining paths from NTFS raw evidence";
  }
  const phase = titleCase(progress.phase);
  const processed = progress.processed_units > 0 ? ` • ${progress.processed_units.toLocaleString()} units` : "";
  return `${titleCase(progress.state)} • ${phase} • ${formatPercent(progress.progress_percent)}${processed}`;
}

function formatDeletedBrowseProgressText(
  progress: ScanProgress | null,
  deletedBrowseProgress: DeletedBrowseProgressEvent | null,
) {
  if (!deletedBrowseProgress) {
    return progress ? formatScanProgressText(progress) : "Preparing deleted results";
  }

  const processed = deletedBrowseProgress.processed_artifacts.toLocaleString();
  const total = deletedBrowseProgress.total_artifacts.toLocaleString();
  const hits = (progress?.validated_hits ?? progress?.recoverable_hits ?? 0).toLocaleString();
  const status = progress?.status === "completed_with_warnings" ? "Completed with warnings" : "Completed";
  return `${status} • Building deleted folder index • ${processed} / ${total} deleted artifacts placed • ${hits} stable hits ready`;
}

function buildPreviewResponse(
  session: ReturnType<typeof usePreviewSession>["session"],
  chunk: ReturnType<typeof usePreviewSession>["chunk"],
  archivePage: ReturnType<typeof usePreviewSession>["archivePage"],
): ContentPreviewResponse | null {
  if (!session) {
    return null;
  }

  const warningSet = new Set<string>(session.warnings);
  for (const warning of chunk?.warnings ?? []) {
    warningSet.add(warning);
  }
  for (const warning of archivePage?.warnings ?? []) {
    warningSet.add(warning);
  }

  return {
    target_key: session.target_key,
    requested_mode: session.requested_mode,
    resolved_mode: session.resolved_mode,
    offset: session.resolved_mode === "archive" ? archivePage?.offset ?? 0 : chunk?.offset ?? 0,
    length: session.resolved_mode === "archive" ? archivePage?.count ?? 0 : chunk?.length ?? 0,
    total_size: chunk?.total_size ?? session.total_size,
    has_more: session.resolved_mode === "archive" ? archivePage?.has_more ?? false : chunk?.has_more ?? false,
    warnings: [...warningSet],
    summary: session.summary,
    text_excerpt: chunk?.text_excerpt ?? null,
    hex_rows: chunk?.hex_rows ?? [],
    archive_entry_count: archivePage?.total_entries ?? session.archive_entry_count,
    archive_entries_truncated:
      session.resolved_mode === "archive"
        ? Boolean((archivePage?.has_more ?? false) || session.archive_entries_truncated)
        : session.archive_entries_truncated,
    archive_entries: archivePage?.entries ?? [],
  };
}

function buildImmediateEntryDetails(entry: SourceEntry, loading: boolean): SourceEntryDetails {
  const summary: SourceEntryDetails["summary"] = [];
  if (entry.attr_bits != null) {
    summary.push({
      label: "ATTR",
      value: `0x${entry.attr_bits.toString(16).padStart(4, "0")}`,
    });
  }
  if (entry.attributes.length > 0) {
    summary.push({
      label: "Attributes",
      value: entry.attributes.join(", "),
    });
  }
  return {
    entry,
    notes: loading ? ["Loading extended metadata in the background."] : ["Basic entry metadata is ready."],
    summary,
  };
}

function formatCatalogPhase(
  phase: SourceCatalogStatus["phase"] | undefined,
  state: SourceCatalogStatus["state"] | undefined,
) {
  switch (phase) {
    case "opening_volume":
      return "Opening volume";
    case "enumerating_files":
      return "Enumerating files";
    case "augmenting_ntfs_metadata":
      return "Reading metadata";
    case "building_indexes":
      return "Building indexes";
    case "finalizing":
      return "Finalizing";
    default:
      return titleCase(state ?? "unloaded");
  }
}

function readInitialZoom() {
  if (typeof window === "undefined") {
    return 1;
  }

  const parsed = Number.parseFloat(window.localStorage.getItem(WORKBENCH_ZOOM_KEY) ?? "1");
  return Number.isFinite(parsed) ? clampZoom(parsed) : 1;
}

function clampZoom(value: number) {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round(value * 10) / 10));
}

function browserScaleStyle(zoom: number) {
  return {
    width: `${100 / zoom}%`,
    height: `${100 / zoom}%`,
    transform: `scale(${zoom})`,
    transformOrigin: "top left",
  } as const;
}
