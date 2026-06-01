import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowUp,
  ChevronRight,
  Database,
  EyeOff,
  File,
  FileArchive,
  FileCode2,
  FileImage,
  FileText,
  Folder,
  FolderOpen,
  Lock,
  Shield,
} from "lucide-react";
import {
  startTransition,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
} from "react";

import { cn } from "@/shared/lib/cn";
import { formatBytes, formatDate } from "@/shared/lib/format";
import type {
  ArtifactSummary,
  BrowseSourceRequest,
  SourceDirectoryListing,
  ScanSource,
  SourceEntry,
} from "@/shared/types/api";
import { isUnknownBucketPath, normalizeBrowserPath } from "./source-browser-index";

const TREE_PAGE_SIZE = 256;
const LIST_PAGE_SIZE = 256;
const TREE_ROW_HEIGHT = 30;
const LIST_ROW_HEIGHT = 48;
const LIST_MIN_WIDTH = 1260;

type DirectorySortKey = "name" | "type" | "size" | "created_at" | "modified_at" | "accessed_at" | "deleted_hits";
type DirectorySortState = {
  key: DirectorySortKey;
  direction: "asc" | "desc";
};

type ListingCache = Record<string, SourceDirectoryListing>;

type TreeRow =
  | {
      kind: "entry";
      depth: number;
      path: string;
      synthetic: boolean;
      active: boolean;
      expanded: boolean;
      loading: boolean;
      isRoot: boolean;
      entry: SourceEntry | null;
      deletedHits: number;
    }
  | {
      kind: "load_more";
      depth: number;
      path: string;
    };

type BrowserListRow =
  | {
      kind: "entry";
      key: string;
      entry: SourceEntry;
      synthetic: boolean;
    }
  | {
      kind: "deleted";
      key: string;
      artifact: ArtifactSummary;
    };

interface SourceBrowserProps {
  leftPaneWidth: number;
  source: ScanSource | null;
  activePath: string | null;
  refreshToken: number;
  selectedEntryPath: string | null;
  selectedArtifactId: string | null;
  filterText: string;
  loadDirectory: (request: BrowseSourceRequest) => Promise<SourceDirectoryListing>;
  onInspectArtifact: (artifact: ArtifactSummary) => void;
  onSelectPath: (path: string) => void;
  onSelectEntry: (entry: SourceEntry | null) => void;
  onResizePointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
}

export function SourceBrowser({
  leftPaneWidth,
  source,
  activePath,
  refreshToken,
  selectedEntryPath,
  selectedArtifactId,
  filterText,
  loadDirectory,
  onInspectArtifact,
  onSelectPath,
  onSelectEntry,
  onResizePointerDown,
}: SourceBrowserProps) {
  const [cache, setCache] = useState<ListingCache>({});
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [loadingKeys, setLoadingKeys] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [sort, setSort] = useState<DirectorySortState>({ key: "name", direction: "asc" });
  const treeRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const browserGenerationRef = useRef<string | null>(null);
  const cacheRef = useRef<ListingCache>({});
  const requestVersionRef = useRef(0);
  const activeRequestVersionsRef = useRef(new Map<string, number>());
  const inFlightRequestsRef = useRef(new Map<string, { version: number; promise: Promise<void> }>());

  const rootPath = source?.mount_point ?? null;
  const currentPath = activePath ?? rootPath;
  const normalizedFilterText = filterText.trim();
  const listSortKey = `${sort.key}:${sort.direction}`;
  const treeRoot = rootPath ? cache[cacheKey(rootPath, true)] : null;
  const currentListing = currentPath ? cache[cacheKey(currentPath, false, normalizedFilterText, listSortKey)] : null;
  const currentPathLabel = currentListing?.path ?? currentPath ?? source?.mount_point ?? "";
  const parentPath = currentListing?.parent_path ?? null;
  const generationKey = `${source?.id ?? "none"}::${source?.mount_point ?? "none"}::${refreshToken}`;

  useEffect(() => {
    cacheRef.current = cache;
  }, [cache]);

  async function ensureDirectory(
    path: string,
    options?: {
      directoriesOnly?: boolean;
      expand?: boolean;
      loadMore?: boolean;
      reset?: boolean;
    },
  ) {
    if (!source) {
      return;
    }

    const directoriesOnly = options?.directoriesOnly ?? false;
    const requestFilter = directoriesOnly ? "" : normalizedFilterText;
    const requestSortKey = directoriesOnly ? "" : listSortKey;
    const key = cacheKey(path, directoriesOnly, requestFilter, requestSortKey);
    const existing = cacheRef.current[key];
    const cursor = options?.loadMore ? existing?.next_cursor ?? null : null;
    const deletedCursor = options?.loadMore ? existing?.deleted_artifact_next_cursor ?? null : null;

    if (existing && !options?.loadMore && !options?.reset) {
      const resolvedPath = existing.path;
      if (options?.expand) {
        setExpandedPaths((current) => new Set(current).add(resolvedPath));
      }
      return;
    }

    if (!options?.loadMore && !options?.reset) {
      const inFlight = inFlightRequestsRef.current.get(key)?.promise;
      if (inFlight) {
        if (options?.expand) {
          setExpandedPaths((current) => new Set(current).add(path));
        }
        await inFlight;
        return;
      }
    }

    const generationAtRequest = browserGenerationRef.current ?? generationKey;
    const requestVersion = requestVersionRef.current + 1;
    requestVersionRef.current = requestVersion;
    activeRequestVersionsRef.current.set(key, requestVersion);
    setLoadingKeys((current) => new Set(current).add(key));
    const requestPromise = (async () => {
      try {
        const listing = await loadDirectory({
          source_id: source.id,
          path,
          cursor,
          deleted_cursor: deletedCursor,
          limit: directoriesOnly ? TREE_PAGE_SIZE : LIST_PAGE_SIZE,
          directories_only: directoriesOnly,
          filter: requestFilter || null,
          sort_key: directoriesOnly ? null : sort.key,
          sort_direction: directoriesOnly ? null : sort.direction,
        });
        if (browserGenerationRef.current !== generationAtRequest) {
          return;
        }
        if (activeRequestVersionsRef.current.get(key) !== requestVersion) {
          return;
        }

        const resolvedPath = listing.path;
        const resolvedKey = cacheKey(resolvedPath, directoriesOnly, requestFilter, requestSortKey);

        startTransition(() => {
          setCache((current) => {
            const prior = current[resolvedKey] ?? current[key];
            const next = { ...current };
            if (resolvedKey !== key) {
              delete next[key];
            }
            next[resolvedKey] =
              options?.loadMore && prior
                ? mergeListings(prior, listing)
                : {
                    ...listing,
                    entries: [...listing.entries],
                  };
            return {
              ...next,
            };
          });

          if (options?.expand) {
            setExpandedPaths((current) => new Set(current).add(resolvedPath));
          }
          setError(null);
        });
      } catch (caughtError) {
        setError(caughtError instanceof Error ? caughtError.message : "Directory browser unavailable");
      } finally {
        if (activeRequestVersionsRef.current.get(key) === requestVersion) {
          activeRequestVersionsRef.current.delete(key);
        }
        if (inFlightRequestsRef.current.get(key)?.version === requestVersion) {
          inFlightRequestsRef.current.delete(key);
        }
        setLoadingKeys((current) => {
          const next = new Set(current);
          next.delete(key);
          return next;
        });
      }
    })();
    inFlightRequestsRef.current.set(key, { version: requestVersion, promise: requestPromise });
    await requestPromise;
  }

  useEffect(() => {
    if (!source?.mount_point) {
      browserGenerationRef.current = null;
      setCache({});
      setExpandedPaths(new Set());
      setError(null);
      return;
    }

    const mountPoint = source.mount_point;
    const generationChanged = browserGenerationRef.current !== generationKey;
    if (generationChanged) {
      browserGenerationRef.current = generationKey;
      startTransition(() => {
        setCache({});
        setExpandedPaths(new Set());
        setError(null);
      });
      cacheRef.current = {};
      activeRequestVersionsRef.current.clear();
      inFlightRequestsRef.current.clear();
      const nextPath = activePath ?? mountPoint;
      const initialLoads = [
        ensureDirectory(mountPoint, { directoriesOnly: true, expand: true, reset: true }),
        ensureDirectory(nextPath, { directoriesOnly: false, reset: true }),
      ];
      if (normalizeBrowserPath(nextPath) !== normalizeBrowserPath(mountPoint)) {
        initialLoads.push(ensureDirectory(nextPath, { directoriesOnly: true, reset: true }));
      }
      void Promise.all(initialLoads);
      return;
    }

    if (!currentPath) {
      return;
    }

    const currentLoads = [ensureDirectory(currentPath, { directoriesOnly: false })];
    if (normalizeBrowserPath(currentPath) !== normalizeBrowserPath(mountPoint)) {
      currentLoads.push(ensureDirectory(currentPath, { directoriesOnly: true }));
    }
    void Promise.all(currentLoads);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activePath, currentPath, generationKey, normalizedFilterText, source?.mount_point, sort.direction, sort.key]);

  const visibleRows = useMemo<BrowserListRow[]>(() => {
    const searchNeedle = filterText.trim().toLowerCase();
    const filterLiveEntry = (entry: SourceEntry) => {
      if (!searchNeedle) {
        return true;
      }
      const haystack = `${entry.name} ${entry.path} ${entry.extension ?? ""} ${entry.attributes.join(" ")}`.toLowerCase();
      return haystack.includes(searchNeedle);
    };
    const filterDeletedArtifact = (artifact: ArtifactSummary) => {
      if (!searchNeedle) {
        return true;
      }
      const haystack =
        `${artifact.name} ${artifact.original_path ?? ""} ${artifact.probable_path ?? ""} ${artifact.kind} ${artifact.created_at ?? ""} ${artifact.modified_at ?? ""} ${artifact.deleted_at ?? ""}`.toLowerCase();
      return haystack.includes(searchNeedle);
    };

    if (!currentListing) {
      return [];
    }

    const liveEntries = currentListing.entries.filter(filterLiveEntry);
    const deletedRows = currentListing.deleted_artifacts
      .filter(filterDeletedArtifact)
      .map((artifact) => ({
        kind: "deleted" as const,
        key: artifact.id,
        artifact,
      }));

    return [
      ...sortEntries(liveEntries, sort).map((entry) => ({
        kind: "entry" as const,
        key: `${entry.path}${isSyntheticDeletedFolderEntry(entry) ? "::deleted-folder" : "::live"}`,
        entry,
        synthetic: isSyntheticDeletedFolderEntry(entry),
      })),
      ...sortArtifactsForBrowser(
        deletedRows.map((row) => row.artifact),
        sort,
      ).map((artifact) => ({
        kind: "deleted" as const,
        key: artifact.id,
        artifact,
        })),
    ];
  }, [
    currentListing,
    filterText,
    sort,
  ]);

  const browserStatus = useMemo(
    () => buildBrowserStatus(currentListing, visibleRows.length, filterText.trim().length > 0, error),
    [currentListing, error, filterText, visibleRows.length],
  );

  const treeRows = useMemo(() => {
    if (!rootPath) {
      return [];
    }

    const rows: TreeRow[] = [
      {
        kind: "entry",
        depth: 0,
        path: rootPath,
        synthetic: false,
        active: currentPath === rootPath,
        expanded: expandedPaths.has(rootPath),
        loading: loadingKeys.has(cacheKey(rootPath, true)),
        isRoot: true,
        entry: null,
        deletedHits: treeRoot?.deleted_subtree_count ?? 0,
      },
    ];

    if (!expandedPaths.has(rootPath) || !treeRoot) {
      return rows;
    }

    appendTreeRows(rows, {
      activePath: currentPath,
      cache,
      expandedPaths,
      listing: treeRoot,
      loadingKeys,
      parentDepth: 0,
    });
    if (treeRoot.next_cursor) {
      rows.push({ kind: "load_more", depth: 1, path: rootPath });
    }
    return rows;
  }, [cache, currentPath, expandedPaths, loadingKeys, rootPath, treeRoot]);

  const treeVirtualizer = useVirtualizer({
    count: treeRows.length,
    getScrollElement: () => treeRef.current,
    estimateSize: () => TREE_ROW_HEIGHT,
    getItemKey: (index) =>
      `${normalizeBrowserPath(rootPath ?? source?.id ?? "source")}::${treeRows[index]?.kind ?? "row"}:${treeRows[index]?.path ?? index}`,
    overscan: 10,
  });

  const listVirtualizer = useVirtualizer({
    count: visibleRows.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => LIST_ROW_HEIGHT,
    getItemKey: (index) =>
      `${normalizeBrowserPath(currentListing?.path ?? currentPath ?? rootPath ?? source?.id ?? "source")}::${visibleRows[index]?.key ?? index}`,
    overscan: 14,
  });

  const treeVirtualItems = treeVirtualizer.getVirtualItems();
  const listVirtualItems = listVirtualizer.getVirtualItems();
  const lastListIndex = listVirtualItems.at(-1)?.index ?? -1;

  useEffect(() => {
    treeVirtualizer.measure();
  }, [treeRows, treeVirtualizer]);

  useEffect(() => {
    listVirtualizer.measure();
  }, [currentPath, listVirtualizer, visibleRows]);

  useEffect(() => {
    if (typeof listRef.current?.scrollTo === "function") {
      listRef.current.scrollTo({ top: 0, left: 0 });
    }
    listVirtualizer.scrollToOffset(0);
  }, [currentPath, listSortKey, listVirtualizer, normalizedFilterText, refreshToken]);

  useEffect(() => {
    if (typeof treeRef.current?.scrollTo === "function") {
      treeRef.current.scrollTo({ top: 0 });
    }
    treeVirtualizer.scrollToOffset(0);
  }, [source?.id, treeVirtualizer]);

  useEffect(() => {
    if (!currentPath || (!currentListing?.next_cursor && !currentListing?.deleted_artifact_next_cursor)) {
      return;
    }
    if (lastListIndex < visibleRows.length - 24) {
      return;
    }

    const key = cacheKey(currentPath, false, normalizedFilterText, listSortKey);
    if (loadingKeys.has(key)) {
      return;
    }

    void ensureDirectory(currentPath, { loadMore: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentListing?.deleted_artifact_next_cursor, currentListing?.next_cursor, currentPath, lastListIndex, listSortKey, normalizedFilterText, visibleRows.length]);

  if (!source) {
    return <EmptyBrowser message="No source available" />;
  }

  if (!source.mount_point) {
    return <EmptyBrowser message="Directory browsing is available only for mounted volumes" />;
  }

  return (
    <section
      className="grid min-h-0 min-w-0 bg-[#101114]"
      data-testid="browser-workbench"
      style={{ gridTemplateColumns: `${leftPaneWidth}px 6px minmax(0, 1fr)` }}
    >
      <aside className="flex min-h-0 min-w-0 flex-col border-r border-white/8 bg-[#131417]">
        <div className="border-b border-white/8 px-3 py-2.5">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Tree</div>
          <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-slate-500">
            <span className="truncate">{source.mount_point ?? source.display_name}</span>
            <span className="shrink-0">{source.filesystem.toUpperCase()}</span>
          </div>
        </div>

        <div className="min-h-0 flex-1 px-2 py-2">
          <div
            className="h-full min-h-0 overflow-y-auto overflow-x-hidden overscroll-contain rounded-md border border-white/6 bg-[#111318]"
            data-testid="source-tree"
            ref={treeRef}
          >
            <div className="relative" style={{ height: `${treeVirtualizer.getTotalSize()}px` }}>
              {treeRows.length > 0 ? (
                treeVirtualItems.map((virtualRow) => {
                  const row = treeRows[virtualRow.index];
                  return (
                    <div
                      className="absolute left-0 top-0 w-full"
                      key={`${row.kind}-${row.path}-${virtualRow.index}`}
                      style={{
                        height: `${virtualRow.size}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                    >
                      {row.kind === "entry" ? (
                        <TreeEntryRow
                          active={row.active}
                          deletedHits={row.deletedHits}
                          depth={row.depth}
                          entry={row.entry}
                          expanded={row.expanded}
                          isRoot={row.isRoot}
                          loading={row.loading}
                          path={row.path}
                          synthetic={row.synthetic}
                          onExpand={() => {
                            const nextExpanded = !row.expanded;
                            setExpandedPaths((current) => {
                              const next = new Set(current);
                              if (nextExpanded) {
                                next.add(row.path);
                              } else {
                                next.delete(row.path);
                              }
                              return next;
                            });
                            if (nextExpanded) {
                              void ensureDirectory(row.path, { directoriesOnly: true, expand: true });
                            }
                          }}
                          onOpen={() => {
                            onSelectEntry(null);
                            onSelectPath(row.path);
                            void Promise.all([
                              ensureDirectory(row.path, { directoriesOnly: true }),
                              ensureDirectory(row.path, { directoriesOnly: false }),
                            ]);
                          }}
                        />
                      ) : (
                        <TreeLoadMoreRow
                          depth={row.depth}
                          onClick={() => void ensureDirectory(row.path, { directoriesOnly: true, loadMore: true })}
                        />
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="px-3 py-3 text-sm text-slate-500">Loading tree…</div>
              )}
            </div>
          </div>
        </div>
      </aside>

      <div
        className="relative cursor-col-resize bg-white/[0.03] hover:bg-[#6b73ff]/30"
        onPointerDown={onResizePointerDown}
        role="separator"
      >
        <div className="pointer-events-none absolute left-1/2 top-1/2 h-10 w-1 -translate-x-1/2 -translate-y-1/2 rounded-full bg-white/10" />
      </div>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="flex items-start justify-between gap-3 border-b border-white/8 px-4 py-3">
          <div className="min-w-0">
            <div
              className="max-w-full truncate text-sm font-medium leading-5 text-white"
              title={currentPathLabel ?? undefined}
            >
              {currentPathLabel}
            </div>
            <div
              className="mt-1 truncate text-[11px] text-slate-500"
              data-testid="browser-status"
              title={browserStatus}
            >
              {browserStatus}
            </div>
          </div>

          {parentPath ? (
            <button
              className="inline-flex h-8 shrink-0 items-center gap-1 rounded border border-white/8 px-2 text-xs text-slate-300 hover:bg-white/[0.04]"
              onClick={() => {
                onSelectEntry(null);
                onSelectPath(parentPath);
                void Promise.all([
                  ensureDirectory(parentPath, { directoriesOnly: true }),
                  ensureDirectory(parentPath, { directoriesOnly: false }),
                ]);
              }}
              type="button"
            >
              <ArrowUp className="size-3.5" />
              Up
            </button>
          ) : null}
        </header>

        <div
          className="min-h-0 min-w-0 overflow-auto overscroll-contain"
          data-path={currentPath ?? ""}
          data-testid="browser-list"
          ref={listRef}
          style={{ contain: "layout paint" }}
        >
          <div
            className="sticky top-0 z-10 grid shrink-0 border-b border-white/8 bg-[#14161a] px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500"
            style={{ ...listColumns, minWidth: `${LIST_MIN_WIDTH}px` }}
          >
            <BrowserHeaderCell active={sort.key === "name"} direction={sort.direction} label="Name" onClick={() => setSort(toggleSort(sort, "name"))} />
            <BrowserHeaderCell active={sort.key === "type"} direction={sort.direction} label="Type" onClick={() => setSort(toggleSort(sort, "type"))} />
            <BrowserHeaderCell active={sort.key === "size"} direction={sort.direction} label="Size" onClick={() => setSort(toggleSort(sort, "size"))} />
            <BrowserHeaderCell active={sort.key === "created_at"} direction={sort.direction} label="Created" onClick={() => setSort(toggleSort(sort, "created_at"))} />
            <BrowserHeaderCell active={sort.key === "modified_at"} direction={sort.direction} label="Modified" onClick={() => setSort(toggleSort(sort, "modified_at"))} />
            <BrowserHeaderCell active={sort.key === "accessed_at"} direction={sort.direction} label="Accessed" onClick={() => setSort(toggleSort(sort, "accessed_at"))} />
            <BrowserHeaderCell active={sort.key === "deleted_hits"} direction={sort.direction} label="Deleted" onClick={() => setSort(toggleSort(sort, "deleted_hits"))} />
            <div>Attr</div>
          </div>

          <div
            className="relative"
            style={{
              height: `${Math.max(listVirtualizer.getTotalSize(), 1)}px`,
              minWidth: `${LIST_MIN_WIDTH}px`,
              contain: "layout paint",
            }}
          >
            {visibleRows.length > 0 ? (
              listVirtualItems.map((virtualRow) => {
                const row = visibleRows[virtualRow.index];
                return row.kind === "entry" ? (
                    <BrowserEntryRow
                      entry={row.entry}
                      index={virtualRow.index}
                      isSelected={row.entry.path === selectedEntryPath}
                      key={row.key}
                        onOpenPath={(path) => {
                          onSelectEntry(null);
                          onSelectPath(path);
                          void Promise.all([
                            ensureDirectory(path, { directoriesOnly: true, expand: true }),
                            ensureDirectory(path, { directoriesOnly: false }),
                          ]);
                        }}
                        onSelect={() => onSelectEntry(row.entry)}
                      synthetic={row.synthetic}
                      style={{
                        ...listColumns,
                        height: `${LIST_ROW_HEIGHT}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                  />
                ) : (
                  <BrowserDeletedRow
                    artifact={row.artifact}
                    index={virtualRow.index}
                    isSelected={row.artifact.id === selectedArtifactId}
                    key={row.key}
                    onInspect={() => onInspectArtifact(row.artifact)}
                    style={{
                      ...listColumns,
                      height: `${LIST_ROW_HEIGHT}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                  />
                );
              })
            ) : (
              <div className="px-4 py-6 text-sm text-slate-500">
                {emptyBrowserMessage(currentListing, filterText)}
              </div>
            )}
          </div>

          {currentListing?.next_cursor || currentListing?.deleted_artifact_next_cursor ? (
            <div className="border-t border-white/6 px-3 py-2">
              <button
                className="rounded border border-white/8 px-2 py-1 text-xs text-slate-300 hover:bg-white/[0.04]"
                data-testid="browser-list-load-more"
                onClick={() => void ensureDirectory(currentPath ?? source.mount_point!, { loadMore: true })}
                type="button"
              >
                Load more
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

function appendTreeRows(
  rows: TreeRow[],
  context: {
    activePath: string | null;
    cache: ListingCache;
    expandedPaths: Set<string>;
    listing: SourceDirectoryListing;
    loadingKeys: Set<string>;
    parentDepth: number;
  },
) {
  const directories = context.listing.entries
    .filter((candidate) => candidate.is_directory)
    .sort((left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: "base" }));

  for (const entry of directories) {
    const childListing = context.cache[cacheKey(entry.path, true)];
    const expanded = context.expandedPaths.has(entry.path);
    rows.push({
      kind: "entry",
      depth: context.parentDepth + 1,
      path: entry.path,
      synthetic: isSyntheticDeletedFolderEntry(entry),
      active: context.activePath === entry.path,
      expanded,
      loading: context.loadingKeys.has(cacheKey(entry.path, true)),
      isRoot: false,
      entry,
      deletedHits: entry.deleted_hits,
    });

    if (!expanded) {
      continue;
    }

    if (childListing) {
      appendTreeRows(rows, {
        ...context,
        listing: childListing,
        parentDepth: context.parentDepth + 1,
      });
      if (childListing.next_cursor) {
        rows.push({ kind: "load_more", depth: context.parentDepth + 2, path: entry.path });
      }
    }
  }
}

function TreeEntryRow({
  active,
  deletedHits,
  depth,
  entry,
  expanded,
  isRoot,
  loading,
  path,
  synthetic,
  onExpand,
  onOpen,
}: {
  active: boolean;
  deletedHits: number;
  depth: number;
  entry: SourceEntry | null;
  expanded: boolean;
  isRoot: boolean;
  loading: boolean;
  path: string;
  synthetic: boolean;
  onExpand: () => void;
  onOpen: () => void;
}) {
  const canExpand = isRoot || entry?.has_children !== false || loading;
  const canOpen = isRoot || (entry != null && isNavigableDirectory(entry));
  const label = isRoot ? path : entry?.name ?? path;
  const icon = isRoot
    ? <FolderOpen className="size-4 shrink-0 text-slate-400" />
    : entry?.is_metafile
      ? <Shield className="size-4 shrink-0 text-slate-400" />
      : expanded
        ? <FolderOpen className="size-4 shrink-0 text-slate-400" />
        : <Folder className="size-4 shrink-0 text-slate-400" />;

  return (
    <div
      className={cn(
        "flex h-full items-center gap-1 px-2 text-sm",
        active ? "bg-[#1d2026] text-white" : "text-slate-300 hover:bg-white/[0.04]",
      )}
      data-path={path}
      data-testid="tree-entry-row"
      style={{ paddingLeft: `${depth * 14 + 8}px` }}
    >
      {canExpand ? (
        <button
          className="flex size-5 items-center justify-center rounded text-slate-500 hover:bg-white/[0.05]"
          data-path={path}
          data-testid="tree-expand"
          onClick={onExpand}
          type="button"
        >
          <ChevronRight className={cn("size-3 transition-transform", expanded ? "rotate-90" : "")} />
        </button>
      ) : (
        <span className="block w-5" />
      )}
      <button
        className={cn(
          "flex min-w-0 flex-1 items-center gap-2 text-left",
          !canOpen && "cursor-default opacity-70",
        )}
        data-path={path}
        data-testid="tree-open"
        disabled={!canOpen}
        onClick={onOpen}
        type="button"
      >
        {icon}
        <span className="min-w-0 truncate" title={label}>
          {label}
        </span>
        {synthetic ? (
          <span className="shrink-0 rounded border border-rose-400/30 px-1 py-0.5 text-[10px] uppercase tracking-[0.16em] text-rose-200">
            Deleted
          </span>
        ) : null}
        {deletedHits > 0 ? (
          <span className="ml-auto shrink-0 text-[10px] font-medium text-rose-300">{deletedHits}</span>
        ) : null}
      </button>
      {loading ? <span className="text-[10px] text-slate-600">…</span> : null}
    </div>
  );
}

function TreeLoadMoreRow({ depth, onClick }: { depth: number; onClick: () => void }) {
  return (
    <div className="flex h-full items-center px-2" style={{ paddingLeft: `${depth * 14 + 8}px` }}>
      <button
        className="rounded border border-white/8 px-2 py-1 text-[11px] text-slate-400 hover:bg-white/[0.04]"
        data-testid="tree-load-more"
        onClick={onClick}
        type="button"
      >
        Load more
      </button>
    </div>
  );
}

function BrowserHeaderCell({
  active,
  direction,
  label,
  onClick,
}: {
  active: boolean;
  direction: "asc" | "desc";
  label: string;
  onClick: () => void;
}) {
  return (
    <button className="inline-flex items-center gap-1 text-left text-inherit" onClick={onClick} type="button">
      <span>{label}</span>
      {active ? <ChevronRight className={cn("size-3 rotate-90", direction === "desc" ? "rotate-[270deg]" : "")} /> : null}
    </button>
  );
}

function BrowserEntryRow({
  entry,
  index,
  isSelected,
  onOpenPath,
  onSelect,
  synthetic,
  style,
}: {
  entry: SourceEntry;
  index: number;
  isSelected: boolean;
  onOpenPath: (path: string) => void;
  onSelect: () => void;
  synthetic: boolean;
  style: CSSProperties;
}) {
  const canOpenDirectory = isNavigableDirectory(entry);

  return (
    <div
      className={cn(
        "absolute left-0 top-0 grid w-full items-center overflow-hidden border-b border-white/6 px-3 text-sm text-slate-300",
        isSelected ? "bg-[#1d2026]" : "hover:bg-white/[0.03]",
      )}
      data-index={index}
      data-entry-name={entry.name}
      data-path={entry.path}
      data-testid="browser-list-row"
      onClick={onSelect}
      onDoubleClick={() => {
        if (canOpenDirectory) {
          onOpenPath(entry.path);
        }
      }}
      style={{ ...style, contain: "layout paint", willChange: "transform" }}
    >
      <div className="flex min-w-0 items-center gap-2 overflow-hidden py-2">
        <span className="shrink-0 text-slate-400">{entryIcon(entry)}</span>
        <div className="flex min-w-0 items-center gap-2 overflow-hidden">
          <div className="truncate font-medium text-slate-100">{entry.name}</div>
          {entry.is_metafile ? (
            <span className="shrink-0 rounded border border-[#7f88ff]/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-[#9da4ff]">
              Meta
            </span>
          ) : null}
          {entry.access_state === "denied" ? (
            <span className="shrink-0 rounded border border-amber-400/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-amber-200">
              Denied
            </span>
          ) : null}
          {isUnknownBucketPath(entry.path) ? (
            <span className="shrink-0 rounded border border-amber-400/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-amber-200">
              Deleted
            </span>
          ) : synthetic ? (
            <span className="shrink-0 rounded border border-rose-400/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-rose-200">
              Deleted folder
            </span>
          ) : null}
        </div>
      </div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-400">{entryType(entry)}</div>
      <div className="min-w-0 whitespace-nowrap py-2 font-mono text-xs text-slate-300">{entry.is_directory ? "" : formatBytes(entry.size)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-400">{formatDate(entry.created_at)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-400">{formatDate(entry.modified_at)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-400">{formatDate(entry.accessed_at)}</div>
      <div className="min-w-0 whitespace-nowrap py-2 font-mono text-xs text-slate-300">
        {entry.is_directory || isUnknownBucketPath(entry.path) ? (entry.deleted_hits > 0 ? entry.deleted_hits : "") : ""}
      </div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 font-mono text-xs text-slate-300" title={attrTooltip(entry)}>
        {formatAttrBits(entry)}
      </div>
    </div>
  );
}

function BrowserDeletedRow({
  artifact,
  index,
  isSelected,
  onInspect,
  style,
}: {
  artifact: ArtifactSummary;
  index: number;
  isSelected: boolean;
  onInspect: () => void;
  style: CSSProperties;
}) {
  const artifactPath = artifact.original_path ?? artifact.probable_path ?? "";
  return (
    <div
      className={cn(
        "absolute left-0 top-0 grid w-full items-center overflow-hidden border-b border-rose-500/10 px-3 text-sm text-slate-200",
        isSelected ? "bg-[#24161a]" : "bg-[#151114] hover:bg-[#1c1418]",
      )}
      data-artifact-id={artifact.id}
      data-index={index}
      data-testid="browser-deleted-row"
      onClick={onInspect}
      style={{ ...style, contain: "layout paint", willChange: "transform" }}
    >
      <div className="flex min-w-0 items-center gap-2 overflow-hidden py-2">
        <span className="shrink-0 text-rose-300">{deletedArtifactIcon(artifact)}</span>
        <div className="flex min-w-0 flex-col overflow-hidden">
          <div className="flex min-w-0 items-center gap-2 overflow-hidden">
          <div className="truncate font-medium text-rose-50" title={artifact.name}>
            {artifact.name}
          </div>
          <span className="shrink-0 rounded border border-rose-400/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-rose-200">
            Deleted
          </span>
          {artifact.probable_path && !artifact.original_path ? (
            <span className="shrink-0 rounded border border-amber-400/30 px-1.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-amber-200">
              Probable
            </span>
          ) : null}
          </div>
          {artifactPath ? (
            <div className="truncate font-mono text-[11px] text-slate-500" title={artifactPath}>
              {artifactPath}
            </div>
          ) : null}
        </div>
      </div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-300">{artifact.kind}</div>
      <div className="min-w-0 whitespace-nowrap py-2 font-mono text-xs text-rose-100">{formatBytes(artifact.size)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-300">{formatDate(artifact.created_at)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-300">{formatDate(artifact.modified_at)}</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 text-slate-500">-</div>
      <div className="min-w-0 whitespace-nowrap py-2 font-mono text-xs text-rose-200">Deleted</div>
      <div className="min-w-0 truncate whitespace-nowrap py-2 font-mono text-xs text-slate-500">-</div>
    </div>
  );
}

function isSyntheticDeletedFolderEntry(entry: SourceEntry) {
  return entry.is_directory && entry.access_state === "unknown" && entry.attributes.includes("Deleted folder");
}

function isNavigableDirectory(entry: SourceEntry) {
  return entry.is_directory && entry.access_state !== "denied" && !entry.attributes.includes("reparse_point");
}

function sortArtifactsForBrowser(artifacts: ArtifactSummary[], sort: DirectorySortState) {
  const direction = sort.direction === "asc" ? 1 : -1;
  return [...artifacts].sort((left, right) => {
    const leftValue = sortArtifactValue(left, sort.key);
    const rightValue = sortArtifactValue(right, sort.key);
    if (leftValue < rightValue) {
      return -1 * direction;
    }
    if (leftValue > rightValue) {
      return 1 * direction;
    }
    return left.name.localeCompare(right.name);
  });
}

function sortArtifactValue(artifact: ArtifactSummary, key: DirectorySortKey) {
  switch (key) {
    case "type":
      return artifact.kind.toLowerCase();
    case "size":
      return artifact.size;
    case "created_at":
      return artifact.created_at ?? "";
    case "modified_at":
      return artifact.modified_at ?? "";
    case "accessed_at":
      return "";
    case "deleted_hits":
      return 1;
    case "name":
    default:
      return artifact.name.toLowerCase();
  }
}

function sortEntries(entries: SourceEntry[], sort: DirectorySortState) {
  const direction = sort.direction === "asc" ? 1 : -1;
  return [...entries].sort((left, right) => {
    if (left.is_directory !== right.is_directory) {
      return left.is_directory ? -1 : 1;
    }

    const leftValue = sortValue(left, sort.key);
    const rightValue = sortValue(right, sort.key);
    if (leftValue < rightValue) {
      return -1 * direction;
    }
    if (leftValue > rightValue) {
      return 1 * direction;
    }
    return left.name.localeCompare(right.name);
  });
}

function sortValue(entry: SourceEntry, key: DirectorySortKey) {
  switch (key) {
    case "type":
      return entryType(entry).toLowerCase();
    case "size":
      return entry.size;
    case "created_at":
      return entry.created_at ?? "";
    case "modified_at":
      return entry.modified_at ?? "";
    case "accessed_at":
      return entry.accessed_at ?? "";
    case "deleted_hits":
      return entry.deleted_hits;
    case "name":
    default:
      return entry.name.toLowerCase();
  }
}

function toggleSort(current: DirectorySortState, key: DirectorySortKey): DirectorySortState {
  if (current.key !== key) {
    return { key, direction: "asc" };
  }

  return { key, direction: current.direction === "asc" ? "desc" : "asc" };
}

function mergeListings(existing: SourceDirectoryListing, incoming: SourceDirectoryListing): SourceDirectoryListing {
  const seen = new Set(existing.entries.map((entry) => normalizeBrowserPath(entry.path)));
  const appended = incoming.entries.filter((entry) => !seen.has(normalizeBrowserPath(entry.path)));
  const deletedSeen = new Set(existing.deleted_artifacts.map((artifact) => artifact.id));
  const deletedAppended = incoming.deleted_artifacts.filter((artifact) => !deletedSeen.has(artifact.id));
  return {
    ...incoming,
    entries: [...existing.entries, ...appended],
    deleted_artifacts: [...existing.deleted_artifacts, ...deletedAppended],
  };
}

function formatIndexProgress(listing: SourceDirectoryListing) {
  if (listing.total_estimated_entries && listing.total_estimated_entries > 0) {
    const percent = Math.min(100, Math.round((listing.indexed_entries / listing.total_estimated_entries) * 100));
    return `${percent}% (${listing.indexed_entries}/${listing.total_estimated_entries})`;
  }

  return `${listing.indexed_entries} entries`;
}

function buildBrowserStatus(
  listing: SourceDirectoryListing | null,
  visibleCount: number,
  filterActive: boolean,
  error: string | null,
) {
  if (!listing) {
    return error ? `Loading... • ${error}` : "Loading...";
  }

  if (!listing.indexing_complete) {
    const indexingStatus = `${visibleCount} visible • indexing ${formatIndexProgress(listing)}`;
    return error ? `${indexingStatus} • ${error}` : indexingStatus;
  }

  const syntheticDeletedFolders = listing.entries.filter(isSyntheticDeletedFolderEntry).length;
  const liveLoaded = listing.entries.length - syntheticDeletedFolders;
  const deletedLoaded = listing.deleted_artifacts.length;
  const nestedDeleted = Math.max(0, listing.deleted_subtree_count - listing.deleted_artifact_count);
  const deletedSegments = [
    syntheticDeletedFolders > 0 ? `${syntheticDeletedFolders} deleted folders` : null,
    listing.deleted_artifact_count > 0 ? `${deletedLoaded}/${listing.deleted_artifact_count} deleted` : null,
    !filterActive && nestedDeleted > 0 ? `${nestedDeleted} nested deleted` : null,
  ].filter((segment): segment is string => Boolean(segment));
  const deletedSegment = deletedSegments.length > 0 ? ` • ${deletedSegments.join(" • ")}` : "";
  const loadedStatus = `${liveLoaded}/${listing.total_entry_count} live${deletedSegment}`;
  const filteredStatus = filterActive ? `${visibleCount} matching • ${loadedStatus}` : loadedStatus;
  return error ? `${filteredStatus} • ${error}` : filteredStatus;
}

function emptyBrowserMessage(listing: SourceDirectoryListing | null, filterText: string) {
  if (filterText.trim()) {
    return "No items match the current filter";
  }
  if (listing && listing.deleted_subtree_count > listing.deleted_artifact_count) {
    return "Deleted files are in nested folders";
  }
  return "Folder is empty";
}

function cacheKey(path: string, directoriesOnly: boolean, filterText = "", sortKey = "") {
  const filterKey = directoriesOnly ? "" : filterText.trim().toLowerCase();
  const sortPart = directoriesOnly ? "" : sortKey;
  return `${normalizeBrowserPath(path)}::${directoriesOnly ? "dirs" : "all"}::${filterKey}::${sortPart}`;
}

function entryType(entry: SourceEntry) {
  if (entry.is_directory) {
    return entry.is_metafile ? "Metadata folder" : "Folder";
  }
  if (entry.is_metafile && !entry.extension) {
    return "Metadata";
  }
  if (entry.extension) {
    return entry.extension.toUpperCase();
  }
  return "File";
}

function entryIcon(entry: SourceEntry) {
  const extension = entry.extension?.toLowerCase();

  if (entry.access_state === "denied") {
    return <Lock className="size-4" />;
  }
  if (entry.is_metafile) {
    return <Shield className="size-4" />;
  }
  if (entry.system) {
    return <Shield className="size-4" />;
  }
  if (entry.hidden) {
    return <EyeOff className="size-4" />;
  }
  if (entry.is_directory) {
    return <Folder className="size-4" />;
  }
  if (extension && ["zip", "rar", "7z", "cab", "iso", "tar", "gz", "bz2", "xz"].includes(extension)) {
    return <FileArchive className="size-4" />;
  }
  if (extension && ["exe", "dll", "sys", "msi", "jar", "ps1", "cmd", "bat"].includes(extension)) {
    return <FileCode2 className="size-4" />;
  }
  if (extension && ["sqlite", "sqlite3", "db", "db3", "edb"].includes(extension)) {
    return <Database className="size-4" />;
  }
  if (extension && ["pdf", "txt", "log", "json", "ini", "cfg", "yml", "yaml", "xml", "md"].includes(extension)) {
    return <FileText className="size-4" />;
  }
  if (extension && ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico"].includes(extension)) {
    return <FileImage className="size-4" />;
  }
  return <File className="size-4" />;
}

function deletedArtifactIcon(artifact: ArtifactSummary) {
  if (artifact.family === "archive") {
    return <FileArchive className="size-4" />;
  }
  if (artifact.family === "executable" || artifact.kind === "exe" || artifact.kind === "dll" || artifact.kind === "sys") {
    return <FileCode2 className="size-4" />;
  }
  if (artifact.family === "database") {
    return <Database className="size-4" />;
  }
  if (artifact.family === "document" || artifact.family === "text" || artifact.family === "config") {
    return <FileText className="size-4" />;
  }
  if (artifact.family === "image") {
    return <FileImage className="size-4" />;
  }
  return <File className="size-4" />;
}

function EmptyBrowser({ message }: { message: string }) {
  return (
    <section className="flex h-full items-center justify-center rounded-md border border-white/8 bg-[#101114] text-sm text-slate-500">
      {message}
    </section>
  );
}

const listColumns = {
  gridTemplateColumns:
    "minmax(280px,2.3fr) minmax(86px,0.8fr) minmax(84px,0.7fr) minmax(140px,1fr) minmax(140px,1fr) minmax(140px,1fr) minmax(70px,0.5fr) minmax(160px,1.1fr)",
} as const;

const FILE_ATTRIBUTE_READONLY = 0x0001;
const FILE_ATTRIBUTE_HIDDEN = 0x0002;
const FILE_ATTRIBUTE_SYSTEM = 0x0004;
const FILE_ATTRIBUTE_ARCHIVE = 0x0020;
const FILE_ATTRIBUTE_TEMPORARY = 0x0100;
const FILE_ATTRIBUTE_SPARSE = 0x0200;
const FILE_ATTRIBUTE_REPARSE = 0x0400;
const FILE_ATTRIBUTE_COMPRESSED = 0x0800;
const FILE_ATTRIBUTE_OFFLINE = 0x1000;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000;
const FILE_ATTRIBUTE_ENCRYPTED = 0x4000;

function formatAttrBits(entry: SourceEntry) {
  if (entry.attr_bits == null) {
    return entry.access_state === "denied" ? "DENIED" : "-";
  }

  const bits = entry.attr_bits;
  const codes = [
    bits & FILE_ATTRIBUTE_READONLY ? "R" : "",
    bits & FILE_ATTRIBUTE_HIDDEN ? "H" : "",
    bits & FILE_ATTRIBUTE_SYSTEM ? "S" : "",
    bits & FILE_ATTRIBUTE_REPARSE ? "P" : "",
    bits & FILE_ATTRIBUTE_SPARSE ? "SP" : "",
    bits & FILE_ATTRIBUTE_COMPRESSED ? "C" : "",
    bits & FILE_ATTRIBUTE_ENCRYPTED ? "E" : "",
    bits & FILE_ATTRIBUTE_OFFLINE ? "O" : "",
    bits & FILE_ATTRIBUTE_TEMPORARY ? "T" : "",
    bits & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED ? "I" : "",
    bits & FILE_ATTRIBUTE_ARCHIVE && bits !== FILE_ATTRIBUTE_ARCHIVE ? "A" : "",
  ].filter(Boolean);

  return codes.length > 0 ? codes.join(" ") : "-";
}

function attrTooltip(entry: SourceEntry) {
  const labels = entry.attributes.length > 0 ? entry.attributes.join(", ") : "No special attributes";
  const bits = entry.attr_bits != null ? `0x${entry.attr_bits.toString(16).padStart(4, "0")}` : "n/a";
  return `${bits} • ${labels}`;
}
