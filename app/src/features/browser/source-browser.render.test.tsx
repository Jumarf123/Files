import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({
    count,
    estimateSize,
    getItemKey,
  }: {
    count: number;
    estimateSize: () => number;
    getItemKey?: (index: number) => string | number;
  }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: getItemKey ? getItemKey(index) : index,
        size: estimateSize(),
        start: index * estimateSize(),
      })),
    measure: () => {},
    scrollToOffset: () => {},
  }),
}));

import { SourceBrowser } from "./source-browser";
import type { ArtifactSummary, BrowseSourceRequest, ScanSource, SourceDirectoryListing, SourceEntry } from "@/shared/types/api";

const source: ScanSource = {
  id: "vol-c",
  kind: "logical_volume",
  device_path: "\\\\.\\C:",
  mount_point: "C:\\",
  display_name: "System C:",
  volume_label: "Windows",
  filesystem: "ntfs",
  volume_serial: 1,
  total_bytes: 1024,
  free_bytes: 512,
  cluster_size: 4096,
  is_system: true,
  requires_elevation: true,
};

function entry(path: string, options?: Partial<SourceEntry>): SourceEntry {
  const name = path.split("\\").at(-1) ?? path;
  const isDirectory = options?.is_directory ?? true;
  return {
    name,
    path,
    parent_path: path.includes("\\") ? path.slice(0, path.lastIndexOf("\\")) || "C:\\" : "C:\\",
    mft_reference: null,
    parent_reference: null,
    extension: isDirectory ? null : name.split(".").at(-1) ?? null,
    is_directory: isDirectory,
    has_children: isDirectory,
    is_metafile: false,
    entry_class: isDirectory ? "directory" : "file",
    size: options?.size ?? 0,
    created_at: null,
    modified_at: null,
    accessed_at: null,
    hidden: false,
    system: false,
    read_only: false,
    attr_bits: 0x0020,
    attributes: [],
    deleted_hits: 0,
    access_state: "readable",
    ...options,
  };
}

function listing(
  path: string,
  entries: SourceEntry[],
  parentPath: string | null,
  options?: Partial<SourceDirectoryListing>,
): SourceDirectoryListing {
  return {
    source_id: source.id,
    root_path: "C:\\",
    path,
    parent_path: parentPath,
    entries,
    deleted_artifacts: [],
    total_entry_count: entries.length,
    deleted_artifact_count: 0,
    next_cursor: null,
    deleted_artifact_next_cursor: null,
    indexing_complete: true,
    indexed_entries: entries.length,
    total_estimated_entries: entries.length,
    index_generation: 1,
    deleted_subtree_count: 0,
    ...options,
  };
}

function deletedArtifact(id: string, originalPath: string): ArtifactSummary {
  const name = originalPath.split("\\").at(-1) ?? originalPath;
  return {
    id,
    scan_id: "scan-1",
    source_id: source.id,
    name,
    original_path: originalPath,
    probable_path: null,
    placement_kind: "original_path",
    path_confidence: "exact",
    path_evidence: [],
    name_source: "long_name",
    content_source: "raw_runs",
    artifact_class: "named_metadata_candidate",
    preview_ready: false,
    is_fragment: false,
    fragment_id: null,
    extension: name.split(".").at(-1) ?? null,
    family: "binary",
    kind: "bin",
    origin_type: "filesystem_deleted_entry",
    confidence: "medium",
    recoverability: "partial",
    deleted_entry: true,
    size: 1024,
    priority_score: 20,
    filesystem_record: null,
    raw_offset: null,
    raw_length: null,
    created_at: null,
    modified_at: null,
    deleted_at: null,
    deleted_time_source: null,
    deleted_time_confidence: "unknown",
    last_metadata_change_at: null,
  };
}

describe("SourceBrowser rendering stability", () => {
  it("does not clear the whole browser cache when only the active path changes", async () => {
    const requests: BrowseSourceRequest[] = [];
    const listings = new Map<string, SourceDirectoryListing>([
      ["C:\\::dirs", listing("C:\\", [entry("C:\\Users"), entry("C:\\Windows")], null)],
      ["C:\\::all", listing("C:\\", [entry("C:\\Users"), entry("C:\\Windows")], null)],
      [
        "C:\\Users::dirs",
        listing("C:\\Users", [entry("C:\\Users\\Downloads"), entry("C:\\Users\\Desktop")], "C:\\"),
      ],
      [
        "C:\\Users::all",
        listing("C:\\Users", [entry("C:\\Users\\Downloads"), entry("C:\\Users\\Desktop")], "C:\\"),
      ],
      [
        "C:\\Users\\Downloads::dirs",
        listing("C:\\Users\\Downloads", [], "C:\\Users"),
      ],
      [
        "C:\\Users\\Downloads::all",
        listing("C:\\Users\\Downloads", [entry("C:\\Users\\Downloads\\alpha.txt", { is_directory: false, size: 32 })], "C:\\Users"),
      ],
      [
        "C:\\Users\\Desktop::dirs",
        listing("C:\\Users\\Desktop", [], "C:\\Users"),
      ],
      [
        "C:\\Users\\Desktop::all",
        listing("C:\\Users\\Desktop", [entry("C:\\Users\\Desktop\\beta.txt", { is_directory: false, size: 64 })], "C:\\Users"),
      ],
    ]);

    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      requests.push(request);
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      return structuredClone(resolved);
    });

    function Harness() {
      const [activePath, setActivePath] = useState<string | null>("C:\\");
      return (
        <div>
          <button onClick={() => setActivePath("C:\\Users")} type="button">
            Switch Users
          </button>
          <button onClick={() => setActivePath("C:\\Users\\Downloads")} type="button">
            Switch Downloads
          </button>
          <button onClick={() => setActivePath("C:\\Users\\Desktop")} type="button">
            Switch Desktop
          </button>
          <SourceBrowser
            activePath={activePath}
            filterText=""
            leftPaneWidth={320}
            loadDirectory={loadDirectory}
            onInspectArtifact={() => {}}
            onResizePointerDown={() => {}}
            onSelectEntry={() => {}}
            onSelectPath={setActivePath}
            refreshToken={0}
            selectedArtifactId={null}
            selectedEntryPath={null}
            source={source}
          />
        </div>
      );
    }

    render(<Harness />);

    expect(await screen.findAllByText("Windows")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Switch Users" }));
    expect(await screen.findByText("Downloads")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Switch Downloads" }));
    expect(await screen.findByText("alpha.txt")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Switch Desktop" }));
    expect(await screen.findByText("beta.txt")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("alpha.txt")).not.toBeInTheDocument());

    expect(requests.filter((request) => (request.path ?? "C:\\") === "C:\\" && request.directories_only === true)).toHaveLength(1);
    expect(requests.filter((request) => (request.path ?? "C:\\") === "C:\\" && !request.directories_only)).toHaveLength(1);
  });

  it("ignores stale folder responses when navigation requests resolve out of order", async () => {
    const listings = new Map<string, SourceDirectoryListing>([
      ["C:\\::dirs", listing("C:\\", [entry("C:\\Users"), entry("C:\\Desktop")], null)],
      ["C:\\::all", listing("C:\\", [entry("C:\\Users"), entry("C:\\Desktop")], null)],
      ["C:\\Users::dirs", listing("C:\\Users", [], "C:\\")],
      [
        "C:\\Users::all",
        listing("C:\\Users", [entry("C:\\Users\\alpha.txt", { is_directory: false, size: 16 })], "C:\\"),
      ],
      ["C:\\Desktop::dirs", listing("C:\\Desktop", [], "C:\\")],
      [
        "C:\\Desktop::all",
        listing("C:\\Desktop", [entry("C:\\Desktop\\beta.txt", { is_directory: false, size: 32 })], "C:\\"),
      ],
    ]);

    const deferredLoads = new Map<string, Array<(value: SourceDirectoryListing) => void>>();
    const loadDirectory = vi.fn((request: BrowseSourceRequest) => {
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      if ((request.path ?? source.mount_point) === "C:\\") {
        return Promise.resolve(structuredClone(resolved));
      }
      return new Promise<SourceDirectoryListing>((resolve) => {
        const bucket = deferredLoads.get(key) ?? [];
        bucket.push(resolve);
        deferredLoads.set(key, bucket);
      });
    });

    function resolveDeferred(key: string) {
      const resolver = deferredLoads.get(key)?.shift();
      if (!resolver) {
        throw new Error(`No deferred request queued for ${key}`);
      }
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing listing for ${key}`);
      }
      resolver(structuredClone(resolved));
    }

    function Harness() {
      const [activePath, setActivePath] = useState<string | null>("C:\\");
      const [selectedEntryPath, setSelectedEntryPath] = useState<string | null>(null);
      return (
        <SourceBrowser
          activePath={activePath}
          filterText=""
          leftPaneWidth={320}
          loadDirectory={loadDirectory}
          onInspectArtifact={() => {}}
          onResizePointerDown={() => {}}
          onSelectEntry={(selected) => setSelectedEntryPath(selected?.path ?? null)}
          onSelectPath={setActivePath}
          refreshToken={0}
          selectedArtifactId={null}
          selectedEntryPath={selectedEntryPath}
          source={source}
        />
      );
    }

    render(<Harness />);

    expect(await screen.findAllByText("Users")).toHaveLength(2);

    const treeRows = () => screen.getAllByTestId("tree-entry-row");
    fireEvent.click(treeRows().find((candidate) => candidate.textContent?.includes("Users"))!.querySelector("[data-testid='tree-open']")!);
    fireEvent.click(treeRows().find((candidate) => candidate.textContent?.includes("Desktop"))!.querySelector("[data-testid='tree-open']")!);

    await act(async () => {
      resolveDeferred("C:\\Desktop::dirs");
      resolveDeferred("C:\\Desktop::all");
      await Promise.resolve();
    });

    expect(await screen.findByText("beta.txt")).toBeInTheDocument();

    await act(async () => {
      resolveDeferred("C:\\Users::dirs");
      resolveDeferred("C:\\Users::all");
      await Promise.resolve();
    });

    expect(screen.getByText("C:\\Desktop")).toBeInTheDocument();
    expect(screen.getByText("beta.txt")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("alpha.txt")).not.toBeInTheDocument());
  });

  it("keeps recursive deleted tree counts separate from direct deleted pages", async () => {
    const listings = new Map<string, SourceDirectoryListing>([
      [
        "C:\\::dirs",
        listing(
          "C:\\",
          [entry("C:\\ProgramData", { deleted_hits: 50_000, has_children: true })],
          null,
          { deleted_subtree_count: 50_000 },
        ),
      ],
      [
        "C:\\::all",
        listing(
          "C:\\",
          [entry("C:\\ProgramData", { deleted_hits: 50_000, has_children: true })],
          null,
          { deleted_subtree_count: 50_000 },
        ),
      ],
      [
        "C:\\ProgramData::dirs",
        listing(
          "C:\\ProgramData",
          [entry("C:\\ProgramData\\Vendor", { deleted_hits: 50_000, has_children: true })],
          "C:\\",
          {
            deleted_artifact_count: 2,
            deleted_artifacts: [
              deletedArtifact("direct-a", "C:\\ProgramData\\direct-a.bin"),
              deletedArtifact("direct-b", "C:\\ProgramData\\direct-b.bin"),
            ],
            deleted_subtree_count: 50_000,
          },
        ),
      ],
      [
        "C:\\ProgramData::all",
        listing(
          "C:\\ProgramData",
          [entry("C:\\ProgramData\\Vendor", { deleted_hits: 50_000, has_children: true })],
          "C:\\",
          {
            deleted_artifact_count: 2,
            deleted_artifacts: [
              deletedArtifact("direct-a", "C:\\ProgramData\\direct-a.bin"),
              deletedArtifact("direct-b", "C:\\ProgramData\\direct-b.bin"),
            ],
            deleted_subtree_count: 50_000,
          },
        ),
      ],
    ]);
    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      return structuredClone(resolved);
    });

    function Harness() {
      const [activePath, setActivePath] = useState<string | null>("C:\\");
      return (
        <SourceBrowser
          activePath={activePath}
          filterText=""
          leftPaneWidth={320}
          loadDirectory={loadDirectory}
          onInspectArtifact={() => {}}
          onResizePointerDown={() => {}}
          onSelectEntry={() => {}}
          onSelectPath={setActivePath}
          refreshToken={0}
          selectedArtifactId={null}
          selectedEntryPath={null}
          source={source}
        />
      );
    }

    render(<Harness />);

    await waitFor(() => expect(screen.getAllByText("50000").length).toBeGreaterThan(0));
    const programDataTreeRow = screen
      .getAllByTestId("tree-entry-row")
      .find((candidate) => candidate.textContent?.includes("ProgramData"));
    expect(programDataTreeRow?.textContent).toContain("50000");

    fireEvent.click(programDataTreeRow!.querySelector("[data-testid='tree-open']")!);

    expect(await screen.findByText("C:\\ProgramData")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("browser-status").textContent).toContain("2/2 deleted"));
    expect(await screen.findByText("direct-a.bin")).toBeInTheDocument();
    expect(screen.getAllByText("50000").length).toBeGreaterThan(0);
  });

  it("does not render probable-path descendants as deleted files in ancestor folders", async () => {
    const probablePath = "C:\\Users\\jumarf\\AppData\\Local\\Temp\\_MEI96042\\rules\\.git";
    const leafPath = "C:\\Users\\jumarf\\AppData\\Local\\Temp\\_MEI96042\\rules";
    const probableArtifact: ArtifactSummary = {
      ...deletedArtifact("probable-git", probablePath),
      original_path: null,
      probable_path: probablePath,
      placement_kind: "broken_parent_chain",
      path_confidence: "partial",
    };
    const listings = new Map<string, SourceDirectoryListing>([
      [
        "C:\\::dirs",
        listing("C:\\", [entry("C:\\Users", { deleted_hits: 1, has_children: true })], null, {
          deleted_subtree_count: 1,
        }),
      ],
      [
        "C:\\::all",
        listing("C:\\", [entry("C:\\Users", { deleted_hits: 1, has_children: true })], null, {
          deleted_subtree_count: 1,
        }),
      ],
      [
        "C:\\Users::dirs",
        listing("C:\\Users", [entry("C:\\Users\\jumarf", { deleted_hits: 1, has_children: true })], "C:\\", {
          deleted_subtree_count: 1,
        }),
      ],
      [
        "C:\\Users::all",
        listing("C:\\Users", [entry("C:\\Users\\jumarf", { deleted_hits: 1, has_children: true })], "C:\\", {
          deleted_subtree_count: 1,
        }),
      ],
      [`${leafPath}::dirs`, listing(leafPath, [], "C:\\Users\\jumarf\\AppData\\Local\\Temp\\_MEI96042")],
      [
        `${leafPath}::all`,
        listing(leafPath, [], "C:\\Users\\jumarf\\AppData\\Local\\Temp\\_MEI96042", {
          deleted_artifact_count: 1,
          deleted_artifacts: [probableArtifact],
          deleted_subtree_count: 1,
        }),
      ],
    ]);
    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      return structuredClone(resolved);
    });

    function Harness() {
      const [activePath, setActivePath] = useState<string | null>("C:\\Users");
      return (
        <div>
          <button onClick={() => setActivePath(leafPath)} type="button">
            Open leaf
          </button>
          <SourceBrowser
            activePath={activePath}
            filterText=""
            leftPaneWidth={320}
            loadDirectory={loadDirectory}
            onInspectArtifact={() => {}}
            onResizePointerDown={() => {}}
            onSelectEntry={() => {}}
            onSelectPath={setActivePath}
            refreshToken={0}
            selectedArtifactId={null}
            selectedEntryPath={null}
            source={source}
          />
        </div>
      );
    }

    render(<Harness />);

    expect(await screen.findByText("C:\\Users")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("browser-status").textContent).toContain("1 nested deleted"));
    expect(screen.queryByText(".git")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open leaf" }));

    expect(await screen.findByText(".git")).toBeInTheDocument();
    expect(screen.getByText("Probable")).toBeInTheDocument();
  });

  it("shows a child route when a probable deleted folder has only nested deleted files", async () => {
    const folderPath = "C:\\Users\\jumarf\\Downloads\\yara_fp_strict_rules";
    const childPath = `${folderPath}\\private`;
    const listings = new Map<string, SourceDirectoryListing>([
      ["C:\\::dirs", listing("C:\\", [entry("C:\\Users", { deleted_hits: 1741, has_children: true })], null)],
      ["C:\\::all", listing("C:\\", [entry("C:\\Users", { deleted_hits: 1741, has_children: true })], null)],
      [
        `${folderPath}::dirs`,
        listing(
          folderPath,
          [
            entry(`${folderPath}\\live-a.txt`, { is_directory: false }),
            entry(`${folderPath}\\live-b.txt`, { is_directory: false }),
            entry(childPath, {
              access_state: "unknown",
              attributes: ["Deleted folder"],
              deleted_hits: 1741,
              has_children: true,
            }),
          ],
          "C:\\Users\\jumarf\\Downloads",
          { deleted_subtree_count: 1741 },
        ),
      ],
      [
        `${folderPath}::all`,
        listing(
          folderPath,
          [
            entry(`${folderPath}\\live-a.txt`, { is_directory: false }),
            entry(`${folderPath}\\live-b.txt`, { is_directory: false }),
            entry(childPath, {
              access_state: "unknown",
              attributes: ["Deleted folder"],
              deleted_hits: 1741,
              has_children: true,
            }),
          ],
          "C:\\Users\\jumarf\\Downloads",
          { deleted_subtree_count: 1741 },
        ),
      ],
    ]);
    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      return structuredClone(resolved);
    });

    render(
      <SourceBrowser
        activePath={folderPath}
        filterText=""
        leftPaneWidth={320}
        loadDirectory={loadDirectory}
        onInspectArtifact={() => {}}
        onResizePointerDown={() => {}}
        onSelectEntry={() => {}}
        onSelectPath={() => {}}
        refreshToken={0}
        selectedArtifactId={null}
        selectedEntryPath={null}
        source={source}
      />,
    );

    expect(await screen.findByText("private")).toBeInTheDocument();
    expect(screen.getByText("Deleted folder")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("browser-status").textContent).toContain("1741 nested deleted"));
  });

  it("does not show an empty tree expander for folders with only direct deleted files", async () => {
    const listings = new Map<string, SourceDirectoryListing>([
      [
        "C:\\::dirs",
        listing("C:\\", [entry("C:\\ProgramData", { deleted_hits: 2, has_children: false })], null, {
          deleted_subtree_count: 2,
        }),
      ],
      [
        "C:\\::all",
        listing("C:\\", [entry("C:\\ProgramData", { deleted_hits: 2, has_children: false })], null, {
          deleted_subtree_count: 2,
        }),
      ],
      [
        "C:\\ProgramData::dirs",
        listing("C:\\ProgramData", [], "C:\\", {
          deleted_artifact_count: 2,
          deleted_subtree_count: 2,
        }),
      ],
      [
        "C:\\ProgramData::all",
        listing("C:\\ProgramData", [], "C:\\", {
          deleted_artifact_count: 2,
          deleted_artifacts: [
            deletedArtifact("direct-a", "C:\\ProgramData\\direct-a.bin"),
            deletedArtifact("direct-b", "C:\\ProgramData\\direct-b.bin"),
          ],
          deleted_subtree_count: 2,
        }),
      ],
    ]);
    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      const key = `${request.path ?? source.mount_point}::${request.directories_only ? "dirs" : "all"}`;
      const resolved = listings.get(key);
      if (!resolved) {
        throw new Error(`Missing mock listing for ${key}`);
      }
      return structuredClone(resolved);
    });

    function Harness() {
      const [activePath, setActivePath] = useState<string | null>("C:\\");
      return (
        <SourceBrowser
          activePath={activePath}
          filterText=""
          leftPaneWidth={320}
          loadDirectory={loadDirectory}
          onInspectArtifact={() => {}}
          onResizePointerDown={() => {}}
          onSelectEntry={() => {}}
          onSelectPath={setActivePath}
          refreshToken={0}
          selectedArtifactId={null}
          selectedEntryPath={null}
          source={source}
        />
      );
    }

    render(<Harness />);

    await waitFor(() => expect(screen.getAllByText("2").length).toBeGreaterThan(0));
    const programDataTreeRow = screen
      .getAllByTestId("tree-entry-row")
      .find((candidate) => candidate.textContent?.includes("ProgramData"));

    expect(programDataTreeRow?.querySelector("[data-testid='tree-expand']")).toBeNull();
    fireEvent.click(programDataTreeRow!.querySelector("[data-testid='tree-open']")!);

    expect(await screen.findByText("direct-a.bin")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("browser-status").textContent).toContain("2/2 deleted"));
  });

  it("sends the browser filter to the backend for deleted artifact search", async () => {
    const requests: BrowseSourceRequest[] = [];
    const loadDirectory = vi.fn(async (request: BrowseSourceRequest) => {
      requests.push(request);
      if (request.directories_only) {
        return listing("C:\\", [], null);
      }
      return listing("C:\\", [], null, {
        deleted_artifact_count: 1,
        deleted_artifacts: [deletedArtifact("jar-a", "C:\\Recovered\\library.jar")],
      });
    });

    render(
      <SourceBrowser
        activePath="C:\\"
        filterText=".jar"
        leftPaneWidth={320}
        loadDirectory={loadDirectory}
        onInspectArtifact={() => {}}
        onResizePointerDown={() => {}}
        onSelectEntry={() => {}}
        onSelectPath={() => {}}
        refreshToken={0}
        selectedArtifactId={null}
        selectedEntryPath={null}
        source={source}
      />,
    );

    await waitFor(() =>
      expect(
        requests.some(
          (request) =>
            request.directories_only === false &&
            request.filter === ".jar" &&
            request.sort_key === "name" &&
            request.sort_direction === "asc",
        ),
      ).toBe(true),
    );

    fireEvent.click(screen.getByText("Modified"));

    await waitFor(() =>
      expect(
        requests.some(
          (request) =>
            request.directories_only === false &&
            request.filter === ".jar" &&
            request.sort_key === "modified_at" &&
            request.sort_direction === "asc",
        ),
      ).toBe(true),
    );
  });
});
