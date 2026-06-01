import type { ArtifactSummary } from "@/shared/types/api";

export type DeletedFolderNode = {
  path: string;
  parentPath: string | null;
  name: string;
};

export type DeletedIndex = {
  directFolderCounts: Map<string, number>;
  subtreeFolderCounts: Map<string, number>;
  directArtifactsByFolder: Map<string, ArtifactSummary[]>;
  syntheticFolders: Map<string, DeletedFolderNode>;
  syntheticFoldersByParent: Map<string, DeletedFolderNode[]>;
  unknownArtifacts: ArtifactSummary[];
};

export function createEmptyDeletedIndex(): DeletedIndex {
  return {
    directFolderCounts: new Map(),
    subtreeFolderCounts: new Map(),
    directArtifactsByFolder: new Map(),
    syntheticFolders: new Map(),
    syntheticFoldersByParent: new Map(),
    unknownArtifacts: [],
  };
}

export function buildDeletedIndex(results: ArtifactSummary[], rootPath: string | null): DeletedIndex {
  const directFolderCounts = new Map<string, number>();
  const subtreeFolderCounts = new Map<string, number>();
  const directArtifactsByFolder = new Map<string, ArtifactSummary[]>();
  const syntheticFolders = new Map<string, DeletedFolderNode>();
  const syntheticFoldersByParent = new Map<string, DeletedFolderNode[]>();
  const unknownArtifacts: ArtifactSummary[] = [];
  const rootDisplayPath = canonicalizeBrowserPath(rootPath ?? "");

  for (const artifact of results) {
    if (isUnknownArtifact(artifact, rootPath)) {
      unknownArtifacts.push(artifact);
      continue;
    }

    const artifactPath = canonicalizeBrowserPath(artifact.original_path!);
    const folderPath = parentDirectoryPath(artifactPath, rootPath);
    const folderKey = normalizeBrowserPath(folderPath);
    directFolderCounts.set(folderKey, (directFolderCounts.get(folderKey) ?? 0) + 1);

    const directBucket = directArtifactsByFolder.get(folderKey) ?? [];
    directBucket.push(artifact);
    directArtifactsByFolder.set(folderKey, directBucket);

    const subtreeFolders = [folderPath, ...collectArtifactAncestors(folderPath, rootPath)];
    for (const candidateFolder of subtreeFolders) {
      const candidateKey = normalizeBrowserPath(candidateFolder);
      subtreeFolderCounts.set(candidateKey, (subtreeFolderCounts.get(candidateKey) ?? 0) + 1);
    }

    registerDeletedFolderHierarchy(folderPath, rootDisplayPath, syntheticFolders, syntheticFoldersByParent);
  }

  for (const folders of syntheticFoldersByParent.values()) {
    folders.sort((left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: "base" }));
  }

  return {
    directFolderCounts,
    subtreeFolderCounts,
    directArtifactsByFolder,
    syntheticFolders,
    syntheticFoldersByParent,
    unknownArtifacts,
  };
}

export function unknownBucketPath(sourceId: string) {
  return `rss://unknown/${sourceId.toLowerCase()}`;
}

export function isUnknownBucketPath(path: string) {
  return path.startsWith("rss://unknown/");
}

export function normalizeBrowserPath(path: string) {
  return path.replaceAll("/", "\\").toLowerCase();
}

export function parentDirectoryPath(path: string, rootPath: string | null) {
  const normalizedPath = normalizeBrowserPath(path);
  const canonicalPath = canonicalizeBrowserPath(path);
  const canonicalRoot = canonicalizeBrowserPath(rootPath ?? "");
  const normalizedRoot = canonicalRoot ? normalizeBrowserPath(canonicalRoot) : "";
  if (normalizedRoot && normalizedPath === normalizedRoot) {
    return canonicalRoot;
  }
  const lastSlash = canonicalPath.lastIndexOf("\\");
  if (lastSlash < 0) {
    return canonicalRoot || canonicalPath;
  }
  if (normalizedRoot && lastSlash < normalizedRoot.length) {
    return canonicalRoot;
  }
  const parent = canonicalPath.slice(0, lastSlash);
  if (/^[a-z]:$/i.test(parent)) {
    return canonicalRoot || `${parent}\\`;
  }
  if (!normalizedRoot) {
    return parent;
  }
  return parent.length < canonicalRoot.length ? canonicalRoot : parent;
}

export function collectArtifactAncestors(path: string, rootPath: string | null) {
  const ancestors: string[] = [];
  const normalizedRoot = rootPath ? normalizeBrowserPath(rootPath) : "";
  if (normalizedRoot && normalizeBrowserPath(path) === normalizedRoot) {
    return ancestors;
  }
  let cursor = parentDirectoryPath(path, rootPath);
  while (cursor) {
    ancestors.push(cursor);
    if (normalizedRoot && normalizeBrowserPath(cursor) === normalizedRoot) {
      break;
    }
    const next = parentDirectoryPath(cursor, rootPath);
    if (next === cursor) {
      break;
    }
    cursor = next;
  }
  return ancestors;
}

function isUnknownArtifact(artifact: ArtifactSummary, rootPath: string | null) {
  if (!artifact.original_path) {
    return true;
  }
  if (!rootPath) {
    return false;
  }
  return !pathIsWithinRoot(artifact.original_path, rootPath);
}

function pathIsWithinRoot(path: string, rootPath: string) {
  const normalizedPath = normalizeBrowserPath(path);
  const normalizedRoot = normalizeBrowserPath(rootPath);
  if (!normalizedRoot) {
    return true;
  }
  if (normalizedRoot.endsWith("\\")) {
    return normalizedPath.startsWith(normalizedRoot);
  }
  return normalizedPath === normalizedRoot || normalizedPath.startsWith(`${normalizedRoot}\\`);
}

function registerDeletedFolderHierarchy(
  folderPath: string,
  rootPath: string,
  folders: Map<string, DeletedFolderNode>,
  foldersByParent: Map<string, DeletedFolderNode[]>,
) {
  for (const candidatePath of collectFolderHierarchy(folderPath, rootPath)) {
    const candidateKey = normalizeBrowserPath(candidatePath);
    if (folders.has(candidateKey)) {
      continue;
    }

    const rootKey = rootPath ? normalizeBrowserPath(rootPath) : "";
    const parentPath =
      rootKey && candidateKey === rootKey ? null : parentDirectoryPath(candidatePath, rootPath || null);
    const parentKey = parentPath ? normalizeBrowserPath(parentPath) : null;
    const folder = {
      path: candidatePath,
      parentPath,
      name: folderName(candidatePath),
    } satisfies DeletedFolderNode;
    folders.set(candidateKey, folder);

    if (parentKey) {
      const siblings = foldersByParent.get(parentKey) ?? [];
      siblings.push(folder);
      foldersByParent.set(parentKey, siblings);
    }
  }
}

function collectFolderHierarchy(folderPath: string, rootPath: string) {
  const chain: string[] = [];
  const rootKey = rootPath ? normalizeBrowserPath(rootPath) : "";
  let cursor = folderPath;
  while (cursor && (!rootKey || normalizeBrowserPath(cursor) !== rootKey)) {
    chain.push(cursor);
    const next = parentDirectoryPath(cursor, rootPath || null);
    if (!next || next === cursor) {
      break;
    }
    cursor = next;
  }
  return chain.reverse();
}

function canonicalizeBrowserPath(path: string) {
  return path.replaceAll("/", "\\");
}

function folderName(path: string) {
  const trimmed = path.endsWith("\\") ? path.slice(0, -1) : path;
  const lastSlash = trimmed.lastIndexOf("\\");
  if (lastSlash < 0) {
    return trimmed;
  }
  return trimmed.slice(lastSlash + 1);
}
