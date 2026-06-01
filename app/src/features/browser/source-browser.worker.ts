import { buildDeletedIndex } from "./source-browser-index";

type BuildDeletedIndexRequest = {
  requestId: number;
  deletedArtifacts: unknown[];
  rootPath: string | null;
};

self.onmessage = (event: MessageEvent<BuildDeletedIndexRequest>) => {
  const { deletedArtifacts, requestId, rootPath } = event.data;
  const deletedIndex = buildDeletedIndex(deletedArtifacts as never[], rootPath);
  self.postMessage({ deletedIndex, requestId });
};
