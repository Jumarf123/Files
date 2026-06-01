import { useEffect, useMemo, useReducer, useRef } from "react";

import type { ArtifactSummary } from "@/shared/types/api";

import { buildDeletedIndex, createEmptyDeletedIndex, type DeletedIndex } from "./source-browser-index";

type WorkerResponse = {
  deletedIndex: DeletedIndex;
  requestId: number;
};

type DeletedIndexState = {
  deletedIndex: DeletedIndex;
  ready: boolean;
};

type DeletedIndexAction =
  | { type: "start" }
  | { type: "resolved"; deletedIndex: DeletedIndex }
  | { type: "idle" };

function deletedIndexReducer(state: DeletedIndexState, action: DeletedIndexAction): DeletedIndexState {
  switch (action.type) {
    case "start":
      return { deletedIndex: createEmptyDeletedIndex(), ready: false };
    case "resolved":
      return { deletedIndex: action.deletedIndex, ready: true };
    case "idle":
      return { deletedIndex: createEmptyDeletedIndex(), ready: true };
    default:
      return state;
  }
}

export function useDeletedIndex(deletedArtifacts: ArtifactSummary[], rootPath: string | null) {
  const workerRef = useRef<Worker | null>(null);
  const requestIdRef = useRef(0);
  const [state, dispatch] = useReducer(deletedIndexReducer, {
    deletedIndex: createEmptyDeletedIndex(),
    ready: true,
  });

  const workerAvailable = useMemo(
    () => typeof window !== "undefined" && typeof Worker !== "undefined",
    [],
  );

  useEffect(() => {
    if (!workerAvailable) {
      return;
    }

    const worker = new Worker(new URL("./source-browser.worker.ts", import.meta.url), { type: "module" });
    workerRef.current = worker;
    return () => {
      workerRef.current = null;
      worker.terminate();
    };
  }, [workerAvailable]);

  useEffect(() => {
    const requestId = ++requestIdRef.current;
    dispatch({ type: "start" });

    if (!deletedArtifacts.length) {
      dispatch({ type: "idle" });
      return;
    }

    const worker = workerRef.current;
    if (!worker) {
      const handle = window.setTimeout(() => {
        dispatch({ type: "resolved", deletedIndex: buildDeletedIndex(deletedArtifacts, rootPath) });
      }, 0);
      return () => {
        window.clearTimeout(handle);
      };
    }

    const handleMessage = (event: MessageEvent<WorkerResponse>) => {
      if (event.data.requestId !== requestId) {
        return;
      }
      dispatch({ type: "resolved", deletedIndex: event.data.deletedIndex });
    };

    worker.addEventListener("message", handleMessage);
    worker.postMessage({ deletedArtifacts, requestId, rootPath });

    return () => {
      worker.removeEventListener("message", handleMessage);
    };
  }, [deletedArtifacts, rootPath]);

  return {
    deletedIndex: state.deletedIndex,
    ready: state.ready,
  };
}
