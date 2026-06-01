import { FolderOutput, LoaderCircle } from "lucide-react";

import { titleCase } from "@/shared/lib/format";
import type { RecoverySummary, ReportBundle } from "@/shared/types/api";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";

export function RecoveryPanel({
  destination,
  exportPending,
  lastReportBundle,
  lastRecovery,
  onBrowseDestination,
  onBrowseReports,
  onExport,
  onRecover,
  recoverPending,
  reportDestination,
  selectedCount,
}: {
  destination: string;
  exportPending: boolean;
  lastReportBundle: ReportBundle | null;
  lastRecovery: RecoverySummary | null;
  onBrowseDestination: () => void;
  onBrowseReports: () => void;
  onExport: () => void;
  onRecover: () => void;
  recoverPending: boolean;
  reportDestination: string;
  selectedCount: number;
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(360px,440px)_minmax(0,1fr)]">
      <section className="space-y-4 rounded-md border border-white/8 bg-[#111318] p-4">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Recover selected</div>
          <div className="mt-1 text-sm text-slate-300">{selectedCount} artifacts queued</div>
        </div>

        <PathField label="Destination" value={destination} onBrowse={onBrowseDestination} />
        <Button
          className="w-full rounded-md"
          disabled={selectedCount === 0 || recoverPending}
          onClick={onRecover}
          type="button"
        >
          {recoverPending ? <LoaderCircle className="size-4 animate-spin" /> : <FolderOutput className="size-4" />}
          Recover selected
        </Button>

        <div className="border-t border-white/8 pt-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Reports</div>
          <div className="mt-1 text-sm text-slate-300">Export JSON, CSV, HTML, and DFXML summary files.</div>
        </div>

        <PathField label="Reports" value={reportDestination} onBrowse={onBrowseReports} />
        <Button className="w-full rounded-md" disabled={exportPending} onClick={onExport} type="button" variant="secondary">
          {exportPending ? <LoaderCircle className="size-4 animate-spin" /> : <FolderOutput className="size-4" />}
          Export reports
        </Button>
      </section>

      <section className="space-y-4">
        <div className="rounded-md border border-white/8 bg-[#111318] p-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Latest recovery</div>
          {lastRecovery ? (
            <div className="mt-3 space-y-2 text-sm text-slate-300">
              <div className="truncate" title={lastRecovery.destination}>
                {lastRecovery.destination}
              </div>
              <div className="text-slate-500">{lastRecovery.items.length} items written</div>
              <div className="max-h-56 overflow-auto overscroll-contain rounded border border-white/8 bg-[#0d0f13]">
                {lastRecovery.items.map((item) => (
                  <div className="border-b border-white/6 px-3 py-2 last:border-b-0" key={item.artifact_id}>
                    <div className="truncate text-slate-200" title={item.file_path ?? item.artifact_id}>
                      {item.file_path ?? item.artifact_id}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">{titleCase(item.status)}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="mt-3 text-sm text-slate-500">No recovery run yet.</div>
          )}
        </div>

        <div className="rounded-md border border-white/8 bg-[#111318] p-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Latest report bundle</div>
          {lastReportBundle ? (
            <div className="mt-3 space-y-2 text-sm text-slate-300">
              <PathFact label="JSON" value={lastReportBundle.json_path} />
              <PathFact label="CSV" value={lastReportBundle.csv_path} />
              <PathFact label="HTML" value={lastReportBundle.html_path} />
              <PathFact label="DFXML" value={lastReportBundle.dfxml_path} />
            </div>
          ) : (
            <div className="mt-3 text-sm text-slate-500">No report export yet.</div>
          )}
        </div>
      </section>
    </div>
  );
}

function PathField({
  label,
  onBrowse,
  value,
}: {
  label: string;
  onBrowse: () => void;
  value: string;
}) {
  return (
    <div className="space-y-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className="flex items-center gap-2">
        <Input className="h-9 rounded-md border-white/8 bg-[#0d0f13] text-sm" readOnly title={value} value={value} />
        <Button className="h-9 rounded-md px-3" onClick={onBrowse} size="sm" type="button" variant="secondary">
          Browse
        </Button>
      </div>
    </div>
  );
}

function PathFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-white/8 bg-[#0d0f13] px-3 py-2">
      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className="mt-1 truncate text-slate-200" title={value}>
        {value}
      </div>
    </div>
  );
}
