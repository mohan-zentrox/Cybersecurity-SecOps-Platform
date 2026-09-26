import { useCallback, useEffect, useState } from "react";

import { errorMessage } from "@/api/client";
import {
  FRAMEWORKS,
  generateReport,
  getReport,
  listReports,
  reportDownloadUrl,
  type ComplianceReport,
  type Framework,
} from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  inputClass,
  Loading,
  PageHeader,
  Panel,
  StatusBadge,
} from "@/components/ui";

function isoDaysAgo(days: number): string {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return date.toISOString().slice(0, 10);
}

export default function Compliance() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [selected, setSelected] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const [framework, setFramework] = useState<Framework>("SOC2");
  const [periodStart, setPeriodStart] = useState(isoDaysAgo(90));
  const [periodEnd, setPeriodEnd] = useState(isoDaysAgo(0));

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listReports({ limit: 50 });
      setReports(page.items);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load reports"));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function generate() {
    setGenerating(true);
    try {
      const report = await generateReport(
        framework,
        new Date(`${periodStart}T00:00:00Z`).toISOString(),
        new Date(`${periodEnd}T23:59:59Z`).toISOString(),
      );
      toast.success(
        `${report.framework}: ${report.controls_passed}/${report.controls_total} controls passed`,
      );
      setSelected(report);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Report generation failed"));
    } finally {
      setGenerating(false);
    }
  }

  async function open(report: ComplianceReport) {
    try {
      setSelected(await getReport(report.id));
    } catch (error) {
      toast.error(errorMessage(error, "Could not open report"));
    }
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Compliance"
        subtitle="Control verdicts derived from live platform data — audit chain, SLA performance, detection coverage, vulnerability posture"
      />

      <Panel title="Generate a report" className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Framework</span>
            <select
              value={framework}
              onChange={(e) => setFramework(e.target.value as Framework)}
              className={inputClass}
            >
              {FRAMEWORKS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Period start</span>
            <input
              type="date"
              value={periodStart}
              onChange={(e) => setPeriodStart(e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Period end</span>
            <input
              type="date"
              value={periodEnd}
              onChange={(e) => setPeriodEnd(e.target.value)}
              className={inputClass}
            />
          </label>
          <Button tone="primary" onClick={generate} disabled={generating}>
            {generating ? "Generating…" : "Generate"}
          </Button>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Reports" className="lg:col-span-1">
          {loading ? (
            <Loading />
          ) : reports.length === 0 ? (
            <EmptyState message="No reports generated yet." />
          ) : (
            <ul className="space-y-2">
              {reports.map((report) => (
                <li key={report.id}>
                  <button
                    onClick={() => open(report)}
                    className={`w-full rounded border p-3 text-left text-sm transition-colors ${
                      selected?.id === report.id
                        ? "border-aegis-accent bg-aegis-bg"
                        : "border-aegis-border hover:border-slate-600"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-slate-200">{report.framework}</span>
                      <span
                        className={
                          report.controls_failed === 0 ? "text-xs text-emerald-400" : "text-xs text-red-400"
                        }
                      >
                        {report.controls_passed}/{report.controls_total}
                      </span>
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      {formatDateTime(report.created_at)} · by {report.generated_by}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="lg:col-span-2">
          {selected === null ? (
            <Panel>
              <EmptyState
                message="Select a report to view its control verdicts."
                hint="Or generate a new one above."
              />
            </Panel>
          ) : (
            <Panel
              title={`${selected.framework} · ${formatDateTime(selected.period_start)} → ${formatDateTime(
                selected.period_end,
              )}`}
              actions={
                <a
                  href={reportDownloadUrl(selected.id)}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="rounded border border-aegis-border px-3 py-1.5 text-sm text-slate-200 hover:border-aegis-accent"
                >
                  Download HTML
                </a>
              }
            >
              <div className="mb-4 flex gap-6 text-sm">
                <span className="text-slate-400">
                  Passed <span className="ml-1 font-semibold text-emerald-400">{selected.controls_passed}</span>
                </span>
                <span className="text-slate-400">
                  Failed <span className="ml-1 font-semibold text-red-400">{selected.controls_failed}</span>
                </span>
                <span className="text-slate-400">
                  Total <span className="ml-1 font-semibold text-slate-200">{selected.controls_total}</span>
                </span>
              </div>

              {!selected.results?.controls ? (
                <EmptyState message="This report has no control results." />
              ) : (
                <div className="space-y-3">
                  {selected.results.controls.map((control) => (
                    <div key={control.control_id} className="rounded border border-aegis-border p-3">
                      <div className="mb-1 flex flex-wrap items-center gap-3">
                        <span className="font-mono text-xs text-slate-400">{control.control_id}</span>
                        <span className="flex-1 text-sm font-medium text-slate-200">{control.title}</span>
                        <StatusBadge value={control.verdict} />
                      </div>
                      <p className="text-sm text-slate-400">{control.summary}</p>
                      {Object.keys(control.metrics).length > 0 && (
                        <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                          {Object.entries(control.metrics).map(([key, value]) => (
                            <div key={key} className="flex gap-1">
                              <dt className="font-mono">{key}:</dt>
                              <dd className="text-slate-400">
                                {typeof value === "object" ? JSON.stringify(value) : String(value)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
