import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { errorMessage } from "@/api/client";
import { getKpiSummary, runSlaSweep, type KPISummary } from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatMinutes,
  formatPercent,
  Loading,
  PageHeader,
  Panel,
  Select,
  StatTile,
  StatusBadge,
} from "@/components/ui";
import { ADMIN_ONLY, useHasRole } from "@/store/authStore";

const WINDOWS = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

const SEVERITY_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-slate-500",
};

export default function Dashboard() {
  const [summary, setSummary] = useState<KPISummary | null>(null);
  const [window, setWindow] = useState("7d");
  const [loading, setLoading] = useState(true);
  const canSweep = useHasRole(...ADMIN_ONLY, "analyst");
  const toast = useToast();

  const load = useCallback(
    async (selected: string) => {
      setLoading(true);
      try {
        setSummary(await getKpiSummary(selected));
      } catch (error) {
        toast.error(errorMessage(error, "Could not load dashboard metrics"));
      } finally {
        setLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    load(window);
  }, [window, load]);

  async function sweep() {
    try {
      const result = await runSlaSweep();
      toast.success(
        result.total === 0
          ? "SLA sweep complete — nothing is overdue"
          : `SLA sweep flagged ${result.total} overdue item(s)`,
      );
      load(window);
    } catch (error) {
      toast.error(errorMessage(error, "SLA sweep failed"));
    }
  }

  if (loading && !summary) return <Loading label="Loading SOC metrics…" />;
  if (!summary) return <EmptyState message="No metrics available." />;

  const { alerts, cases, ingestion, detection } = summary;
  const peak = Math.max(1, ...summary.volume_series.map((point) => point.total));

  return (
    <div className="p-6">
      <PageHeader
        title="SOC Dashboard"
        subtitle={`Operational metrics for the ${summary.window} window`}
        actions={
          <>
            <Select value={window} onChange={setWindow} options={WINDOWS} />
            {canSweep && <Button onClick={sweep}>Run SLA sweep</Button>}
            <Button onClick={() => load(window)}>Refresh</Button>
          </>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile
          label="Open alerts"
          value={alerts.open}
          hint={`${alerts.total} raised in window`}
          tone={alerts.open > 0 ? "warning" : "good"}
        />
        <StatTile
          label="Open cases"
          value={cases.open}
          hint={`${cases.closed} closed in window`}
          tone={cases.open > 0 ? "warning" : "good"}
        />
        <StatTile
          label="SLA breaches"
          value={alerts.sla_breached + cases.sla_breached}
          hint={`Alert breach rate ${formatPercent(alerts.sla_breach_rate)}`}
          tone={alerts.sla_breached + cases.sla_breached > 0 ? "danger" : "good"}
        />
        <StatTile
          label="Threat-intel hits"
          value={ingestion.events_with_threat_match}
          hint={`${ingestion.events_normalized} events normalized`}
        />
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="MTTD" value={formatMinutes(alerts.mttd_minutes)} hint="Event → alert" />
        <StatTile label="MTTA" value={formatMinutes(alerts.mtta_minutes)} hint="Alert → first action" />
        <StatTile label="MTTR (alerts)" value={formatMinutes(alerts.mttr_minutes)} hint="Alert → closed" />
        <StatTile
          label="MTTR p95"
          value={formatMinutes(alerts.mttr_p95_minutes)}
          hint="95th percentile"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Alert volume by day">
          {summary.volume_series.length === 0 ? (
            <EmptyState message="No alerts in this window." />
          ) : (
            <div className="flex h-44 items-end gap-1" role="img" aria-label="Daily alert volume by severity">
              {summary.volume_series.map((point) => (
                <div key={point.date} className="group flex flex-1 flex-col items-center gap-1">
                  <div
                    className="flex w-full flex-col-reverse justify-end"
                    style={{ height: `${(point.total / peak) * 100}%`, minHeight: point.total ? "4px" : "0" }}
                    title={`${point.date}: ${point.total} alert(s)`}
                  >
                    {(["low", "medium", "high", "critical"] as const).map((severity) =>
                      point[severity] > 0 ? (
                        <div
                          key={severity}
                          className={SEVERITY_BAR_COLORS[severity]}
                          style={{ height: `${(point[severity] / point.total) * 100}%` }}
                        />
                      ) : null,
                    )}
                  </div>
                  <span className="text-[10px] text-slate-600">{point.date.slice(5)}</span>
                </div>
              ))}
            </div>
          )}
          <div className="mt-3 flex gap-4 text-xs text-slate-500">
            {(["critical", "high", "medium", "low"] as const).map((severity) => (
              <span key={severity} className="flex items-center gap-1">
                <span className={`inline-block h-2 w-2 rounded-sm ${SEVERITY_BAR_COLORS[severity]}`} />
                {severity}
              </span>
            ))}
          </div>
        </Panel>

        <Panel title="Noisiest detection rules">
          {summary.top_rules.length === 0 ? (
            <EmptyState message="No rules have fired in this window." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="pb-2">Rule</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2 text-right">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {summary.top_rules.map((rule) => (
                  <tr key={rule.rule_id} className="border-t border-aegis-border/50">
                    <td className="py-2">
                      <Link to={`/rules/${rule.rule_id}`} className="text-slate-200 hover:text-aegis-accent">
                        {rule.rule_name}
                      </Link>
                    </td>
                    <td className="py-2">
                      <StatusBadge value={rule.severity} />
                    </td>
                    <td className="py-2 text-right font-medium text-slate-300">{rule.alert_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Analyst workload">
          {summary.workload.length === 0 ? (
            <EmptyState message="No active users." />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr>
                  <th className="pb-2">Analyst</th>
                  <th className="pb-2 text-right">Open alerts</th>
                  <th className="pb-2 text-right">Open cases</th>
                  <th className="pb-2 text-right">Breached</th>
                </tr>
              </thead>
              <tbody>
                {summary.workload.map((entry) => (
                  <tr key={entry.user_id} className="border-t border-aegis-border/50">
                    <td className="py-2 text-slate-200">
                      {entry.username} <span className="text-xs text-slate-500">({entry.role})</span>
                    </td>
                    <td className="py-2 text-right">{entry.open_alerts}</td>
                    <td className="py-2 text-right">{entry.open_cases}</td>
                    <td
                      className={`py-2 text-right ${entry.breached_cases > 0 ? "text-red-400" : "text-slate-500"}`}
                    >
                      {entry.breached_cases}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Pipeline health">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
            <dt className="text-slate-400">Events normalized</dt>
            <dd className="text-right text-slate-200">{ingestion.events_normalized.toLocaleString()}</dd>

            <dt className="text-slate-400">Dead-lettered</dt>
            <dd
              className={`text-right ${ingestion.events_dead_lettered > 0 ? "text-amber-400" : "text-slate-200"}`}
            >
              {ingestion.events_dead_lettered} ({formatPercent(ingestion.dead_letter_rate)})
            </dd>

            <dt className="text-slate-400">Detection rules enabled</dt>
            <dd className="text-right text-slate-200">
              {detection.rules_enabled} / {detection.rules_total}
            </dd>

            <dt className="text-slate-400">MITRE techniques covered</dt>
            <dd className="text-right text-slate-200">{detection.mitre_technique_count}</dd>

            <dt className="text-slate-400">Case MTTR</dt>
            <dd className="text-right text-slate-200">{formatMinutes(cases.mttr_minutes)}</dd>

            <dt className="text-slate-400">Case SLA compliance</dt>
            <dd className="text-right text-slate-200">{formatPercent(1 - cases.sla_breach_rate)}</dd>
          </dl>

          {Object.keys(cases.by_resolution).length > 0 && (
            <div className="mt-4 border-t border-aegis-border pt-3">
              <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">Case dispositions</div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(cases.by_resolution).map(([resolution, count]) => (
                  <span key={resolution} className="rounded bg-aegis-bg px-2 py-1 text-xs text-slate-300">
                    {resolution.replace(/_/g, " ")}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
