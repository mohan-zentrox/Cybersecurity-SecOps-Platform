import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { type Alert, listAlerts, promoteAlertsToCase, updateAlertStatus } from "@/api/alerts";
import { StatusBadge } from "@/components/StatusBadge";

const NEXT_STATUS: Record<string, string[]> = {
  new: ["investigating"],
  investigating: ["closed", "escalated"],
  escalated: ["investigating", "closed"],
  closed: [],
};

export default function AlertQueue() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  async function refresh() {
    setLoading(true);
    try {
      setAlerts(await listAlerts());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  function toggle(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function transition(alertId: number, status: string) {
    await updateAlertStatus(alertId, status as any);
    refresh();
  }

  async function promote() {
    if (selected.size === 0) return;
    const result = await promoteAlertsToCase(Array.from(selected));
    setSelected(new Set());
    navigate(`/cases/${(result as any).id}`);
  }

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-lg font-semibold">Alert Queue</h1>
        <button
          onClick={promote}
          disabled={selected.size === 0}
          className="rounded bg-aegis-accent px-3 py-1.5 text-sm font-medium text-slate-900 disabled:opacity-40"
        >
          Promote {selected.size > 0 ? `(${selected.size})` : ""} to Case
        </button>
      </div>

      {loading ? (
        <p className="text-slate-400">Loading…</p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr className="border-b border-aegis-border">
              <th className="w-8 py-2"></th>
              <th className="py-2">Title</th>
              <th className="py-2">Severity</th>
              <th className="py-2">Status</th>
              <th className="py-2">Created</th>
              <th className="py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id} className="border-b border-aegis-border/50">
                <td className="py-2">
                  <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                </td>
                <td className="py-2">{a.title}</td>
                <td className="py-2">
                  <StatusBadge value={a.severity} />
                </td>
                <td className="py-2">
                  <StatusBadge value={a.status} />
                </td>
                <td className="py-2 text-slate-400">{new Date(a.created_at).toLocaleString()}</td>
                <td className="py-2">
                  {(NEXT_STATUS[a.status] ?? []).map((next) => (
                    <button
                      key={next}
                      onClick={() => transition(a.id, next)}
                      className="mr-2 rounded border border-aegis-border px-2 py-1 text-xs hover:border-aegis-accent"
                    >
                      → {next}
                    </button>
                  ))}
                </td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan={6} className="py-6 text-center text-slate-500">
                  No alerts yet — ingest events and enabled detection rules will raise alerts here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
