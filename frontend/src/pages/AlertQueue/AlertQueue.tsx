import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  assignAlert,
  bulkUpdateStatus,
  listAlerts,
  promoteAlertsToCase,
  updateAlertStatus,
  type Alert,
  type AlertFilters,
  type AlertStatus,
} from "@/api/alerts";
import { errorMessage } from "@/api/client";
import { listUsers, type User } from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  formatRelative,
  inputClass,
  Loading,
  PageHeader,
  Pagination,
  Panel,
  Select,
  StatusBadge,
} from "@/components/ui";

const NEXT_STATUS: Record<string, AlertStatus[]> = {
  new: ["investigating"],
  investigating: ["closed", "escalated"],
  escalated: ["investigating", "closed"],
  closed: [],
};

const PAGE_SIZE = 25;

const STATUS_OPTIONS = [
  { value: "", label: "Any status" },
  { value: "new", label: "New" },
  { value: "investigating", label: "Investigating" },
  { value: "escalated", label: "Escalated" },
  { value: "closed", label: "Closed" },
];

const SEVERITY_OPTIONS = [
  { value: "", label: "Any severity" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const SCOPE_OPTIONS = [
  { value: "", label: "All alerts" },
  { value: "unassigned", label: "Unassigned only" },
  { value: "breached", label: "SLA breached" },
];

export default function AlertQueue() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [users, setUsers] = useState<User[]>([]);

  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [scope, setScope] = useState("");
  const [search, setSearch] = useState("");

  const navigate = useNavigate();
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const filters: AlertFilters = {
        limit: PAGE_SIZE,
        offset,
        status: status || undefined,
        severity: severity || undefined,
        search: search || undefined,
        unassigned: scope === "unassigned" ? true : undefined,
        sla_breached: scope === "breached" ? true : undefined,
      };
      const page = await listAlerts(filters);
      setAlerts(page.items);
      setTotal(page.total);
      // Drop selections for rows no longer on screen so a bulk action cannot
      // silently apply to alerts the user can no longer see.
      const visible = new Set(page.items.map((a) => a.id));
      setSelected((current) => new Set([...current].filter((id) => visible.has(id))));
    } catch (error) {
      toast.error(errorMessage(error, "Could not load alerts"));
    } finally {
      setLoading(false);
    }
  }, [offset, status, severity, scope, search, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    listUsers({ is_active: true })
      .then((page) => setUsers(page.items))
      .catch(() => setUsers([]));
  }, []);

  function toggle(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected((prev) => (prev.size === alerts.length ? new Set() : new Set(alerts.map((a) => a.id))));
  }

  async function transition(alertId: number, next: AlertStatus) {
    try {
      await updateAlertStatus(alertId, next);
      toast.success(`Alert #${alertId} moved to ${next}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Status change rejected"));
    }
  }

  async function bulkTransition(next: AlertStatus) {
    try {
      const result = await bulkUpdateStatus([...selected], next);
      const failures = Object.keys(result.failed).length;
      if (result.updated.length) {
        toast.success(`${result.updated.length} alert(s) moved to ${next}`);
      }
      if (failures) {
        toast.error(`${failures} alert(s) could not be moved: ${Object.values(result.failed)[0]}`);
      }
      setSelected(new Set());
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Bulk update failed"));
    }
  }

  async function assign(alertId: number, userId: string) {
    try {
      await assignAlert(alertId, userId ? Number(userId) : null);
      toast.success(userId ? "Alert assigned" : "Assignment cleared");
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Assignment failed"));
    }
  }

  async function promote() {
    if (selected.size === 0) return;
    try {
      const result = await promoteAlertsToCase([...selected]);
      toast.success(`Created case #${result.id}`);
      setSelected(new Set());
      navigate(`/cases/${result.id}`);
    } catch (error) {
      toast.error(errorMessage(error, "Could not promote alerts"));
    }
  }

  function applyFilter(setter: (value: string) => void) {
    return (value: string) => {
      setOffset(0);
      setter(value);
    };
  }

  const assigneeOptions = [
    { value: "", label: "Unassigned" },
    ...users.map((u) => ({ value: String(u.id), label: u.username })),
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Alert Queue"
        subtitle={`${total} alert${total === 1 ? "" : "s"} matching the current filters`}
        actions={
          <>
            <Button onClick={() => bulkTransition("investigating")} disabled={selected.size === 0}>
              Triage {selected.size > 0 ? `(${selected.size})` : ""}
            </Button>
            <Button onClick={() => bulkTransition("closed")} disabled={selected.size === 0}>
              Close
            </Button>
            <Button tone="primary" onClick={promote} disabled={selected.size === 0}>
              Promote to case
            </Button>
          </>
        }
      />

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={(e) => applyFilter(setSearch)(e.target.value)}
            placeholder="Search alert title…"
            className={`${inputClass} w-64`}
            aria-label="Search alerts"
          />
          <Select value={status} onChange={applyFilter(setStatus)} options={STATUS_OPTIONS} label="Status" />
          <Select
            value={severity}
            onChange={applyFilter(setSeverity)}
            options={SEVERITY_OPTIONS}
            label="Severity"
          />
          <Select value={scope} onChange={applyFilter(setScope)} options={SCOPE_OPTIONS} label="Scope" />
          <Button
            onClick={() => {
              setStatus("");
              setSeverity("");
              setScope("");
              setSearch("");
              setOffset(0);
            }}
          >
            Clear
          </Button>
        </div>
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : alerts.length === 0 ? (
          <EmptyState
            message="No alerts match these filters."
            hint="Ingest events and enabled detection rules will raise alerts here."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="w-8 py-2">
                    <input
                      type="checkbox"
                      checked={selected.size === alerts.length && alerts.length > 0}
                      onChange={toggleAll}
                      aria-label="Select all alerts on this page"
                    />
                  </th>
                  <th className="py-2">Title</th>
                  <th className="py-2">Severity</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">SLA</th>
                  <th className="py-2">Assignee</th>
                  <th className="py-2">Created</th>
                  <th className="py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id} className="border-b border-aegis-border/50 hover:bg-aegis-bg/40">
                    <td className="py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(alert.id)}
                        onChange={() => toggle(alert.id)}
                        aria-label={`Select alert ${alert.id}`}
                      />
                    </td>
                    <td className="py-2">
                      <div className="text-slate-200">{alert.title}</div>
                      {alert.enrichment?.matched && (
                        <div className="mt-0.5 text-xs text-red-400">
                          Threat intel:{" "}
                          {alert.enrichment.indicators?.map((i) => i.value).join(", ") ?? "matched"}
                        </div>
                      )}
                    </td>
                    <td className="py-2">
                      <StatusBadge value={alert.severity} />
                    </td>
                    <td className="py-2">
                      <StatusBadge value={alert.status} />
                    </td>
                    <td className="py-2 text-xs">
                      {alert.sla_breached ? (
                        <span className="font-medium text-red-400">Breached</span>
                      ) : (
                        <span className="text-slate-400">{formatRelative(alert.sla_due_at)}</span>
                      )}
                    </td>
                    <td className="py-2">
                      <select
                        value={alert.assigned_to ? String(alert.assigned_to) : ""}
                        onChange={(e) => assign(alert.id, e.target.value)}
                        className={`${inputClass} text-xs`}
                        aria-label={`Assignee for alert ${alert.id}`}
                      >
                        {assigneeOptions.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-2 text-xs text-slate-400">{formatDateTime(alert.created_at)}</td>
                    <td className="py-2">
                      {(NEXT_STATUS[alert.status] ?? []).map((next) => (
                        <button
                          key={next}
                          onClick={() => transition(alert.id, next)}
                          className="mr-2 rounded border border-aegis-border px-2 py-1 text-xs hover:border-aegis-accent"
                        >
                          → {next}
                        </button>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      </Panel>
    </div>
  );
}
