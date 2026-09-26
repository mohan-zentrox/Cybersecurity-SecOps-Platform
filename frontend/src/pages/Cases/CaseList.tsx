import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { errorMessage } from "@/api/client";
import { listCases, RESOLUTION_LABELS, type CaseSummary } from "@/api/cases";
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

const RESOLUTION_OPTIONS = [
  { value: "", label: "Any resolution" },
  ...Object.entries(RESOLUTION_LABELS).map(([value, label]) => ({ value, label })),
];

/**
 * The case list. Previously a case was only reachable by direct URL
 * immediately after promoting alerts — once you navigated away, there was no
 * route back to it. This is that route.
 */
export default function CaseList() {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [users, setUsers] = useState<Record<number, string>>({});

  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [resolution, setResolution] = useState("");
  const [breachedOnly, setBreachedOnly] = useState(false);
  const [search, setSearch] = useState("");

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listCases({
        limit: PAGE_SIZE,
        offset,
        status: status || undefined,
        severity: severity || undefined,
        resolution: resolution || undefined,
        sla_breached: breachedOnly ? true : undefined,
        search: search || undefined,
      });
      setCases(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load cases"));
    } finally {
      setLoading(false);
    }
  }, [offset, status, severity, resolution, breachedOnly, search, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    listUsers({ is_active: true })
      .then((page) =>
        setUsers(Object.fromEntries(page.items.map((u: User) => [u.id, u.username]))),
      )
      .catch(() => setUsers({}));
  }, []);

  function applyFilter<T>(setter: (value: T) => void) {
    return (value: T) => {
      setOffset(0);
      setter(value);
    };
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Cases"
        subtitle={`${total} case${total === 1 ? "" : "s"} matching the current filters`}
        actions={<Button onClick={refresh}>Refresh</Button>}
      />

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={(e) => applyFilter(setSearch)(e.target.value)}
            placeholder="Search case title…"
            className={`${inputClass} w-64`}
            aria-label="Search cases"
          />
          <Select value={status} onChange={applyFilter(setStatus)} options={STATUS_OPTIONS} label="Status" />
          <Select
            value={severity}
            onChange={applyFilter(setSeverity)}
            options={SEVERITY_OPTIONS}
            label="Severity"
          />
          <Select
            value={resolution}
            onChange={applyFilter(setResolution)}
            options={RESOLUTION_OPTIONS}
            label="Resolution"
          />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={breachedOnly}
              onChange={(e) => applyFilter(setBreachedOnly)(e.target.checked)}
            />
            SLA breached only
          </label>
        </div>
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : cases.length === 0 ? (
          <EmptyState
            message="No cases match these filters."
            hint="Promote alerts or vulnerabilities to open an investigation."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="py-2">ID</th>
                  <th className="py-2">Title</th>
                  <th className="py-2">Severity</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">Resolution</th>
                  <th className="py-2">SLA</th>
                  <th className="py-2">Assignee</th>
                  <th className="py-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item) => (
                  <tr key={item.id} className="border-b border-aegis-border/50 hover:bg-aegis-bg/40">
                    <td className="py-2 text-slate-500">#{item.id}</td>
                    <td className="py-2">
                      <Link to={`/cases/${item.id}`} className="text-slate-200 hover:text-aegis-accent">
                        {item.title}
                      </Link>
                    </td>
                    <td className="py-2">
                      <StatusBadge value={item.severity} />
                    </td>
                    <td className="py-2">
                      <StatusBadge value={item.status} />
                    </td>
                    <td className="py-2 text-xs text-slate-400">
                      {item.resolution ? RESOLUTION_LABELS[item.resolution] : "—"}
                    </td>
                    <td className="py-2 text-xs">
                      {item.sla_breached ? (
                        <span className="font-medium text-red-400">Breached</span>
                      ) : item.status === "closed" ? (
                        <span className="text-slate-500">Met</span>
                      ) : (
                        <span className="text-slate-400">{formatRelative(item.sla_due_at)}</span>
                      )}
                    </td>
                    <td className="py-2 text-xs text-slate-400">
                      {item.assigned_to ? (users[item.assigned_to] ?? `#${item.assigned_to}`) : "—"}
                    </td>
                    <td className="py-2 text-xs text-slate-400">{formatDateTime(item.created_at)}</td>
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
