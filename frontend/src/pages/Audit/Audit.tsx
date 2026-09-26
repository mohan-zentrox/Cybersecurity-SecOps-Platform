import { useCallback, useEffect, useState } from "react";

import { errorMessage } from "@/api/client";
import {
  auditExportUrl,
  listAuditActions,
  listAuditEvents,
  verifyAuditChain,
  type AuditEvent,
  type ChainVerification,
} from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  inputClass,
  Loading,
  PageHeader,
  Pagination,
  Panel,
  Select,
} from "@/components/ui";

const PAGE_SIZE = 50;

export default function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [actions, setActions] = useState<string[]>([]);
  const [verification, setVerification] = useState<ChainVerification | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listAuditEvents({
        limit: PAGE_SIZE,
        offset,
        actor: actor || undefined,
        action: action || undefined,
      });
      setEvents(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load the audit log"));
    } finally {
      setLoading(false);
    }
  }, [offset, actor, action, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    listAuditActions().then(setActions).catch(() => setActions([]));
  }, []);

  const verify = useCallback(async () => {
    try {
      const result = await verifyAuditChain();
      setVerification(result);
      if (result.intact) {
        toast.success(`Chain intact across ${result.total_events} events`);
      } else {
        toast.error(`Chain BROKEN at event ${result.first_broken_event_id}`);
      }
    } catch (error) {
      toast.error(errorMessage(error, "Chain verification failed"));
    }
  }, [toast]);

  useEffect(() => {
    verify();
    // Run once on mount; re-verification is explicit via the button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const actionOptions = [
    { value: "", label: "Any action" },
    ...actions.map((a) => ({ value: a, label: a.replace(/_/g, " ") })),
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Audit Log"
        subtitle="Tamper-evident record of every privileged action. Each row commits to the hash of the row before it."
        actions={
          <>
            <Button onClick={verify}>Verify chain</Button>
            <a
              href={auditExportUrl}
              className="rounded border border-aegis-border px-3 py-1.5 text-sm text-slate-200 hover:border-aegis-accent"
            >
              Export CSV
            </a>
          </>
        }
      />

      {verification && (
        <div
          className={`mb-4 rounded border p-3 text-sm ${
            verification.intact
              ? "border-emerald-800 bg-emerald-950 text-emerald-200"
              : "border-red-800 bg-red-950 text-red-200"
          }`}
        >
          {verification.intact ? (
            <>
              <strong>Chain intact.</strong> {verification.total_events} audit events verified — no row has
              been edited, deleted, or reordered.
            </>
          ) : (
            <>
              <strong>Chain broken.</strong> {verification.reason}
            </>
          )}
        </div>
      )}

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={actor}
            onChange={(e) => {
              setOffset(0);
              setActor(e.target.value);
            }}
            placeholder="Filter by actor…"
            className={`${inputClass} w-48`}
            aria-label="Filter by actor"
          />
          <Select
            value={action}
            onChange={(value) => {
              setOffset(0);
              setAction(value);
            }}
            options={actionOptions}
            label="Action"
          />
        </div>
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : events.length === 0 ? (
          <EmptyState message="No audit events match these filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="py-2">ID</th>
                  <th className="py-2">Time</th>
                  <th className="py-2">Actor</th>
                  <th className="py-2">Action</th>
                  <th className="py-2">Resource</th>
                  <th className="py-2">Hash</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <>
                    <tr
                      key={event.id}
                      onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                      className="cursor-pointer border-b border-aegis-border/50 hover:bg-aegis-bg/40"
                    >
                      <td className="py-2 text-slate-500">{event.id}</td>
                      <td className="py-2 text-xs text-slate-400">{formatDateTime(event.timestamp)}</td>
                      <td className="py-2 text-slate-200">{event.actor}</td>
                      <td className="py-2 text-slate-300">{event.action.replace(/_/g, " ")}</td>
                      <td className="py-2 font-mono text-xs text-slate-400">{event.resource}</td>
                      <td className="py-2 font-mono text-xs text-slate-600">
                        {event.content_hash.slice(0, 12)}…
                      </td>
                    </tr>
                    {expanded === event.id && (
                      <tr key={`${event.id}-detail`}>
                        <td colSpan={6} className="bg-aegis-bg/60 p-3">
                          <div className="mb-2 grid gap-1 font-mono text-xs text-slate-500">
                            <div>prev_hash: {event.prev_hash}</div>
                            <div>content_hash: {event.content_hash}</div>
                          </div>
                          <pre className="overflow-x-auto text-xs text-slate-400">
                            {JSON.stringify(event.details, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </>
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
