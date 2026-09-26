import { useCallback, useEffect, useState } from "react";

import { errorMessage } from "@/api/client";
import {
  listDeadLetters,
  replayDeadLetters,
  searchEvents,
  type DeadLetter,
  type NormalizedEvent,
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
import { RULE_AUTHORS, useHasRole } from "@/store/authStore";

const PAGE_SIZE = 25;

const THREAT_OPTIONS = [
  { value: "", label: "All events" },
  { value: "true", label: "Threat-intel matches only" },
  { value: "false", label: "No threat match" },
];

export default function Events() {
  const [tab, setTab] = useState<"events" | "dead-letters">("events");
  const canManageDlq = useHasRole(...RULE_AUTHORS);

  return (
    <div className="p-6">
      <PageHeader
        title="Event Store"
        subtitle="ECS-normalized security telemetry and the dead-letter queue"
        actions={
          <div className="flex gap-2">
            <Button tone={tab === "events" ? "primary" : "secondary"} onClick={() => setTab("events")}>
              Events
            </Button>
            {canManageDlq && (
              <Button
                tone={tab === "dead-letters" ? "primary" : "secondary"}
                onClick={() => setTab("dead-letters")}
              >
                Dead letters
              </Button>
            )}
          </div>
        }
      />
      {tab === "events" ? <EventSearch /> : <DeadLetterQueue />}
    </div>
  );
}

function EventSearch() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);

  const [action, setAction] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [userName, setUserName] = useState("");
  const [threat, setThreat] = useState("");

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await searchEvents({
        limit: PAGE_SIZE,
        offset,
        event_action: action || undefined,
        source_ip: sourceIp || undefined,
        user_name: userName || undefined,
        threat_matched: threat === "" ? undefined : threat === "true",
      });
      setEvents(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not search events"));
    } finally {
      setLoading(false);
    }
  }, [offset, action, sourceIp, userName, threat, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <>
      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={action}
            onChange={(e) => {
              setOffset(0);
              setAction(e.target.value);
            }}
            placeholder="event.action"
            className={`${inputClass} w-48`}
            aria-label="Filter by event action"
          />
          <input
            value={sourceIp}
            onChange={(e) => {
              setOffset(0);
              setSourceIp(e.target.value);
            }}
            placeholder="source.ip"
            className={`${inputClass} w-40`}
            aria-label="Filter by source IP"
          />
          <input
            value={userName}
            onChange={(e) => {
              setOffset(0);
              setUserName(e.target.value);
            }}
            placeholder="user.name"
            className={`${inputClass} w-40`}
            aria-label="Filter by user name"
          />
          <Select
            value={threat}
            onChange={(value) => {
              setOffset(0);
              setThreat(value);
            }}
            options={THREAT_OPTIONS}
            label="Threat"
          />
        </div>
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : events.length === 0 ? (
          <EmptyState message="No events match these filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="py-2">Time</th>
                  <th className="py-2">Action</th>
                  <th className="py-2">Category</th>
                  <th className="py-2">Source IP</th>
                  <th className="py-2">User</th>
                  <th className="py-2">Host</th>
                  <th className="py-2">Threat</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <>
                    <tr key={event.id} className="border-b border-aegis-border/50 hover:bg-aegis-bg/40">
                      <td className="py-2 text-xs text-slate-400">
                        {formatDateTime(event.event_timestamp)}
                      </td>
                      <td className="py-2 text-slate-200">{event.event_action ?? "—"}</td>
                      <td className="py-2 text-slate-400">{event.event_category ?? "—"}</td>
                      <td className="py-2 font-mono text-xs text-slate-300">{event.source_ip ?? "—"}</td>
                      <td className="py-2 text-slate-300">{event.user_name ?? "—"}</td>
                      <td className="py-2 text-slate-300">{event.host_name ?? "—"}</td>
                      <td className="py-2">
                        {event.threat_matched ? (
                          <span className="text-xs font-medium text-red-400">match</span>
                        ) : (
                          <span className="text-xs text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-2">
                        <button
                          onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                          className="text-xs text-aegis-accent hover:underline"
                        >
                          {expanded === event.id ? "Hide" : "ECS"}
                        </button>
                      </td>
                    </tr>
                    {expanded === event.id && (
                      <tr key={`${event.id}-ecs`}>
                        <td colSpan={8} className="bg-aegis-bg/60 p-3">
                          <pre className="overflow-x-auto text-xs text-slate-400">
                            {JSON.stringify(event.ecs, null, 2)}
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
    </>
  );
}

function DeadLetterQueue() {
  const [rows, setRows] = useState<DeadLetter[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showResolved, setShowResolved] = useState(false);
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listDeadLetters({
        limit: PAGE_SIZE,
        offset,
        resolved: showResolved ? undefined : false,
      });
      setRows(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load the dead-letter queue"));
    } finally {
      setLoading(false);
    }
  }, [offset, showResolved, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function replay(ids?: number[]) {
    try {
      const result = await replayDeadLetters(ids);
      if (result.attempted === 0) {
        toast.info("Nothing to replay");
      } else {
        toast.success(
          `Replayed ${result.attempted}: ${result.succeeded} succeeded, ${result.still_failing} still failing`,
        );
      }
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Replay failed"));
    }
  }

  return (
    <Panel
      title="Dead-letter queue"
      actions={
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={showResolved}
              onChange={(e) => {
                setOffset(0);
                setShowResolved(e.target.checked);
              }}
            />
            Include resolved
          </label>
          <Button tone="primary" onClick={() => replay()} disabled={rows.length === 0}>
            Replay all unresolved
          </Button>
        </div>
      }
    >
      <p className="mb-3 text-xs text-slate-500">
        Events that failed ECS normalization. Fix the upstream producer, then replay — a payload that
        still fails is marked with its reason rather than being dead-lettered again.
      </p>

      {loading ? (
        <Loading />
      ) : rows.length === 0 ? (
        <EmptyState message="No dead-lettered events." hint="Every ingested event normalized cleanly." />
      ) : (
        <div className="space-y-2">
          {rows.map((row) => (
            <div key={row.id} className="rounded border border-aegis-border bg-aegis-bg p-3">
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm text-red-300">{row.error_message}</span>
                <div className="flex items-center gap-3 text-xs text-slate-500">
                  <span>{formatDateTime(row.received_at)}</span>
                  {row.resolved ? (
                    <span className="text-emerald-400">resolved</span>
                  ) : (
                    <Button onClick={() => replay([row.id])}>Replay</Button>
                  )}
                </div>
              </div>
              {row.replay_status && !row.resolved && (
                <div className="mb-1 text-xs text-amber-400">Last replay: {row.replay_status}</div>
              )}
              <pre className="overflow-x-auto text-xs text-slate-400">
                {JSON.stringify(row.raw_payload, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      )}
      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
    </Panel>
  );
}
