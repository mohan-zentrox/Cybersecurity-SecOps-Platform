import { useCallback, useEffect, useState } from "react";

import { errorMessage, type Severity } from "@/api/client";
import {
  createIoc,
  deactivateIoc,
  IOC_TYPES,
  listFeeds,
  listIocs,
  pollFeed,
  type IOC,
  type IOCType,
  type ThreatFeed,
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
  StatusBadge,
} from "@/components/ui";
import { RULE_AUTHORS, useHasRole } from "@/store/authStore";

const PAGE_SIZE = 25;

const TYPE_OPTIONS = [
  { value: "", label: "Any type" },
  ...IOC_TYPES.map((t) => ({ value: t, label: t.replace("_", " ") })),
];

const ACTIVE_OPTIONS = [
  { value: "true", label: "Active only" },
  { value: "false", label: "Inactive only" },
  { value: "", label: "All indicators" },
];

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export default function ThreatIntel() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);

  const [type, setType] = useState("");
  const [active, setActive] = useState("true");
  const [search, setSearch] = useState("");

  const [adding, setAdding] = useState(false);
  const [newType, setNewType] = useState<IOCType>("ip");
  const [newValue, setNewValue] = useState("");
  const [newSeverity, setNewSeverity] = useState<Severity>("medium");
  const [newConfidence, setNewConfidence] = useState(75);
  const [newDescription, setNewDescription] = useState("");

  const canAuthor = useHasRole(...RULE_AUTHORS);
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listIocs({
        limit: PAGE_SIZE,
        offset,
        type: type || undefined,
        active: active === "" ? undefined : active === "true",
        search: search || undefined,
      });
      setIocs(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load indicators"));
    } finally {
      setLoading(false);
    }
  }, [offset, type, active, search, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const loadFeeds = useCallback(async () => {
    try {
      setFeeds(await listFeeds());
    } catch {
      setFeeds([]);
    }
  }, []);

  useEffect(() => {
    loadFeeds();
  }, [loadFeeds]);

  async function addIndicator() {
    if (!newValue.trim()) {
      toast.error("An indicator needs a value");
      return;
    }
    try {
      await createIoc({
        type: newType,
        value: newValue.trim(),
        confidence: newConfidence,
        severity: newSeverity,
        description: newDescription,
      });
      toast.success("Indicator saved");
      setNewValue("");
      setNewDescription("");
      setAdding(false);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not save indicator"));
    }
  }

  async function deactivate(ioc: IOC) {
    try {
      await deactivateIoc(ioc.id);
      toast.success(`${ioc.value} deactivated`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not deactivate indicator"));
    }
  }

  async function poll(feed: ThreatFeed) {
    try {
      const result = await pollFeed(feed.id);
      if (result.error) {
        toast.error(`${feed.name}: ${result.error}`);
      } else {
        toast.success(`${feed.name}: ${result.created} new, ${result.updated} updated`);
      }
      loadFeeds();
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Feed poll failed"));
    }
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Threat Intelligence"
        subtitle={`${total} indicator${total === 1 ? "" : "s"} · matched against every ingested event`}
        actions={
          canAuthor ? (
            <Button tone="primary" onClick={() => setAdding(!adding)}>
              {adding ? "Cancel" : "Add indicator"}
            </Button>
          ) : undefined
        }
      />

      {adding && canAuthor && (
        <Panel title="New indicator" className="mb-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <label className="block text-sm">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Type</span>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value as IOCType)}
                className={`${inputClass} w-full`}
              >
                {IOC_TYPES.map((value) => (
                  <option key={value} value={value}>
                    {value.replace("_", " ")}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm lg:col-span-2">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Value</span>
              <input
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                className={`${inputClass} w-full`}
                placeholder="203.0.113.66"
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Severity</span>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as Severity)}
                className={`${inputClass} w-full`}
              >
                {SEVERITIES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                Confidence
              </span>
              <input
                type="number"
                min={0}
                max={100}
                value={newConfidence}
                onChange={(e) => setNewConfidence(Number(e.target.value))}
                className={`${inputClass} w-full`}
              />
            </label>
            <label className="block text-sm sm:col-span-2 lg:col-span-5">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                Description
              </span>
              <input
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                className={`${inputClass} w-full`}
                placeholder="Where this came from and why it is malicious"
              />
            </label>
          </div>
          <p className="mt-3 text-xs text-amber-400">
            A wrong indicator is expensive: marking your own egress IP malicious turns every outbound
            connection into an alert.
          </p>
          <div className="mt-3">
            <Button tone="primary" onClick={addIndicator}>
              Save indicator
            </Button>
          </div>
        </Panel>
      )}

      {feeds.length > 0 && (
        <Panel title="Feeds" className="mb-4">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="py-2">Name</th>
                  <th className="py-2">Kind</th>
                  <th className="py-2">Last polled</th>
                  <th className="py-2">Status</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {feeds.map((feed) => (
                  <tr key={feed.id} className="border-b border-aegis-border/50">
                    <td className="py-2 text-slate-200">{feed.name}</td>
                    <td className="py-2 text-slate-400">{feed.kind}</td>
                    <td className="py-2 text-xs text-slate-400">{formatDateTime(feed.last_polled_at)}</td>
                    <td className="py-2 text-xs text-slate-400">{feed.last_poll_status ?? "—"}</td>
                    <td className="py-2 text-right">
                      {canAuthor && feed.kind !== "manual" && (
                        <Button onClick={() => poll(feed)}>Poll now</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={(e) => {
              setOffset(0);
              setSearch(e.target.value);
            }}
            placeholder="Search indicator value…"
            className={`${inputClass} w-64`}
            aria-label="Search indicators"
          />
          <Select
            value={type}
            onChange={(value) => {
              setOffset(0);
              setType(value);
            }}
            options={TYPE_OPTIONS}
            label="Type"
          />
          <Select
            value={active}
            onChange={(value) => {
              setOffset(0);
              setActive(value);
            }}
            options={ACTIVE_OPTIONS}
            label="State"
          />
        </div>
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : iocs.length === 0 ? (
          <EmptyState message="No indicators match these filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  <th className="py-2">Type</th>
                  <th className="py-2">Value</th>
                  <th className="py-2">Severity</th>
                  <th className="py-2">Confidence</th>
                  <th className="py-2">Hits</th>
                  <th className="py-2">Source</th>
                  <th className="py-2">Last seen</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="border-b border-aegis-border/50 hover:bg-aegis-bg/40">
                    <td className="py-2 text-xs text-slate-400">{ioc.type.replace("_", " ")}</td>
                    <td className="py-2 font-mono text-xs text-slate-200">
                      {ioc.value}
                      {ioc.description && (
                        <div className="mt-0.5 font-sans text-xs text-slate-500">{ioc.description}</div>
                      )}
                    </td>
                    <td className="py-2">
                      <StatusBadge value={ioc.severity} />
                    </td>
                    <td className="py-2 text-slate-300">{ioc.confidence}</td>
                    <td className={`py-2 ${ioc.match_count > 0 ? "text-red-400" : "text-slate-500"}`}>
                      {ioc.match_count}
                    </td>
                    <td className="py-2 text-xs text-slate-400">{ioc.source}</td>
                    <td className="py-2 text-xs text-slate-400">{formatDateTime(ioc.last_seen)}</td>
                    <td className="py-2 text-right">
                      {canAuthor && ioc.active && (
                        <Button tone="danger" onClick={() => deactivate(ioc)}>
                          Deactivate
                        </Button>
                      )}
                      {!ioc.active && <span className="text-xs text-slate-600">inactive</span>}
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
