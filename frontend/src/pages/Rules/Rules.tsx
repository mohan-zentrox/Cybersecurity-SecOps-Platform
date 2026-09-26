import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { errorMessage } from "@/api/client";
import {
  deleteRule,
  evaluateRule,
  listRules,
  toggleRule,
  type DetectionRule,
} from "@/api/rules";
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

const PAGE_SIZE = 20;

const ENABLED_OPTIONS = [
  { value: "", label: "All rules" },
  { value: "true", label: "Enabled only" },
  { value: "false", label: "Disabled only" },
];

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState("");
  const [search, setSearch] = useState("");

  const canAuthor = useHasRole(...RULE_AUTHORS);
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listRules({
        limit: PAGE_SIZE,
        offset,
        enabled: enabled === "" ? undefined : enabled === "true",
        search: search || undefined,
      });
      setRules(page.items);
      setTotal(page.total);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load detection rules"));
    } finally {
      setLoading(false);
    }
  }, [offset, enabled, search, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onToggle(rule: DetectionRule) {
    try {
      await toggleRule(rule.id, !rule.enabled);
      toast.success(`${rule.name} ${rule.enabled ? "disabled" : "enabled"}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not change rule state"));
    }
  }

  async function onEvaluate(rule: DetectionRule) {
    try {
      const result = await evaluateRule(rule.id);
      toast.success(
        `Scanned ${result.events_scanned} event(s); ${result.alerts_created} new alert(s) raised`,
      );
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Evaluation failed"));
    }
  }

  async function onDelete(rule: DetectionRule) {
    try {
      await deleteRule(rule.id);
      toast.success(`Deleted ${rule.name}`);
      refresh();
    } catch (error) {
      // A rule with alerts attached returns 409 with an explanation; surface it.
      toast.error(errorMessage(error, "Could not delete rule"));
    }
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Detection Rules"
        subtitle={`${total} rule${total === 1 ? "" : "s"} defined`}
        actions={
          canAuthor ? (
            <Link to="/rules/new">
              <Button tone="primary">New rule</Button>
            </Link>
          ) : undefined
        }
      />

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={(e) => {
              setOffset(0);
              setSearch(e.target.value);
            }}
            placeholder="Search rule name…"
            className={`${inputClass} w-64`}
            aria-label="Search rules"
          />
          <Select
            value={enabled}
            onChange={(value) => {
              setOffset(0);
              setEnabled(value);
            }}
            options={ENABLED_OPTIONS}
            label="State"
          />
        </div>
      </Panel>

      {loading ? (
        <Loading />
      ) : rules.length === 0 ? (
        <Panel>
          <EmptyState
            message="No detection rules match these filters."
            hint={canAuthor ? "Create one to start detecting on ingested telemetry." : undefined}
          />
        </Panel>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => (
            <Panel key={rule.id}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="mb-1 flex flex-wrap items-center gap-3">
                    <Link
                      to={`/rules/${rule.id}`}
                      className="font-medium text-slate-100 hover:text-aegis-accent"
                    >
                      {rule.name}
                    </Link>
                    <StatusBadge value={rule.severity} />
                    {rule.mitre_technique_id && (
                      <a
                        href={`https://attack.mitre.org/techniques/${rule.mitre_technique_id}/`}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-xs text-slate-500 hover:text-aegis-accent"
                      >
                        MITRE {rule.mitre_technique_id}
                      </a>
                    )}
                    <span className={`text-xs ${rule.enabled ? "text-emerald-400" : "text-slate-500"}`}>
                      {rule.enabled ? "enabled" : "disabled"}
                    </span>
                  </div>
                  <p className="mb-2 text-sm text-slate-400">{rule.description || "No description."}</p>
                  <div className="flex flex-wrap gap-4 text-xs text-slate-500">
                    <span>{rule.alert_count} alert(s) raised</span>
                    <span>Last evaluated: {formatDateTime(rule.last_evaluated_at)}</span>
                    <span>
                      {rule.logic.conditions.length} condition(s)
                      {rule.logic.threshold
                        ? `, threshold ${rule.logic.threshold.count}/${rule.logic.threshold.window_seconds}s`
                        : ""}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button onClick={() => onEvaluate(rule)}>Evaluate now</Button>
                  {canAuthor && (
                    <>
                      <Link to={`/rules/${rule.id}`}>
                        <Button>Edit</Button>
                      </Link>
                      <Button onClick={() => onToggle(rule)}>{rule.enabled ? "Disable" : "Enable"}</Button>
                      <Button tone="danger" onClick={() => onDelete(rule)}>
                        Delete
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </Panel>
          ))}
        </div>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
    </div>
  );
}
