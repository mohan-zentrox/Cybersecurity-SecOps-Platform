import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { errorMessage, type Severity } from "@/api/client";
import {
  COMMON_FIELDS,
  createRule,
  getRule,
  RULE_OPERATORS,
  testRule,
  updateRule,
  type RuleCondition,
  type RuleLogic,
  type RuleOperator,
  type RuleTestResult,
} from "@/api/rules";
import { useToast } from "@/components/Toast";
import { Button, inputClass, Loading, PageHeader, Panel } from "@/components/ui";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

const DEFAULT_LOGIC: RuleLogic = {
  match: "all",
  conditions: [{ field: "event.action", operator: "eq", value: "" }],
  threshold: null,
};

const DEFAULT_SAMPLE = JSON.stringify(
  [
    {
      "@timestamp": new Date().toISOString(),
      event: { action: "logon_failed", category: "authentication" },
      source: { ip: "203.0.113.66" },
      user: { name: "svc_backup" },
    },
  ],
  null,
  2,
);

/**
 * Create/edit a detection rule.
 *
 * Values are typed as strings in the form and coerced on submit: the API
 * accepts any JSON for `value`, and a rule comparing `threat.indicator.matched`
 * to the string "true" would silently never fire, which is the kind of bug a
 * detection engineer should not have to debug at 3am.
 */
function coerceValue(raw: string, operator: RuleOperator): unknown {
  if (operator === "in") {
    return raw
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }
  if (operator === "exists") return true;
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (raw !== "" && !Number.isNaN(Number(raw)) && /^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
  return raw;
}

function displayValue(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value === null || value === undefined) return "";
  return String(value);
}

export default function RuleEditor() {
  const { ruleId } = useParams();
  const isNew = ruleId === undefined || ruleId === "new";
  const navigate = useNavigate();
  const toast = useToast();

  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [mitre, setMitre] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [logic, setLogic] = useState<RuleLogic>(DEFAULT_LOGIC);

  const [sampleText, setSampleText] = useState(DEFAULT_SAMPLE);
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);

  const load = useCallback(async () => {
    if (isNew) return;
    setLoading(true);
    try {
      const rule = await getRule(Number(ruleId));
      setName(rule.name);
      setDescription(rule.description);
      setSeverity(rule.severity);
      setMitre(rule.mitre_technique_id ?? "");
      setEnabled(rule.enabled);
      setLogic({
        match: rule.logic.match ?? "all",
        conditions: rule.logic.conditions ?? [],
        threshold: rule.logic.threshold ?? null,
      });
    } catch (error) {
      toast.error(errorMessage(error, "Could not load rule"));
    } finally {
      setLoading(false);
    }
  }, [isNew, ruleId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  function updateCondition(index: number, patch: Partial<RuleCondition>) {
    setLogic((current) => ({
      ...current,
      conditions: current.conditions.map((condition, i) =>
        i === index ? { ...condition, ...patch } : condition,
      ),
    }));
  }

  function addCondition() {
    setLogic((current) => ({
      ...current,
      conditions: [...current.conditions, { field: "", operator: "eq", value: "" }],
    }));
  }

  function removeCondition(index: number) {
    setLogic((current) => ({
      ...current,
      conditions: current.conditions.filter((_, i) => i !== index),
    }));
  }

  function buildLogic(): RuleLogic {
    return {
      match: logic.match,
      conditions: logic.conditions.map((condition) => ({
        ...condition,
        value: coerceValue(displayValue(condition.value), condition.operator),
      })),
      threshold: logic.threshold
        ? {
            count: Number(logic.threshold.count) || 1,
            window_seconds: Number(logic.threshold.window_seconds) || 60,
            group_by: logic.threshold.group_by || null,
          }
        : null,
    };
  }

  async function save() {
    if (!name.trim()) {
      toast.error("A rule needs a name");
      return;
    }
    if (logic.conditions.length === 0) {
      toast.error("A rule needs at least one condition");
      return;
    }

    setSaving(true);
    try {
      const payload = {
        name: name.trim(),
        description,
        severity,
        mitre_technique_id: mitre.trim() || null,
        logic: buildLogic(),
        enabled,
      };
      if (isNew) {
        const created = await createRule(payload);
        toast.success(`Created "${created.name}"`);
        navigate(`/rules/${created.id}`);
      } else {
        await updateRule(Number(ruleId), payload);
        toast.success("Rule saved — evaluation watermark reset so history is re-scanned");
      }
    } catch (error) {
      toast.error(errorMessage(error, "Could not save rule"));
    } finally {
      setSaving(false);
    }
  }

  async function runTest() {
    if (isNew) {
      toast.info("Save the rule first — the test harness runs against a stored rule");
      return;
    }
    let samples: Record<string, unknown>[];
    try {
      samples = JSON.parse(sampleText);
      if (!Array.isArray(samples)) throw new Error("Sample events must be a JSON array");
    } catch (error) {
      toast.error(`Sample events are not valid JSON: ${(error as Error).message}`);
      return;
    }

    try {
      const result = await testRule(Number(ruleId), samples);
      setTestResult(result);
      toast.success(
        result.matched_count > 0
          ? `Rule matched ${result.matched_count} time(s)`
          : "Rule did not match the sample events",
      );
    } catch (error) {
      toast.error(errorMessage(error, "Test run failed"));
    }
  }

  if (loading) return <Loading label="Loading rule…" />;

  // `threshold` is optional AND nullable, so narrow once here rather than
  // sprinkling non-null assertions through the JSX below.
  const threshold = logic.threshold ?? null;

  return (
    <div className="p-6">
      <PageHeader
        title={isNew ? "New detection rule" : `Edit rule #${ruleId}`}
        subtitle="Conditions are evaluated against ECS-normalized events."
        actions={
          <>
            <Button onClick={() => navigate("/rules")}>Back</Button>
            <Button tone="primary" onClick={save} disabled={saving}>
              {saving ? "Saving…" : "Save rule"}
            </Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Panel title="Definition">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block text-sm sm:col-span-2">
                <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Name</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={`${inputClass} w-full`}
                  placeholder="Brute force: repeated failed logons"
                />
              </label>

              <label className="block text-sm sm:col-span-2">
                <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                  Description
                </span>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  className={`${inputClass} w-full`}
                  placeholder="What this detects, and why it matters."
                />
              </label>

              <label className="block text-sm">
                <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Severity</span>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as Severity)}
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
                  MITRE technique
                </span>
                <input
                  value={mitre}
                  onChange={(e) => setMitre(e.target.value)}
                  className={`${inputClass} w-full`}
                  placeholder="T1110"
                />
              </label>

              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                Enabled
              </label>
            </div>
          </Panel>

          <Panel
            title="Conditions"
            actions={
              <select
                value={logic.match}
                onChange={(e) => setLogic({ ...logic, match: e.target.value as "all" | "any" })}
                className={`${inputClass} text-xs`}
              >
                <option value="all">Match ALL (AND)</option>
                <option value="any">Match ANY (OR)</option>
              </select>
            }
          >
            <datalist id="ecs-fields">
              {COMMON_FIELDS.map((field) => (
                <option key={field} value={field} />
              ))}
            </datalist>

            <div className="space-y-2">
              {logic.conditions.map((condition, index) => (
                <div key={index} className="flex flex-wrap items-center gap-2">
                  <input
                    list="ecs-fields"
                    value={condition.field}
                    onChange={(e) => updateCondition(index, { field: e.target.value })}
                    className={`${inputClass} flex-1 min-w-[12rem]`}
                    placeholder="event.action"
                    aria-label={`Condition ${index + 1} field`}
                  />
                  <select
                    value={condition.operator}
                    onChange={(e) => updateCondition(index, { operator: e.target.value as RuleOperator })}
                    className={inputClass}
                    aria-label={`Condition ${index + 1} operator`}
                  >
                    {RULE_OPERATORS.map((operator) => (
                      <option key={operator.value} value={operator.value}>
                        {operator.label}
                      </option>
                    ))}
                  </select>
                  <input
                    value={displayValue(condition.value)}
                    onChange={(e) => updateCondition(index, { value: e.target.value })}
                    className={`${inputClass} flex-1 min-w-[10rem]`}
                    placeholder={condition.operator === "in" ? "a, b, c" : "logon_failed"}
                    disabled={condition.operator === "exists"}
                    aria-label={`Condition ${index + 1} value`}
                  />
                  <Button
                    tone="danger"
                    onClick={() => removeCondition(index)}
                    disabled={logic.conditions.length === 1}
                  >
                    Remove
                  </Button>
                </div>
              ))}
            </div>
            <div className="mt-3">
              <Button onClick={addCondition}>Add condition</Button>
            </div>
            <p className="mt-3 text-xs text-slate-500">
              Values are coerced automatically: <code>true</code>/<code>false</code> become booleans and
              numeric text becomes a number, so a comparison against{" "}
              <code>threat.indicator.matched</code> works as expected.
            </p>
          </Panel>

          <Panel
            title="Threshold"
            actions={
              <label className="flex items-center gap-2 text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={Boolean(threshold)}
                  onChange={(e) =>
                    setLogic({
                      ...logic,
                      threshold: e.target.checked
                        ? { count: 5, window_seconds: 300, group_by: "source.ip" }
                        : null,
                    })
                  }
                />
                Enable threshold
              </label>
            }
          >
            {!threshold ? (
              <p className="text-xs text-slate-500">
                Without a threshold, every matching event raises its own alert. Enable a threshold for
                burst detection, e.g. &ldquo;5 failed logons from one IP in 5 minutes&rdquo;.
              </p>
            ) : (
              <div className="grid gap-3 sm:grid-cols-3">
                <label className="block text-sm">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Count</span>
                  <input
                    type="number"
                    min={1}
                    value={threshold.count}
                    onChange={(e) =>
                      setLogic({
                        ...logic,
                        threshold: { ...threshold, count: Number(e.target.value) },
                      })
                    }
                    className={`${inputClass} w-full`}
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                    Window (seconds)
                  </span>
                  <input
                    type="number"
                    min={1}
                    value={threshold.window_seconds}
                    onChange={(e) =>
                      setLogic({
                        ...logic,
                        threshold: { ...threshold, window_seconds: Number(e.target.value) },
                      })
                    }
                    className={`${inputClass} w-full`}
                  />
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                    Group by (optional)
                  </span>
                  <input
                    list="ecs-fields"
                    value={threshold.group_by ?? ""}
                    onChange={(e) =>
                      setLogic({
                        ...logic,
                        threshold: { ...threshold, group_by: e.target.value },
                      })
                    }
                    className={`${inputClass} w-full`}
                    placeholder="source.ip"
                  />
                </label>
              </div>
            )}
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Test harness" actions={<Button onClick={runTest}>Run test</Button>}>
            <p className="mb-2 text-xs text-slate-500">
              Runs the saved rule against sample events. Never persists alerts.
            </p>
            <textarea
              value={sampleText}
              onChange={(e) => setSampleText(e.target.value)}
              rows={14}
              spellCheck={false}
              className={`${inputClass} w-full font-mono text-xs`}
              aria-label="Sample events JSON"
            />
            {testResult && (
              <div className="mt-3 rounded bg-aegis-bg p-3 text-xs">
                <div
                  className={testResult.matched_count > 0 ? "text-emerald-400" : "text-slate-400"}
                >
                  {testResult.matched_count} match(es)
                </div>
                {testResult.matches.length > 0 && (
                  <pre className="mt-2 overflow-x-auto text-slate-400">
                    {JSON.stringify(testResult.matches, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Generated logic">
            <pre className="overflow-x-auto rounded bg-aegis-bg p-3 text-xs text-slate-400">
              {JSON.stringify(buildLogic(), null, 2)}
            </pre>
          </Panel>
        </div>
      </div>
    </div>
  );
}
