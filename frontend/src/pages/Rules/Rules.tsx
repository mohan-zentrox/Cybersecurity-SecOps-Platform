import { useEffect, useState } from "react";

import { type DetectionRule, listRules, testRule } from "@/api/rules";
import { StatusBadge } from "@/components/StatusBadge";

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [testResult, setTestResult] = useState<Record<number, string>>({});

  useEffect(() => {
    listRules().then(setRules);
  }, []);

  async function runSampleTest(rule: DetectionRule) {
    // Minimal built-in sample event matching the rule's first condition, purely
    // to demonstrate the persistence-free test-harness endpoint from the UI.
    const firstCondition = rule.logic.conditions[0];
    const sample = { event: { action: "sample" }, source: { ip: "127.0.0.1" }, "@timestamp": new Date().toISOString() };
    if (firstCondition) {
      const [top, key] = firstCondition.field.split(".");
      (sample as any)[top] = { ...(sample as any)[top], [key]: firstCondition.value };
    }
    const result = await testRule(rule.id, [sample]);
    setTestResult((prev) => ({ ...prev, [rule.id]: JSON.stringify(result) }));
  }

  return (
    <div className="p-6">
      <h1 className="mb-4 text-lg font-semibold">Detection Rules</h1>
      <div className="space-y-3">
        {rules.map((rule) => (
          <div key={rule.id} className="rounded border border-aegis-border bg-aegis-panel p-4">
            <div className="mb-1 flex items-center gap-3">
              <h2 className="font-medium">{rule.name}</h2>
              <StatusBadge value={rule.severity} />
              {rule.mitre_technique_id && (
                <span className="text-xs text-slate-500">MITRE {rule.mitre_technique_id}</span>
              )}
              <span className={`text-xs ${rule.enabled ? "text-emerald-400" : "text-slate-500"}`}>
                {rule.enabled ? "enabled" : "disabled"}
              </span>
            </div>
            <p className="mb-2 text-sm text-slate-400">{rule.description}</p>
            <button
              onClick={() => runSampleTest(rule)}
              className="rounded border border-aegis-border px-2 py-1 text-xs hover:border-aegis-accent"
            >
              Run test harness on sample event
            </button>
            {testResult[rule.id] && (
              <pre className="mt-2 overflow-x-auto rounded bg-aegis-bg p-2 text-xs text-slate-300">
                {testResult[rule.id]}
              </pre>
            )}
          </div>
        ))}
        {rules.length === 0 && <p className="text-slate-500">No rules yet.</p>}
      </div>
    </div>
  );
}
