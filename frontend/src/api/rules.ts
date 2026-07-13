import { apiClient } from "./client";

export interface RuleCondition {
  field: string;
  operator: "eq" | "neq" | "contains" | "gt" | "gte" | "lt" | "lte" | "in";
  value: unknown;
}

export interface DetectionRule {
  id: number;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  mitre_technique_id: string | null;
  logic: {
    match: "all" | "any";
    conditions: RuleCondition[];
    threshold?: { count: number; window_seconds: number; group_by?: string };
  };
  enabled: boolean;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export async function listRules(): Promise<DetectionRule[]> {
  const { data } = await apiClient.get<DetectionRule[]>("/rules");
  return data;
}

export async function testRule(ruleId: number, sampleEvents: Record<string, unknown>[]) {
  const { data } = await apiClient.post(`/rules/${ruleId}/test`, { sample_events: sampleEvents });
  return data;
}
