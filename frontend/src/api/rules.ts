import { apiClient, type Page, queryParams, type Severity } from "./client";

export type RuleOperator =
  | "eq"
  | "neq"
  | "contains"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "in"
  | "regex"
  | "exists";

export const RULE_OPERATORS: { value: RuleOperator; label: string }[] = [
  { value: "eq", label: "equals" },
  { value: "neq", label: "does not equal" },
  { value: "contains", label: "contains" },
  { value: "regex", label: "matches regex" },
  { value: "in", label: "is one of" },
  { value: "gt", label: ">" },
  { value: "gte", label: ">=" },
  { value: "lt", label: "<" },
  { value: "lte", label: "<=" },
  { value: "exists", label: "exists" },
];

/** ECS paths that appear in normalized events; offered as field suggestions. */
export const COMMON_FIELDS = [
  "event.action",
  "event.category",
  "event.outcome",
  "source.ip",
  "destination.ip",
  "user.name",
  "host.name",
  "process.name",
  "process.command_line",
  "group.name",
  "dns.question.name",
  "threat.indicator.matched",
  "threat.indicator.max_confidence",
];

export interface RuleCondition {
  field: string;
  operator: RuleOperator;
  value: unknown;
}

export interface RuleThreshold {
  count: number;
  window_seconds: number;
  group_by?: string | null;
}

export interface RuleLogic {
  match: "all" | "any";
  conditions: RuleCondition[];
  threshold?: RuleThreshold | null;
}

export interface DetectionRule {
  id: number;
  name: string;
  description: string;
  severity: Severity;
  mitre_technique_id: string | null;
  logic: RuleLogic;
  enabled: boolean;
  eval_watermark: string | null;
  last_evaluated_at: string | null;
  alert_count: number;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface RuleInput {
  name: string;
  description?: string;
  severity: Severity;
  mitre_technique_id?: string | null;
  logic: RuleLogic;
  enabled?: boolean;
}

export async function listRules(
  filters: { enabled?: boolean; severity?: string; search?: string; limit?: number; offset?: number } = {},
): Promise<Page<DetectionRule>> {
  const { data } = await apiClient.get<Page<DetectionRule>>("/rules", { params: queryParams(filters) });
  return data;
}

export async function getRule(ruleId: number): Promise<DetectionRule> {
  const { data } = await apiClient.get<DetectionRule>(`/rules/${ruleId}`);
  return data;
}

export async function createRule(input: RuleInput): Promise<DetectionRule> {
  const { data } = await apiClient.post<DetectionRule>("/rules", input);
  return data;
}

export async function updateRule(ruleId: number, input: Partial<RuleInput>): Promise<DetectionRule> {
  const { data } = await apiClient.patch<DetectionRule>(`/rules/${ruleId}`, input);
  return data;
}

export async function toggleRule(ruleId: number, enabled: boolean): Promise<DetectionRule> {
  const { data } = await apiClient.patch<DetectionRule>(`/rules/${ruleId}/enabled`, { enabled });
  return data;
}

export async function deleteRule(ruleId: number): Promise<void> {
  await apiClient.delete(`/rules/${ruleId}`);
}

export interface RuleTestMatch {
  group_key: string | null;
  event_ids: number[];
  sample_event_id: number;
}

export interface RuleTestResult {
  rule_id: number;
  matched_count: number;
  matches: RuleTestMatch[];
}

export async function testRule(
  ruleId: number,
  sampleEvents: Record<string, unknown>[],
): Promise<RuleTestResult> {
  const { data } = await apiClient.post<RuleTestResult>(`/rules/${ruleId}/test`, {
    sample_events: sampleEvents,
  });
  return data;
}

export interface RuleEvaluateResult {
  rule_id: number;
  matches_found: number;
  alerts_created: number;
  alert_ids: number[];
  events_scanned: number;
}

export async function evaluateRule(ruleId: number, fullRescan = false): Promise<RuleEvaluateResult> {
  const { data } = await apiClient.post<RuleEvaluateResult>(
    `/rules/${ruleId}/evaluate`,
    {},
    { params: { full_rescan: fullRescan } },
  );
  return data;
}
