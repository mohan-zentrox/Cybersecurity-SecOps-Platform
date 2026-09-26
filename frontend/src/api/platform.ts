/**
 * API clients for the remaining platform surfaces: users, events and the
 * dead-letter queue, threat intel, vulnerabilities, compliance,
 * notifications, audit, and KPIs.
 *
 * Kept in one module because each is a thin typed wrapper; splitting them
 * into eight files would add imports without adding clarity.
 */
import { apiClient, type Page, queryParams, type Severity } from "./client";
import type { Role } from "@/store/authStore";

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export interface User {
  id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export async function listUsers(
  filters: { role?: string; is_active?: boolean; limit?: number; offset?: number } = {},
): Promise<Page<User>> {
  const { data } = await apiClient.get<Page<User>>("/users", {
    params: queryParams({ limit: 200, ...filters }),
  });
  return data;
}

export async function createUser(input: {
  username: string;
  email: string;
  password: string;
  role: Role;
}): Promise<User> {
  const { data } = await apiClient.post<User>("/users", input);
  return data;
}

export async function updateUser(
  userId: number,
  input: { email?: string; role?: Role; is_active?: boolean },
): Promise<User> {
  const { data } = await apiClient.patch<User>(`/users/${userId}`, input);
  return data;
}

export async function deactivateUser(userId: number): Promise<User> {
  const { data } = await apiClient.delete<User>(`/users/${userId}`);
  return data;
}

export async function resetUserPassword(userId: number, newPassword: string): Promise<User> {
  const { data } = await apiClient.post<User>(`/users/${userId}/password-reset`, {
    new_password: newPassword,
  });
  return data;
}

export async function changeOwnPassword(currentPassword: string, newPassword: string): Promise<User> {
  const { data } = await apiClient.post<User>("/users/me/password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
  return data;
}

// ---------------------------------------------------------------------------
// Events + dead letters
// ---------------------------------------------------------------------------

export interface NormalizedEvent {
  id: number;
  event_action: string | null;
  event_category: string | null;
  event_outcome: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  user_name: string | null;
  host_name: string | null;
  event_timestamp: string;
  ingested_at: string;
  threat_matched: boolean;
  ecs: Record<string, unknown>;
}

export interface EventFilters {
  event_action?: string;
  event_category?: string;
  source_ip?: string;
  user_name?: string;
  host_name?: string;
  threat_matched?: boolean;
  limit?: number;
  offset?: number;
}

export async function searchEvents(filters: EventFilters = {}): Promise<Page<NormalizedEvent>> {
  const { data } = await apiClient.get<Page<NormalizedEvent>>("/events", {
    params: queryParams(filters),
  });
  return data;
}

export interface IngestSummary {
  accepted: number;
  dead_lettered: number;
  threat_matches: number;
  stored_event_ids: number[];
  alerts_created: number[];
  queued_only: boolean;
}

export async function ingestEvents(events: Record<string, unknown>[]): Promise<IngestSummary> {
  const { data } = await apiClient.post<IngestSummary>("/events/ingest", { events });
  return data;
}

export interface DeadLetter {
  id: number;
  raw_payload: Record<string, unknown>;
  error_message: string;
  received_at: string;
  replayed_at: string | null;
  replay_status: string | null;
  resolved: boolean;
}

export async function listDeadLetters(
  filters: { resolved?: boolean; limit?: number; offset?: number } = {},
): Promise<Page<DeadLetter>> {
  const { data } = await apiClient.get<Page<DeadLetter>>("/events/dead-letters", {
    params: queryParams(filters),
  });
  return data;
}

export interface ReplayResult {
  attempted: number;
  succeeded: number;
  still_failing: number;
  alerts_created: number[];
}

export async function replayDeadLetters(deadLetterIds?: number[]): Promise<ReplayResult> {
  const { data } = await apiClient.post<ReplayResult>("/events/dead-letters/replay", {
    dead_letter_ids: deadLetterIds,
  });
  return data;
}

// ---------------------------------------------------------------------------
// Threat intel
// ---------------------------------------------------------------------------

export type IOCType = "ip" | "domain" | "url" | "file_hash" | "email";

export const IOC_TYPES: IOCType[] = ["ip", "domain", "url", "file_hash", "email"];

export interface IOC {
  id: number;
  type: IOCType;
  value: string;
  confidence: number;
  severity: Severity;
  description: string;
  tags: string[];
  source: string;
  feed_id: number | null;
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
  active: boolean;
  match_count: number;
}

export async function listIocs(
  filters: {
    type?: string;
    severity?: string;
    active?: boolean;
    search?: string;
    min_confidence?: number;
    limit?: number;
    offset?: number;
  } = {},
): Promise<Page<IOC>> {
  const { data } = await apiClient.get<Page<IOC>>("/threat-intel/iocs", {
    params: queryParams(filters),
  });
  return data;
}

export async function createIoc(input: {
  type: IOCType;
  value: string;
  confidence: number;
  severity: Severity;
  description?: string;
  tags?: string[];
}): Promise<IOC> {
  const { data } = await apiClient.post<IOC>("/threat-intel/iocs", input);
  return data;
}

export async function deactivateIoc(iocId: number): Promise<void> {
  await apiClient.delete(`/threat-intel/iocs/${iocId}`);
}

export interface ThreatFeed {
  id: number;
  name: string;
  kind: string;
  url: string | null;
  enabled: boolean;
  default_confidence: number;
  last_polled_at: string | null;
  last_poll_status: string | null;
  last_poll_indicator_count: number;
  created_at: string;
}

export async function listFeeds(): Promise<ThreatFeed[]> {
  const { data } = await apiClient.get<ThreatFeed[]>("/threat-intel/feeds");
  return data;
}

export async function pollFeed(feedId: number) {
  const { data } = await apiClient.post(`/threat-intel/feeds/${feedId}/poll`);
  return data as { feed_name: string; fetched: number; created: number; updated: number; error: string | null };
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

export type RemediationStatus =
  | "open"
  | "in_progress"
  | "remediated"
  | "accepted_risk"
  | "false_positive";

export const REMEDIATION_STATUSES: RemediationStatus[] = [
  "open",
  "in_progress",
  "remediated",
  "accepted_risk",
  "false_positive",
];

export interface Vulnerability {
  id: number;
  asset_id: number;
  cve_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cvss_vector: string | null;
  solution: string;
  port: number | null;
  protocol: string | null;
  scanner: string;
  remediation_status: RemediationStatus;
  case_id: number | null;
  discovered_at: string;
  last_seen_at: string;
  remediated_at: string | null;
}

export interface Asset {
  id: number;
  hostname: string;
  ip_address: string | null;
  owner: string | null;
  environment: string;
  criticality: string;
  internet_facing: boolean;
  tags: string[];
  created_at: string;
}

export async function listVulnerabilities(
  filters: {
    severity?: string;
    remediation_status?: string;
    internet_facing?: boolean;
    min_cvss?: number;
    search?: string;
    limit?: number;
    offset?: number;
  } = {},
): Promise<Page<Vulnerability>> {
  const { data } = await apiClient.get<Page<Vulnerability>>("/vulnerabilities", {
    params: queryParams(filters),
  });
  return data;
}

export async function listAssets(
  filters: { search?: string; limit?: number; offset?: number } = {},
): Promise<Page<Asset>> {
  const { data } = await apiClient.get<Page<Asset>>("/vulnerabilities/assets", {
    params: queryParams({ limit: 200, ...filters }),
  });
  return data;
}

export async function updateVulnerabilityStatus(
  vulnerabilityId: number,
  remediationStatus: RemediationStatus,
): Promise<Vulnerability> {
  const { data } = await apiClient.patch<Vulnerability>(`/vulnerabilities/${vulnerabilityId}/status`, {
    remediation_status: remediationStatus,
  });
  return data;
}

export interface ScanIngestResult {
  import_id: number;
  scanner: string;
  imported: number;
  updated: number;
  failed: number;
  assets_touched: number;
  errors: string[];
}

export async function uploadScan(file: File): Promise<ScanIngestResult> {
  const form = new FormData();
  form.append("file", file);
  const { data } = await apiClient.post<ScanIngestResult>("/vulnerabilities/ingest", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function promoteVulnerabilities(
  vulnerabilityIds: number[],
  title?: string,
): Promise<{ id: number }> {
  const { data } = await apiClient.post<{ id: number }>("/vulnerabilities/promote", {
    vulnerability_ids: vulnerabilityIds,
    title,
  });
  return data;
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export type Framework = "SOC2" | "ISO27001" | "PCI-DSS";

export const FRAMEWORKS: Framework[] = ["SOC2", "ISO27001", "PCI-DSS"];

export interface ControlResult {
  control_id: string;
  title: string;
  description: string;
  collector: string;
  verdict: "pass" | "fail" | "not_applicable";
  summary: string;
  metrics: Record<string, unknown>;
}

export interface ComplianceReport {
  id: number;
  framework: Framework;
  period_start: string;
  period_end: string;
  status: string;
  controls_total: number;
  controls_passed: number;
  controls_failed: number;
  error_message: string | null;
  generated_by: string;
  created_at: string;
  completed_at: string | null;
  results?: { controls: ControlResult[] };
}

export async function listReports(
  filters: { framework?: string; limit?: number; offset?: number } = {},
): Promise<Page<ComplianceReport>> {
  const { data } = await apiClient.get<Page<ComplianceReport>>("/compliance/reports", {
    params: queryParams(filters),
  });
  return data;
}

export async function getReport(reportId: number): Promise<ComplianceReport> {
  const { data } = await apiClient.get<ComplianceReport>(`/compliance/reports/${reportId}`);
  return data;
}

export async function generateReport(
  framework: Framework,
  periodStart: string,
  periodEnd: string,
): Promise<ComplianceReport> {
  const { data } = await apiClient.post<ComplianceReport>("/compliance/reports", {
    framework,
    period_start: periodStart,
    period_end: periodEnd,
  });
  return data;
}

export function reportDownloadUrl(reportId: number): string {
  return `/api/v1/compliance/reports/${reportId}/download`;
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

export interface NotificationChannel {
  id: number;
  name: string;
  type: "webhook" | "slack" | "email" | "log";
  enabled: boolean;
  min_severity: Severity;
  config: Record<string, unknown>;
  created_at: string;
}

export interface Delivery {
  id: number;
  channel_id: number | null;
  channel_name: string;
  channel_type: string;
  subject_type: string;
  subject_id: number | null;
  status: string;
  detail: string;
  attempted_at: string;
}

export async function listChannels(): Promise<NotificationChannel[]> {
  const { data } = await apiClient.get<NotificationChannel[]>("/notifications/channels");
  return data;
}

export async function createChannel(input: {
  name: string;
  type: string;
  min_severity: string;
  config: Record<string, unknown>;
}): Promise<NotificationChannel> {
  const { data } = await apiClient.post<NotificationChannel>("/notifications/channels", input);
  return data;
}

export async function updateChannel(
  channelId: number,
  input: { enabled?: boolean; min_severity?: string; config?: Record<string, unknown> },
): Promise<NotificationChannel> {
  const { data } = await apiClient.patch<NotificationChannel>(
    `/notifications/channels/${channelId}`,
    input,
  );
  return data;
}

export async function deleteChannel(channelId: number): Promise<void> {
  await apiClient.delete(`/notifications/channels/${channelId}`);
}

export async function testChannel(channelId: number) {
  const { data } = await apiClient.post(`/notifications/channels/${channelId}/test`);
  return data as { channel_name: string; status: string; detail: string };
}

export async function listDeliveries(
  filters: { status?: string; subject_type?: string; limit?: number; offset?: number } = {},
): Promise<Page<Delivery>> {
  const { data } = await apiClient.get<Page<Delivery>>("/notifications/deliveries", {
    params: queryParams(filters),
  });
  return data;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  details: Record<string, unknown>;
  prev_hash: string;
  content_hash: string;
}

export async function listAuditEvents(
  filters: { actor?: string; action?: string; resource?: string; limit?: number; offset?: number } = {},
): Promise<Page<AuditEvent>> {
  const { data } = await apiClient.get<Page<AuditEvent>>("/audit", { params: queryParams(filters) });
  return data;
}

export interface ChainVerification {
  intact: boolean;
  total_events: number;
  first_broken_event_id: number | null;
  reason: string | null;
}

export async function verifyAuditChain(): Promise<ChainVerification> {
  const { data } = await apiClient.get<ChainVerification>("/audit/verify");
  return data;
}

export async function listAuditActions(): Promise<string[]> {
  const { data } = await apiClient.get<string[]>("/audit/actions");
  return data;
}

export const auditExportUrl = "/api/v1/audit/export";

// ---------------------------------------------------------------------------
// KPIs
// ---------------------------------------------------------------------------

export interface KPISummary {
  window: string;
  window_start: string;
  window_end: string;
  alerts: {
    total: number;
    open: number;
    closed: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    sla_breached: number;
    sla_breach_rate: number;
    mttd_minutes: number | null;
    mtta_minutes: number | null;
    mttr_minutes: number | null;
    mttr_p95_minutes: number | null;
  };
  cases: {
    total: number;
    open: number;
    closed: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_resolution: Record<string, number>;
    sla_breached: number;
    sla_breach_rate: number;
    mttr_minutes: number | null;
    mttr_p95_minutes: number | null;
  };
  ingestion: {
    events_normalized: number;
    events_dead_lettered: number;
    dead_letter_rate: number;
    events_with_threat_match: number;
  };
  detection: {
    rules_total: number;
    rules_enabled: number;
    rules_disabled: number;
    mitre_techniques_covered: string[];
    mitre_technique_count: number;
  };
  top_rules: { rule_id: number; rule_name: string; severity: string; alert_count: number }[];
  volume_series: {
    date: string;
    low: number;
    medium: number;
    high: number;
    critical: number;
    total: number;
  }[];
  workload: {
    user_id: number;
    username: string;
    role: string;
    open_alerts: number;
    open_cases: number;
    breached_cases: number;
  }[];
}

export async function getKpiSummary(window = "7d"): Promise<KPISummary> {
  const { data } = await apiClient.get<KPISummary>("/kpis/summary", { params: { window } });
  return data;
}

export async function runSlaSweep() {
  const { data } = await apiClient.post("/kpis/sla-sweep");
  return data as { alerts_breached: number[]; cases_breached: number[]; total: number };
}
