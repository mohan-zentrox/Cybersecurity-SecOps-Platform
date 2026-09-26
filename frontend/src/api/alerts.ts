import { apiClient, type Page, queryParams, type Severity, type WorkStatus } from "./client";

export type AlertStatus = WorkStatus;

export interface ThreatIndicator {
  id: number;
  type: string;
  value: string;
  confidence: number;
  severity: string;
  source: string;
  tags: string[];
}

export interface AlertEnrichment {
  matched?: boolean;
  count?: number;
  max_confidence?: number;
  indicators?: ThreatIndicator[];
}

export interface Alert {
  id: number;
  rule_id: number | null;
  title: string;
  severity: Severity;
  status: AlertStatus;
  dedup_key: string;
  assigned_to: number | null;
  matched_event_ids: number[];
  enrichment: AlertEnrichment;
  first_event_at: string | null;
  acknowledged_at: string | null;
  closed_at: string | null;
  sla_due_at: string | null;
  sla_breached: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertFilters {
  status?: string;
  severity?: string;
  assigned_to?: number;
  unassigned?: boolean;
  rule_id?: number;
  sla_breached?: boolean;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function listAlerts(filters: AlertFilters = {}): Promise<Page<Alert>> {
  const { data } = await apiClient.get<Page<Alert>>("/alerts", { params: queryParams(filters) });
  return data;
}

export async function getAlert(alertId: number): Promise<Alert> {
  const { data } = await apiClient.get<Alert>(`/alerts/${alertId}`);
  return data;
}

export async function updateAlertStatus(alertId: number, status: AlertStatus): Promise<Alert> {
  const { data } = await apiClient.patch<Alert>(`/alerts/${alertId}/status`, { status });
  return data;
}

export interface BulkResult {
  updated: number[];
  failed: Record<string, string>;
}

export async function bulkUpdateStatus(alertIds: number[], status: AlertStatus): Promise<BulkResult> {
  const { data } = await apiClient.post<BulkResult>("/alerts/bulk/status", {
    alert_ids: alertIds,
    status,
  });
  return data;
}

export async function assignAlert(alertId: number, assignedTo: number | null): Promise<Alert> {
  const { data } = await apiClient.patch<Alert>(`/alerts/${alertId}/assign`, { assigned_to: assignedTo });
  return data;
}

export async function promoteAlertsToCase(alertIds: number[], title?: string): Promise<{ id: number }> {
  const { data } = await apiClient.post<{ id: number }>("/alerts/promote", {
    alert_ids: alertIds,
    title,
  });
  return data;
}
