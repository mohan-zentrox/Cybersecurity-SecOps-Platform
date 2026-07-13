import { apiClient } from "./client";

export type AlertStatus = "new" | "investigating" | "closed" | "escalated";

export interface Alert {
  id: number;
  rule_id: number | null;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  status: AlertStatus;
  dedup_key: string;
  assigned_to: number | null;
  matched_event_ids: unknown[];
  created_at: string;
  updated_at: string;
}

export async function listAlerts(): Promise<Alert[]> {
  const { data } = await apiClient.get<Alert[]>("/alerts");
  return data;
}

export async function updateAlertStatus(alertId: number, status: AlertStatus): Promise<Alert> {
  const { data } = await apiClient.patch<Alert>(`/alerts/${alertId}/status`, { status });
  return data;
}

export async function promoteAlertsToCase(alertIds: number[], title?: string) {
  const { data } = await apiClient.post("/alerts/promote", { alert_ids: alertIds, title });
  return data;
}
