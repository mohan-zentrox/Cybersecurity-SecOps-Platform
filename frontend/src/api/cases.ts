import { apiClient } from "./client";
import type { AlertStatus } from "./alerts";

export interface CaseTimelineEvent {
  id: number;
  type: string;
  content: Record<string, unknown>;
  actor: string;
  created_at: string;
}

export interface CaseDetail {
  id: number;
  title: string;
  severity: string;
  status: AlertStatus;
  assigned_to: number | null;
  sla_due_at: string;
  created_at: string;
  updated_at: string;
  timeline: CaseTimelineEvent[];
  alert_ids: number[];
}

export async function getCase(caseId: number): Promise<CaseDetail> {
  const { data } = await apiClient.get<CaseDetail>(`/cases/${caseId}`);
  return data;
}

export async function updateCaseStatus(caseId: number, status: AlertStatus): Promise<CaseDetail> {
  const { data } = await apiClient.patch<CaseDetail>(`/cases/${caseId}/status`, { status });
  return data;
}

export async function addCaseComment(caseId: number, comment: string): Promise<CaseDetail> {
  const { data } = await apiClient.post<CaseDetail>(`/cases/${caseId}/comments`, { comment });
  return data;
}
