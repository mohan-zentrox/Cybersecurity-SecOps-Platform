import { apiClient, type Page, queryParams, type Severity, type WorkStatus } from "./client";

export type CaseStatus = WorkStatus;

export type CaseResolution =
  | "true_positive"
  | "false_positive"
  | "benign_true_positive"
  | "duplicate"
  | "inconclusive";

export const RESOLUTION_LABELS: Record<CaseResolution, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign_true_positive: "Benign true positive",
  duplicate: "Duplicate",
  inconclusive: "Inconclusive",
};

export interface TimelineEvent {
  id: number;
  type: string;
  content: Record<string, unknown>;
  actor: string;
  created_at: string;
}

export interface CaseSummary {
  id: number;
  title: string;
  severity: Severity;
  status: CaseStatus;
  assigned_to: number | null;
  sla_due_at: string;
  sla_breached: boolean;
  closed_at: string | null;
  resolution: CaseResolution | null;
  resolution_summary: string | null;
  created_at: string;
  updated_at: string;
}

export interface CaseDetail extends CaseSummary {
  timeline: TimelineEvent[];
  alert_ids: number[];
  vulnerability_ids: number[];
}

export interface CaseFilters {
  status?: string;
  severity?: string;
  assigned_to?: number;
  sla_breached?: boolean;
  resolution?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function listCases(filters: CaseFilters = {}): Promise<Page<CaseSummary>> {
  const { data } = await apiClient.get<Page<CaseSummary>>("/cases", { params: queryParams(filters) });
  return data;
}

export async function getCase(caseId: number): Promise<CaseDetail> {
  const { data } = await apiClient.get<CaseDetail>(`/cases/${caseId}`);
  return data;
}

export async function updateCaseStatus(
  caseId: number,
  status: CaseStatus,
  resolution?: CaseResolution,
  resolutionSummary?: string,
): Promise<CaseDetail> {
  const { data } = await apiClient.patch<CaseDetail>(`/cases/${caseId}/status`, {
    status,
    resolution,
    resolution_summary: resolutionSummary,
  });
  return data;
}

export async function addCaseComment(caseId: number, comment: string): Promise<CaseDetail> {
  const { data } = await apiClient.post<CaseDetail>(`/cases/${caseId}/comments`, { comment });
  return data;
}

export async function assignCase(caseId: number, assignedTo: number | null): Promise<CaseDetail> {
  const { data } = await apiClient.patch<CaseDetail>(`/cases/${caseId}/assign`, {
    assigned_to: assignedTo,
  });
  return data;
}
