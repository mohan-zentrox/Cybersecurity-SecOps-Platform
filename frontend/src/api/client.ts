import axios, { AxiosError } from "axios";

import { useAuthStore } from "@/store/authStore";

/**
 * Shared API client. Attaches the session bearer token issued by
 * POST /api/v1/auth/login (see backend/app/api/v1/auth.py) to every
 * request, and clears local auth state on a 401 so the UI falls back to
 * the login page instead of silently failing.
 */
export const apiClient = axios.create({
  baseURL: "/api/v1",
});

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout();
    }
    return Promise.reject(error);
  },
);

/** Envelope returned by every paginated list endpoint (see core/pagination.py). */
export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export const EMPTY_PAGE: Page<never> = { items: [], total: 0, limit: 50, offset: 0 };

export type Severity = "low" | "medium" | "critical" | "high";
export type WorkStatus = "new" | "investigating" | "closed" | "escalated";

/**
 * Turn an axios failure into a sentence worth showing a user.
 *
 * FastAPI reports validation failures as a list of per-field objects, which
 * render as "[object Object]" if passed straight to a toast — the single most
 * common way an API error message becomes useless.
 */
export function errorMessage(error: unknown, fallback = "Something went wrong"): string {
  const axiosError = error as AxiosError<{ detail?: unknown }>;
  const detail = axiosError?.response?.data?.detail;

  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "string") return item;
        const entry = item as { loc?: unknown[]; msg?: string };
        const field = Array.isArray(entry.loc) ? entry.loc.filter((p) => p !== "body").join(".") : "";
        return field ? `${field}: ${entry.msg ?? "invalid"}` : entry.msg ?? "invalid";
      })
      .filter(Boolean);
    if (parts.length) return parts.join("; ");
  }

  if (axiosError?.response?.status) {
    return `${fallback} (HTTP ${axiosError.response.status})`;
  }
  if (axiosError?.message) return axiosError.message;
  return fallback;
}

/** Drop undefined/empty values so they are not sent as literal "undefined". */
export function queryParams<T extends object>(params: T): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}
