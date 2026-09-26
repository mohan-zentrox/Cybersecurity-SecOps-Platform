import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Role = "analyst" | "detection-engineer" | "compliance" | "admin";

export const ALL_ROLES: Role[] = ["analyst", "detection-engineer", "compliance", "admin"];

interface AuthState {
  token: string | null;
  username: string | null;
  userId: number | null;
  role: Role | null;
  login: (token: string, username: string, role: Role, userId?: number | null) => void;
  logout: () => void;
}

/**
 * Client-side session state. The source of truth for authorization is
 * always the backend (see backend/app/core/deps.py::require_roles) — this
 * store only drives what the UI *offers*, e.g. hiding the "Users" nav item
 * for roles that cannot manage accounts. Hiding a control is a usability
 * affordance, never a security boundary.
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      username: null,
      userId: null,
      role: null,
      login: (token, username, role, userId = null) => set({ token, username, role, userId }),
      logout: () => set({ token: null, username: null, role: null, userId: null }),
    }),
    { name: "aegis-auth" },
  ),
);

/** True when the signed-in role is one of `allowed`. */
export function useHasRole(...allowed: Role[]): boolean {
  const role = useAuthStore((s) => s.role);
  return role !== null && allowed.includes(role);
}

export const RULE_AUTHORS: Role[] = ["detection-engineer", "admin"];
export const ANALYST_PLUS: Role[] = ["analyst", "detection-engineer", "admin"];
export const AUDIT_READERS: Role[] = ["compliance", "admin"];
export const ADMIN_ONLY: Role[] = ["admin"];
