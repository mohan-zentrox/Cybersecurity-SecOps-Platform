import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Role = "analyst" | "detection-engineer" | "compliance" | "admin";

interface AuthState {
  token: string | null;
  username: string | null;
  role: Role | null;
  login: (token: string, username: string, role: Role) => void;
  logout: () => void;
}

/**
 * Client-side session state. The source of truth for authorization is
 * always the backend (see backend/app/core/deps.py::require_roles) — this
 * store only drives what the UI *offers*, e.g. hiding the "Rules" nav
 * item for roles that can't author rules.
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      username: null,
      role: null,
      login: (token, username, role) => set({ token, username, role }),
      logout: () => set({ token: null, username: null, role: null }),
    }),
    { name: "aegis-auth" },
  ),
);
