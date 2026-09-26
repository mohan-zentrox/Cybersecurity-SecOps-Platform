import { NavLink } from "react-router-dom";

import {
  ADMIN_ONLY,
  ALL_ROLES,
  ANALYST_PLUS,
  AUDIT_READERS,
  RULE_AUTHORS,
  useAuthStore,
  type Role,
} from "@/store/authStore";

interface NavItem {
  to: string;
  label: string;
  roles: Role[];
}

/**
 * Navigation is role-aware: each entry declares which roles it is useful to,
 * so a compliance user is not shown an alert-triage queue they cannot act on,
 * and an analyst is not shown user administration they cannot use.
 *
 * This only controls what is *offered*. Authorization is enforced server-side
 * by `require_roles` on each endpoint — typing a URL directly still gets a 403.
 */
const NAV_ITEMS: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", roles: ALL_ROLES },
  { to: "/alerts", label: "Alerts", roles: ANALYST_PLUS },
  { to: "/cases", label: "Cases", roles: ANALYST_PLUS },
  { to: "/rules", label: "Detection", roles: [...RULE_AUTHORS, "analyst"] },
  { to: "/events", label: "Events", roles: ALL_ROLES },
  { to: "/threat-intel", label: "Threat Intel", roles: ALL_ROLES },
  { to: "/vulnerabilities", label: "Vulnerabilities", roles: ALL_ROLES },
  { to: "/compliance", label: "Compliance", roles: AUDIT_READERS },
  { to: "/audit", label: "Audit", roles: AUDIT_READERS },
  { to: "/settings", label: "Settings", roles: ADMIN_ONLY },
];

export function Navbar() {
  const { username, role, logout } = useAuthStore();

  if (!username || !role) return null;

  const visible = NAV_ITEMS.filter((item) => item.roles.includes(role));

  return (
    <nav className="border-b border-aegis-border bg-aegis-panel">
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-3">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <span className="font-semibold text-aegis-accent">Project Aegis</span>
          {visible.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `text-sm transition-colors ${
                  isActive ? "font-medium text-white" : "text-slate-400 hover:text-slate-200"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </div>
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <NavLink to="/account" className="hover:text-slate-200">
            {username} <span className="text-slate-600">({role})</span>
          </NavLink>
          <button onClick={logout} className="text-aegis-accent hover:underline">
            Log out
          </button>
        </div>
      </div>
    </nav>
  );
}
