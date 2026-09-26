import type { ReactElement } from "react";
import { Navigate } from "react-router-dom";

import { useAuthStore, type Role } from "@/store/authStore";

/**
 * Route guard. `roles` additionally restricts a route to specific roles and
 * renders an explicit "not permitted" page rather than a blank screen or a
 * confusing redirect — a user who follows a shared link to a page their role
 * cannot use should be told why.
 *
 * This is a usability layer only; the API enforces the same rules server-side.
 */
export function ProtectedRoute({
  children,
  roles,
}: {
  children: ReactElement;
  roles?: Role[];
}): ReactElement {
  const token = useAuthStore((s) => s.token);
  const role = useAuthStore((s) => s.role);

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (roles && role && !roles.includes(role)) {
    return (
      <div className="p-10 text-center">
        <h1 className="text-lg font-semibold text-white">Not permitted</h1>
        <p className="mt-2 text-sm text-slate-400">
          Your role (<span className="text-slate-200">{role}</span>) does not have access to this page.
        </p>
      </div>
    );
  }

  return children;
}
