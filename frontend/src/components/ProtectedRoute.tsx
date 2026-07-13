import type { ReactElement } from "react";
import { Navigate } from "react-router-dom";

import { useAuthStore } from "@/store/authStore";

export function ProtectedRoute({ children }: { children: ReactElement }): ReactElement {
  const token = useAuthStore((s) => s.token);
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
