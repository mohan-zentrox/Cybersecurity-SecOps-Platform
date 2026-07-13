import { Link } from "react-router-dom";

import { useAuthStore } from "@/store/authStore";

export function Navbar() {
  const { username, role, logout } = useAuthStore();

  if (!username) return null;

  return (
    <nav className="flex items-center justify-between border-b border-aegis-border bg-aegis-panel px-6 py-3">
      <div className="flex items-center gap-6">
        <span className="font-semibold text-aegis-accent">Project Aegis</span>
        <Link to="/alerts" className="text-sm text-slate-300 hover:text-white">
          Alert Queue
        </Link>
        <Link to="/rules" className="text-sm text-slate-300 hover:text-white">
          Detection Rules
        </Link>
      </div>
      <div className="flex items-center gap-4 text-sm text-slate-400">
        <span>
          {username} <span className="text-slate-600">({role})</span>
        </span>
        <button onClick={logout} className="text-aegis-accent hover:underline">
          Log out
        </button>
      </div>
    </nav>
  );
}
