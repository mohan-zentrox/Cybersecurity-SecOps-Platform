import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import { login } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const setAuth = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const resp = await login(username, password);
      setAuth(resp.access_token, resp.username, resp.role);
      navigate("/alerts");
    } catch (err: any) {
      if (err?.response?.status === 429) {
        setError("Too many attempts. Please wait before trying again.");
      } else {
        setError("Invalid username or password.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <form onSubmit={onSubmit} className="w-80 rounded-lg border border-aegis-border bg-aegis-panel p-6">
        <h1 className="mb-1 text-xl font-semibold text-aegis-accent">Project Aegis</h1>
        <p className="mb-6 text-sm text-slate-400">SecOps console sign-in</p>

        <label className="mb-1 block text-xs uppercase text-slate-400">Username</label>
        <input
          className="mb-4 w-full rounded border border-aegis-border bg-aegis-bg px-3 py-2 text-sm"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          required
        />

        <label className="mb-1 block text-xs uppercase text-slate-400">Password</label>
        <input
          type="password"
          className="mb-4 w-full rounded border border-aegis-border bg-aegis-bg px-3 py-2 text-sm"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          required
        />

        {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded bg-aegis-accent py-2 text-sm font-medium text-slate-900 disabled:opacity-50"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
