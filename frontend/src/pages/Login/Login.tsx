import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { login as loginRequest } from "@/api/auth";
import { errorMessage } from "@/api/client";
import { inputClass } from "@/components/ui";
import { useAuthStore } from "@/store/authStore";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const token = useAuthStore((s) => s.token);
  const setSession = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  if (token) return <Navigate to="/dashboard" replace />;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const response = await loginRequest(username, password);
      setSession(response.access_token, response.username, response.role);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      // The API deliberately returns the same message for unknown user and
      // wrong password, so this does not leak which accounts exist.
      setError(errorMessage(err, "Sign-in failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm rounded-lg border border-aegis-border bg-aegis-panel p-6"
      >
        <h1 className="mb-1 text-lg font-semibold text-aegis-accent">Project Aegis</h1>
        <p className="mb-6 text-sm text-slate-400">Sign in to the security operations console.</p>

        {error && (
          <div
            role="alert"
            className="mb-4 rounded border border-red-800 bg-red-950 p-2 text-sm text-red-200"
          >
            {error}
          </div>
        )}

        <label className="mb-3 block text-sm">
          <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className={`${inputClass} w-full`}
          />
        </label>

        <label className="mb-5 block text-sm">
          <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className={`${inputClass} w-full`}
          />
        </label>

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded bg-aegis-accent px-3 py-2 text-sm font-medium text-slate-900 hover:bg-sky-300 disabled:opacity-40"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
