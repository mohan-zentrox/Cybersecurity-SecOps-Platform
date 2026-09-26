import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

/**
 * Minimal toast system.
 *
 * Every mutating action in the console reports its outcome here. Without it,
 * a failed status transition or a rejected upload is a silently swallowed
 * promise rejection — the user clicks, nothing visible happens, and they have
 * no way to tell success from failure.
 */

type ToastKind = "success" | "error" | "info";

interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastApi {
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const AUTO_DISMISS_MS = 6000;

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId++;
      setToasts((current) => [...current, { id, kind, message }]);
      window.setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (message) => push("success", message),
      error: (message) => push("error", message),
      info: (message) => push("info", message),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2"
        role="status"
        aria-live="polite"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-3 rounded border p-3 text-sm shadow-lg ${
              toast.kind === "error"
                ? "border-red-800 bg-red-950 text-red-200"
                : toast.kind === "success"
                  ? "border-emerald-800 bg-emerald-950 text-emerald-200"
                  : "border-aegis-border bg-aegis-panel text-slate-200"
            }`}
          >
            <span className="flex-1 break-words">{toast.message}</span>
            <button
              onClick={() => dismiss(toast.id)}
              className="text-slate-400 hover:text-white"
              aria-label="Dismiss notification"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (context === null) {
    throw new Error("useToast must be used inside a <ToastProvider>");
  }
  return context;
}
