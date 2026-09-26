/**
 * Small shared presentational primitives used across the console pages:
 * page shell, panels, stat tiles, pagination, empty/loading states, and the
 * severity/status badge.
 */
import type { ReactNode } from "react";

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------

const BADGE_COLORS: Record<string, string> = {
  // Workflow status
  new: "bg-sky-900 text-sky-300",
  investigating: "bg-amber-900 text-amber-300",
  closed: "bg-emerald-900 text-emerald-300",
  escalated: "bg-red-900 text-red-300",
  // Severity
  low: "bg-slate-800 text-slate-300",
  medium: "bg-amber-900 text-amber-300",
  high: "bg-orange-900 text-orange-300",
  critical: "bg-red-900 text-red-300",
  // Remediation
  open: "bg-sky-900 text-sky-300",
  in_progress: "bg-amber-900 text-amber-300",
  remediated: "bg-emerald-900 text-emerald-300",
  accepted_risk: "bg-purple-900 text-purple-300",
  false_positive: "bg-slate-800 text-slate-400",
  // Verdicts / delivery
  pass: "bg-emerald-900 text-emerald-300",
  fail: "bg-red-900 text-red-300",
  not_applicable: "bg-slate-800 text-slate-400",
  sent: "bg-emerald-900 text-emerald-300",
  failed: "bg-red-900 text-red-300",
  skipped: "bg-slate-800 text-slate-400",
};

export function StatusBadge({ value }: { value: string }) {
  const classes = BADGE_COLORS[value] ?? "bg-slate-800 text-slate-300";
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${classes}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  children,
  actions,
  className = "",
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-lg border border-aegis-border bg-aegis-panel ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-aegis-border px-4 py-3">
          {title && <h2 className="text-sm font-semibold text-slate-200">{title}</h2>}
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "default" | "danger" | "warning" | "good";
}) {
  const valueTone = {
    default: "text-white",
    danger: "text-red-400",
    warning: "text-amber-400",
    good: "text-emerald-400",
  }[tone];

  return (
    <div className="rounded-lg border border-aegis-border bg-aegis-panel p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${valueTone}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <p className="py-8 text-center text-sm text-slate-400">{label}</p>;
}

export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="py-10 text-center">
      <p className="text-sm text-slate-400">{message}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

const BUTTON_TONES = {
  primary: "bg-aegis-accent text-slate-900 hover:bg-sky-300 disabled:opacity-40",
  secondary: "border border-aegis-border text-slate-200 hover:border-aegis-accent disabled:opacity-40",
  danger: "border border-red-800 text-red-300 hover:bg-red-950 disabled:opacity-40",
};

export function Button({
  children,
  onClick,
  disabled,
  tone = "secondary",
  type = "button",
  title,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  tone?: keyof typeof BUTTON_TONES;
  type?: "button" | "submit";
  title?: string;
  className?: string;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded px-3 py-1.5 text-sm font-medium transition-colors ${BUTTON_TONES[tone]} ${className}`}
    >
      {children}
    </button>
  );
}

export const inputClass =
  "rounded border border-aegis-border bg-aegis-bg px-2 py-1.5 text-sm text-slate-100 " +
  "placeholder:text-slate-500 focus:border-aegis-accent focus:outline-none";

export function Select({
  value,
  onChange,
  options,
  label,
  className = "",
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  label?: string;
  className?: string;
}) {
  return (
    <label className={`flex items-center gap-2 text-xs text-slate-400 ${className}`}>
      {label && <span className="whitespace-nowrap">{label}</span>}
      <select value={value} onChange={(e) => onChange(e.target.value)} className={inputClass}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  if (total <= limit) return null;

  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);

  return (
    <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
      <span>
        {from}–{to} of {total}
      </span>
      <div className="flex items-center gap-2">
        <Button onClick={() => onChange(Math.max(0, offset - limit))} disabled={offset === 0}>
          Previous
        </Button>
        <span>
          Page {page} of {pages}
        </span>
        <Button onClick={() => onChange(offset + limit)} disabled={offset + limit >= total}>
          Next
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

/** Compact relative time, e.g. "in 3h" / "5m ago". Used for SLA countdowns. */
export function formatRelative(value: string | null | undefined): string {
  if (!value) return "—";
  const target = new Date(value).getTime();
  if (Number.isNaN(target)) return "—";

  const diffMs = target - Date.now();
  const overdue = diffMs < 0;
  const minutes = Math.round(Math.abs(diffMs) / 60000);

  let text: string;
  if (minutes < 60) text = `${minutes}m`;
  else if (minutes < 60 * 24) text = `${Math.round(minutes / 60)}h`;
  else text = `${Math.round(minutes / (60 * 24))}d`;

  return overdue ? `${text} overdue` : `in ${text}`;
}

export function formatMinutes(value: number | null | undefined): string {
  // Distinguish "no data" from "zero minutes" — an empty MTTR must not read
  // as instant resolution.
  if (value === null || value === undefined) return "—";
  if (value < 60) return `${Math.round(value)}m`;
  if (value < 60 * 24) return `${(value / 60).toFixed(1)}h`;
  return `${(value / (60 * 24)).toFixed(1)}d`;
}

export function formatPercent(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
