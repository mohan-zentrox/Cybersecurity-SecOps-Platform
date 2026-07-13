const COLORS: Record<string, string> = {
  new: "bg-sky-900 text-sky-300",
  investigating: "bg-amber-900 text-amber-300",
  closed: "bg-emerald-900 text-emerald-300",
  escalated: "bg-red-900 text-red-300",
  low: "bg-slate-800 text-slate-300",
  medium: "bg-amber-900 text-amber-300",
  high: "bg-orange-900 text-orange-300",
  critical: "bg-red-900 text-red-300",
};

export function StatusBadge({ value }: { value: string }) {
  const classes = COLORS[value] ?? "bg-slate-800 text-slate-300";
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${classes}`}>
      {value}
    </span>
  );
}
