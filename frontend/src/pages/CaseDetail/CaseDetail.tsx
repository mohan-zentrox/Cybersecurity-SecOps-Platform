import { type FormEvent, useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { addCaseComment, type CaseDetail as CaseDetailType, getCase, updateCaseStatus } from "@/api/cases";
import { StatusBadge } from "@/components/StatusBadge";

const NEXT_STATUS: Record<string, string[]> = {
  new: ["investigating"],
  investigating: ["closed", "escalated"],
  escalated: ["investigating", "closed"],
  closed: [],
};

export default function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const [detail, setDetail] = useState<CaseDetailType | null>(null);
  const [comment, setComment] = useState("");

  async function refresh() {
    if (!caseId) return;
    setDetail(await getCase(Number(caseId)));
  }

  useEffect(() => {
    refresh();
  }, [caseId]);

  async function transition(status: string) {
    if (!caseId) return;
    setDetail(await updateCaseStatus(Number(caseId), status as any));
  }

  async function submitComment(e: FormEvent) {
    e.preventDefault();
    if (!caseId || !comment.trim()) return;
    setDetail(await addCaseComment(Number(caseId), comment));
    setComment("");
  }

  if (!detail) return <p className="p-6 text-slate-400">Loading…</p>;

  return (
    <div className="p-6">
      <div className="mb-2 flex items-center gap-3">
        <h1 className="text-lg font-semibold">{detail.title}</h1>
        <StatusBadge value={detail.severity} />
        <StatusBadge value={detail.status} />
      </div>
      <p className="mb-4 text-sm text-slate-400">
        SLA due {new Date(detail.sla_due_at).toLocaleString()} · Linked alerts: {detail.alert_ids.join(", ") || "none"}
      </p>

      <div className="mb-6 flex gap-2">
        {(NEXT_STATUS[detail.status] ?? []).map((next) => (
          <button
            key={next}
            onClick={() => transition(next)}
            className="rounded border border-aegis-border px-3 py-1.5 text-sm hover:border-aegis-accent"
          >
            Move to {next}
          </button>
        ))}
      </div>

      <h2 className="mb-2 text-sm font-semibold uppercase text-slate-400">Timeline</h2>
      <ul className="mb-6 space-y-2">
        {detail.timeline.map((event) => (
          <li key={event.id} className="rounded border border-aegis-border bg-aegis-panel p-3 text-sm">
            <div className="mb-1 flex justify-between text-xs text-slate-500">
              <span>{event.type}</span>
              <span>
                {event.actor} · {new Date(event.created_at).toLocaleString()}
              </span>
            </div>
            <pre className="whitespace-pre-wrap text-slate-300">{JSON.stringify(event.content)}</pre>
          </li>
        ))}
      </ul>

      <form onSubmit={submitComment} className="flex gap-2">
        <input
          className="flex-1 rounded border border-aegis-border bg-aegis-bg px-3 py-2 text-sm"
          placeholder="Add a comment to the case timeline…"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <button type="submit" className="rounded bg-aegis-accent px-3 py-2 text-sm font-medium text-slate-900">
          Comment
        </button>
      </form>
    </div>
  );
}
