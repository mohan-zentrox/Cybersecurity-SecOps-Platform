import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import {
  addCaseComment,
  assignCase,
  getCase,
  RESOLUTION_LABELS,
  updateCaseStatus,
  type CaseDetail as CaseDetailType,
  type CaseResolution,
  type CaseStatus,
} from "@/api/cases";
import { errorMessage } from "@/api/client";
import { listUsers, type User } from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  formatRelative,
  inputClass,
  Loading,
  PageHeader,
  Panel,
  StatusBadge,
} from "@/components/ui";

const NEXT_STATUS: Record<string, CaseStatus[]> = {
  new: ["investigating"],
  investigating: ["closed", "escalated"],
  escalated: ["investigating", "closed"],
  closed: [],
};

const TIMELINE_LABELS: Record<string, string> = {
  created: "Case opened",
  status_change: "Status changed",
  comment: "Comment",
  assignment: "Assignment",
  alert_linked: "Alert linked",
  vulnerability_linked: "Vulnerability linked",
  sla_breach: "SLA breached",
};

export default function CaseDetail() {
  const { caseId } = useParams();
  const [detail, setDetail] = useState<CaseDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [comment, setComment] = useState("");
  const [users, setUsers] = useState<User[]>([]);

  // Closure requires a disposition (FRD-CASE-06), so closing opens a small
  // form rather than firing the transition straight away.
  const [closing, setClosing] = useState(false);
  const [resolution, setResolution] = useState<CaseResolution>("true_positive");
  const [resolutionSummary, setResolutionSummary] = useState("");

  const toast = useToast();

  const refresh = useCallback(async () => {
    if (!caseId) return;
    setLoading(true);
    try {
      setDetail(await getCase(Number(caseId)));
    } catch (error) {
      toast.error(errorMessage(error, "Could not load case"));
    } finally {
      setLoading(false);
    }
  }, [caseId, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    listUsers({ is_active: true })
      .then((page) => setUsers(page.items))
      .catch(() => setUsers([]));
  }, []);

  async function transition(next: CaseStatus) {
    if (!detail) return;
    if (next === "closed") {
      setClosing(true);
      return;
    }
    try {
      setDetail(await updateCaseStatus(detail.id, next));
      toast.success(`Case moved to ${next}`);
    } catch (error) {
      toast.error(errorMessage(error, "Status change rejected"));
    }
  }

  async function confirmClose() {
    if (!detail) return;
    try {
      setDetail(await updateCaseStatus(detail.id, "closed", resolution, resolutionSummary || undefined));
      setClosing(false);
      setResolutionSummary("");
      toast.success("Case closed");
    } catch (error) {
      toast.error(errorMessage(error, "Could not close case"));
    }
  }

  async function submitComment() {
    if (!detail || !comment.trim()) return;
    try {
      setDetail(await addCaseComment(detail.id, comment.trim()));
      setComment("");
      toast.success("Comment added");
    } catch (error) {
      toast.error(errorMessage(error, "Could not add comment"));
    }
  }

  async function assign(userId: string) {
    if (!detail) return;
    try {
      setDetail(await assignCase(detail.id, userId ? Number(userId) : null));
      toast.success(userId ? "Case assigned" : "Assignment cleared");
    } catch (error) {
      toast.error(errorMessage(error, "Assignment failed"));
    }
  }

  if (loading && !detail) return <Loading label="Loading case…" />;
  if (!detail) return <EmptyState message="Case not found." />;

  return (
    <div className="p-6">
      <PageHeader
        title={detail.title}
        subtitle={`Case #${detail.id} · opened ${formatDateTime(detail.created_at)}`}
        actions={
          <>
            {(NEXT_STATUS[detail.status] ?? []).map((next) => (
              <Button key={next} onClick={() => transition(next)} tone={next === "closed" ? "primary" : "secondary"}>
                {next === "closed" ? "Close case" : `Move to ${next}`}
              </Button>
            ))}
            <Button onClick={refresh}>Refresh</Button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {closing && (
            <Panel title="Close case — record a disposition">
              <p className="mb-3 text-xs text-slate-400">
                A closed case must record why. This is what makes false-positive rate — and therefore
                detection tuning — computable.
              </p>
              <div className="space-y-3">
                <label className="block text-sm">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Resolution</span>
                  <select
                    value={resolution}
                    onChange={(e) => setResolution(e.target.value as CaseResolution)}
                    className={`${inputClass} w-full`}
                  >
                    {Object.entries(RESOLUTION_LABELS).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block text-sm">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
                    Summary (optional)
                  </span>
                  <textarea
                    value={resolutionSummary}
                    onChange={(e) => setResolutionSummary(e.target.value)}
                    rows={3}
                    className={`${inputClass} w-full`}
                    placeholder="What was found, and what was done about it?"
                  />
                </label>
                <div className="flex gap-2">
                  <Button tone="primary" onClick={confirmClose}>
                    Confirm close
                  </Button>
                  <Button onClick={() => setClosing(false)}>Cancel</Button>
                </div>
              </div>
            </Panel>
          )}

          <Panel title="Timeline">
            {detail.timeline.length === 0 ? (
              <EmptyState message="No timeline entries yet." />
            ) : (
              <ol className="space-y-3">
                {detail.timeline.map((entry) => (
                  <li key={entry.id} className="border-l-2 border-aegis-border pl-4">
                    <div className="flex flex-wrap items-baseline gap-2 text-xs text-slate-500">
                      <span className="font-medium text-slate-300">
                        {TIMELINE_LABELS[entry.type] ?? entry.type}
                      </span>
                      <span>·</span>
                      <span>{entry.actor}</span>
                      <span>·</span>
                      <span>{formatDateTime(entry.created_at)}</span>
                    </div>
                    <div className="mt-1 text-sm text-slate-300">
                      {entry.type === "comment" ? (
                        <p className="whitespace-pre-wrap">{String(entry.content.comment ?? "")}</p>
                      ) : (
                        <pre className="overflow-x-auto rounded bg-aegis-bg p-2 text-xs text-slate-400">
                          {JSON.stringify(entry.content, null, 2)}
                        </pre>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          <Panel title="Add a comment">
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              className={`${inputClass} w-full`}
              placeholder="Record an investigation note…"
            />
            <div className="mt-2">
              <Button tone="primary" onClick={submitComment} disabled={!comment.trim()}>
                Add comment
              </Button>
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Details">
            <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
              <dt className="text-slate-400">Status</dt>
              <dd className="text-right">
                <StatusBadge value={detail.status} />
              </dd>

              <dt className="text-slate-400">Severity</dt>
              <dd className="text-right">
                <StatusBadge value={detail.severity} />
              </dd>

              <dt className="text-slate-400">SLA due</dt>
              <dd className="text-right text-xs">
                {detail.sla_breached ? (
                  <span className="font-medium text-red-400">Breached</span>
                ) : (
                  <span className="text-slate-300">{formatRelative(detail.sla_due_at)}</span>
                )}
              </dd>

              <dt className="text-slate-400">Closed</dt>
              <dd className="text-right text-xs text-slate-300">{formatDateTime(detail.closed_at)}</dd>

              {detail.resolution && (
                <>
                  <dt className="text-slate-400">Resolution</dt>
                  <dd className="text-right text-xs text-slate-300">
                    {RESOLUTION_LABELS[detail.resolution]}
                  </dd>
                </>
              )}
            </dl>

            {detail.resolution_summary && (
              <p className="mt-3 border-t border-aegis-border pt-3 text-xs text-slate-400">
                {detail.resolution_summary}
              </p>
            )}

            <label className="mt-4 block text-sm">
              <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">Assignee</span>
              <select
                value={detail.assigned_to ? String(detail.assigned_to) : ""}
                onChange={(e) => assign(e.target.value)}
                className={`${inputClass} w-full`}
              >
                <option value="">Unassigned</option>
                {users.map((user) => (
                  <option key={user.id} value={String(user.id)}>
                    {user.username}
                  </option>
                ))}
              </select>
            </label>
          </Panel>

          <Panel title={`Linked alerts (${detail.alert_ids.length})`}>
            {detail.alert_ids.length === 0 ? (
              <p className="text-xs text-slate-500">None.</p>
            ) : (
              <ul className="space-y-1 text-sm">
                {detail.alert_ids.map((id) => (
                  <li key={id}>
                    <Link to="/alerts" className="text-aegis-accent hover:underline">
                      Alert #{id}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {detail.vulnerability_ids.length > 0 && (
            <Panel title={`Linked vulnerabilities (${detail.vulnerability_ids.length})`}>
              <ul className="space-y-1 text-sm">
                {detail.vulnerability_ids.map((id) => (
                  <li key={id}>
                    <Link to="/vulnerabilities" className="text-aegis-accent hover:underline">
                      Vulnerability #{id}
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
