import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { errorMessage } from "@/api/client";
import {
  listAssets,
  listVulnerabilities,
  promoteVulnerabilities,
  REMEDIATION_STATUSES,
  updateVulnerabilityStatus,
  uploadScan,
  type Asset,
  type RemediationStatus,
  type Vulnerability,
} from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  inputClass,
  Loading,
  PageHeader,
  Pagination,
  Panel,
  Select,
  StatusBadge,
} from "@/components/ui";
import { ANALYST_PLUS, RULE_AUTHORS, useHasRole } from "@/store/authStore";

const PAGE_SIZE = 25;

const SEVERITY_OPTIONS = [
  { value: "", label: "Any severity" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const STATUS_OPTIONS = [
  { value: "", label: "Any status" },
  ...REMEDIATION_STATUSES.map((s) => ({ value: s, label: s.replace(/_/g, " ") })),
];

const EXPOSURE_OPTIONS = [
  { value: "", label: "All assets" },
  { value: "true", label: "Internet-facing only" },
  { value: "false", label: "Internal only" },
];

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [assets, setAssets] = useState<Record<number, Asset>>({});
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [uploading, setUploading] = useState(false);

  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [exposure, setExposure] = useState("");
  const [search, setSearch] = useState("");

  const fileInput = useRef<HTMLInputElement>(null);
  const canUpload = useHasRole(...RULE_AUTHORS);
  const canTriage = useHasRole(...ANALYST_PLUS);
  const navigate = useNavigate();
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listVulnerabilities({
        limit: PAGE_SIZE,
        offset,
        severity: severity || undefined,
        remediation_status: status || undefined,
        internet_facing: exposure === "" ? undefined : exposure === "true",
        search: search || undefined,
      });
      setVulns(page.items);
      setTotal(page.total);
      const visible = new Set(page.items.map((v) => v.id));
      setSelected((current) => new Set([...current].filter((id) => visible.has(id))));
    } catch (error) {
      toast.error(errorMessage(error, "Could not load vulnerabilities"));
    } finally {
      setLoading(false);
    }
  }, [offset, severity, status, exposure, search, toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    listAssets()
      .then((page) => setAssets(Object.fromEntries(page.items.map((a) => [a.id, a]))))
      .catch(() => setAssets({}));
  }, []);

  async function onUpload(file: File) {
    setUploading(true);
    try {
      const result = await uploadScan(file);
      toast.success(
        `${result.scanner}: ${result.imported} new, ${result.updated} updated, ${result.failed} failed ` +
          `across ${result.assets_touched} asset(s)`,
      );
      if (result.errors.length) {
        toast.error(`First parse error: ${result.errors[0]}`);
      }
      refresh();
      listAssets()
        .then((page) => setAssets(Object.fromEntries(page.items.map((a) => [a.id, a]))))
        .catch(() => undefined);
    } catch (error) {
      toast.error(errorMessage(error, "Scan upload failed"));
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function changeStatus(vuln: Vulnerability, next: RemediationStatus) {
    try {
      await updateVulnerabilityStatus(vuln.id, next);
      toast.success(`Marked ${vuln.cve_id ?? vuln.title} as ${next.replace(/_/g, " ")}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not update remediation status"));
    }
  }

  async function promote() {
    if (selected.size === 0) return;
    try {
      const result = await promoteVulnerabilities([...selected]);
      toast.success(`Created case #${result.id}`);
      setSelected(new Set());
      navigate(`/cases/${result.id}`);
    } catch (error) {
      toast.error(errorMessage(error, "Could not promote vulnerabilities"));
    }
  }

  function toggle(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="p-6">
      <PageHeader
        title="Vulnerabilities"
        subtitle={`${total} finding${total === 1 ? "" : "s"} matching the current filters`}
        actions={
          <>
            {canUpload && (
              <>
                <input
                  ref={fileInput}
                  type="file"
                  accept=".nessus,.xml,.csv"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) onUpload(file);
                  }}
                />
                <Button onClick={() => fileInput.current?.click()} disabled={uploading}>
                  {uploading ? "Importing…" : "Import scan"}
                </Button>
              </>
            )}
            {canTriage && (
              <Button tone="primary" onClick={promote} disabled={selected.size === 0}>
                Promote {selected.size > 0 ? `(${selected.size})` : ""} to case
              </Button>
            )}
          </>
        }
      />

      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={(e) => {
              setOffset(0);
              setSearch(e.target.value);
            }}
            placeholder="Search finding title…"
            className={`${inputClass} w-64`}
            aria-label="Search vulnerabilities"
          />
          <Select
            value={severity}
            onChange={(value) => {
              setOffset(0);
              setSeverity(value);
            }}
            options={SEVERITY_OPTIONS}
            label="Severity"
          />
          <Select
            value={status}
            onChange={(value) => {
              setOffset(0);
              setStatus(value);
            }}
            options={STATUS_OPTIONS}
            label="Status"
          />
          <Select
            value={exposure}
            onChange={(value) => {
              setOffset(0);
              setExposure(value);
            }}
            options={EXPOSURE_OPTIONS}
            label="Exposure"
          />
        </div>
        {canUpload && (
          <p className="mt-3 text-xs text-slate-500">
            Supported imports: Tenable <code>.nessus</code> XML and Qualys-style CSV. Re-importing the
            same scan refreshes existing findings instead of duplicating them.
          </p>
        )}
      </Panel>

      <Panel>
        {loading ? (
          <Loading />
        ) : vulns.length === 0 ? (
          <EmptyState
            message="No vulnerabilities match these filters."
            hint={canUpload ? "Import a scanner export to populate this view." : undefined}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-500">
                <tr className="border-b border-aegis-border">
                  {canTriage && <th className="w-8 py-2" />}
                  <th className="py-2">CVE</th>
                  <th className="py-2">Finding</th>
                  <th className="py-2">Asset</th>
                  <th className="py-2">Severity</th>
                  <th className="py-2">CVSS</th>
                  <th className="py-2">Status</th>
                  <th className="py-2">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((vuln) => {
                  const asset = assets[vuln.asset_id];
                  return (
                    <tr key={vuln.id} className="border-b border-aegis-border/50 hover:bg-aegis-bg/40">
                      {canTriage && (
                        <td className="py-2">
                          <input
                            type="checkbox"
                            checked={selected.has(vuln.id)}
                            onChange={() => toggle(vuln.id)}
                            aria-label={`Select vulnerability ${vuln.id}`}
                          />
                        </td>
                      )}
                      <td className="py-2 font-mono text-xs text-slate-300">
                        {vuln.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="hover:text-aegis-accent"
                          >
                            {vuln.cve_id}
                          </a>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-2 text-slate-200">
                        {vuln.title}
                        {vuln.solution && (
                          <div className="mt-0.5 text-xs text-slate-500">Fix: {vuln.solution}</div>
                        )}
                      </td>
                      <td className="py-2 text-xs text-slate-300">
                        {asset ? asset.hostname : `#${vuln.asset_id}`}
                        {asset?.internet_facing && (
                          <span className="ml-1 text-red-400" title="Internet-facing">
                            ●
                          </span>
                        )}
                      </td>
                      <td className="py-2">
                        <StatusBadge value={vuln.severity} />
                      </td>
                      <td className="py-2 text-slate-300">{vuln.cvss_score?.toFixed(1) ?? "—"}</td>
                      <td className="py-2">
                        {canTriage ? (
                          <select
                            value={vuln.remediation_status}
                            onChange={(e) => changeStatus(vuln, e.target.value as RemediationStatus)}
                            className={`${inputClass} text-xs`}
                            aria-label={`Remediation status for vulnerability ${vuln.id}`}
                          >
                            {REMEDIATION_STATUSES.map((value) => (
                              <option key={value} value={value}>
                                {value.replace(/_/g, " ")}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <StatusBadge value={vuln.remediation_status} />
                        )}
                      </td>
                      <td className="py-2 text-xs text-slate-400">{formatDateTime(vuln.last_seen_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
      </Panel>
    </div>
  );
}
