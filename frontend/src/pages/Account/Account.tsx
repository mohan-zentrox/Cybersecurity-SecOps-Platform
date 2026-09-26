import { useState } from "react";

import { errorMessage } from "@/api/client";
import { changeOwnPassword } from "@/api/platform";
import { useToast } from "@/components/Toast";
import { Button, inputClass, PageHeader, Panel } from "@/components/ui";
import { useAuthStore } from "@/store/authStore";

const MIN_PASSWORD_LENGTH = 12;

export default function Account() {
  const { username, role } = useAuthStore();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  async function submit() {
    if (next !== confirm) {
      toast.error("The new passwords do not match");
      return;
    }
    if (next.length < MIN_PASSWORD_LENGTH) {
      toast.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
      return;
    }

    setSaving(true);
    try {
      await changeOwnPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast.success("Password changed");
    } catch (error) {
      toast.error(errorMessage(error, "Could not change password"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-6">
      <PageHeader title="Account" subtitle={`Signed in as ${username} (${role})`} />

      <Panel title="Change password" className="max-w-md">
        <div className="space-y-3">
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
              Current password
            </span>
            <input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              className={`${inputClass} w-full`}
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">New password</span>
            <input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              className={`${inputClass} w-full`}
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block text-xs uppercase tracking-wide text-slate-400">
              Confirm new password
            </span>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              className={`${inputClass} w-full`}
            />
          </label>
          <Button tone="primary" onClick={submit} disabled={saving || !current || !next}>
            {saving ? "Saving…" : "Change password"}
          </Button>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Minimum {MIN_PASSWORD_LENGTH} characters. If this is a seeded development account, change it
          before the deployment is reachable by anyone else.
        </p>
      </Panel>
    </div>
  );
}
