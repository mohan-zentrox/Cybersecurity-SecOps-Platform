import { useCallback, useEffect, useState } from "react";

import { errorMessage, type Severity } from "@/api/client";
import {
  createChannel,
  createUser,
  deactivateUser,
  deleteChannel,
  listChannels,
  listDeliveries,
  listUsers,
  resetUserPassword,
  testChannel,
  updateChannel,
  updateUser,
  type Delivery,
  type NotificationChannel,
  type User,
} from "@/api/platform";
import { useToast } from "@/components/Toast";
import {
  Button,
  EmptyState,
  formatDateTime,
  inputClass,
  Loading,
  PageHeader,
  Panel,
  StatusBadge,
} from "@/components/ui";
import { ALL_ROLES, type Role } from "@/store/authStore";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
const CHANNEL_TYPES = ["log", "webhook", "slack", "email"];

export default function Settings() {
  const [tab, setTab] = useState<"users" | "channels" | "deliveries">("users");

  return (
    <div className="p-6">
      <PageHeader
        title="Settings"
        subtitle="User accounts, notification routing, and delivery history"
        actions={
          <div className="flex gap-2">
            <Button tone={tab === "users" ? "primary" : "secondary"} onClick={() => setTab("users")}>
              Users
            </Button>
            <Button tone={tab === "channels" ? "primary" : "secondary"} onClick={() => setTab("channels")}>
              Notifications
            </Button>
            <Button
              tone={tab === "deliveries" ? "primary" : "secondary"}
              onClick={() => setTab("deliveries")}
            >
              Deliveries
            </Button>
          </div>
        }
      />
      {tab === "users" && <UserAdmin />}
      {tab === "channels" && <ChannelAdmin />}
      {tab === "deliveries" && <DeliveryLog />}
    </div>
  );
}

function UserAdmin() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const page = await listUsers();
      setUsers(page.items);
    } catch (error) {
      toast.error(errorMessage(error, "Could not load users"));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function add() {
    try {
      await createUser({ username, email, password, role });
      toast.success(`Created ${username}`);
      setUsername("");
      setEmail("");
      setPassword("");
      setAdding(false);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not create user"));
    }
  }

  async function changeRole(user: User, nextRole: Role) {
    try {
      await updateUser(user.id, { role: nextRole });
      toast.success(`${user.username} is now ${nextRole}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not change role"));
    }
  }

  async function setActive(user: User, isActive: boolean) {
    try {
      if (isActive) await updateUser(user.id, { is_active: true });
      else await deactivateUser(user.id);
      toast.success(`${user.username} ${isActive ? "reactivated" : "deactivated"}`);
      refresh();
    } catch (error) {
      // The API refuses to remove the last admin, or your own account.
      toast.error(errorMessage(error, "Could not change account state"));
    }
  }

  async function reset(user: User) {
    const next = window.prompt(`New password for ${user.username} (minimum 12 characters):`);
    if (!next) return;
    try {
      await resetUserPassword(user.id, next);
      toast.success(`Password reset for ${user.username}`);
    } catch (error) {
      toast.error(errorMessage(error, "Password reset failed"));
    }
  }

  return (
    <>
      <Panel
        title="Accounts"
        className="mb-4"
        actions={
          <Button tone="primary" onClick={() => setAdding(!adding)}>
            {adding ? "Cancel" : "Add user"}
          </Button>
        }
      >
        {adding && (
          <div className="mb-4 grid gap-3 rounded border border-aegis-border bg-aegis-bg p-3 sm:grid-cols-4">
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username"
              className={inputClass}
              aria-label="New username"
            />
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="email@example.com"
              className={inputClass}
              aria-label="New user email"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="password (min 12 chars)"
              className={inputClass}
              aria-label="New user password"
            />
            <div className="flex gap-2">
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as Role)}
                className={`${inputClass} flex-1`}
                aria-label="New user role"
              >
                {ALL_ROLES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
              <Button tone="primary" onClick={add}>
                Create
              </Button>
            </div>
          </div>
        )}

        {loading ? (
          <Loading />
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr className="border-b border-aegis-border">
                <th className="py-2">Username</th>
                <th className="py-2">Email</th>
                <th className="py-2">Role</th>
                <th className="py-2">Active</th>
                <th className="py-2">Created</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-aegis-border/50">
                  <td className="py-2 text-slate-200">{user.username}</td>
                  <td className="py-2 text-xs text-slate-400">{user.email}</td>
                  <td className="py-2">
                    <select
                      value={user.role}
                      onChange={(e) => changeRole(user, e.target.value as Role)}
                      className={`${inputClass} text-xs`}
                      aria-label={`Role for ${user.username}`}
                    >
                      {ALL_ROLES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="py-2">
                    <span className={user.is_active ? "text-emerald-400" : "text-slate-500"}>
                      {user.is_active ? "yes" : "no"}
                    </span>
                  </td>
                  <td className="py-2 text-xs text-slate-400">{formatDateTime(user.created_at)}</td>
                  <td className="py-2 text-right">
                    <div className="flex justify-end gap-2">
                      <Button onClick={() => reset(user)}>Reset password</Button>
                      <Button
                        tone={user.is_active ? "danger" : "secondary"}
                        onClick={() => setActive(user, !user.is_active)}
                      >
                        {user.is_active ? "Deactivate" : "Reactivate"}
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="mt-3 text-xs text-slate-500">
          Accounts are deactivated rather than deleted so historical alert assignments and audit entries
          keep resolving to a real user.
        </p>
      </Panel>
    </>
  );
}

function ChannelAdmin() {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);

  const [name, setName] = useState("");
  const [type, setType] = useState("webhook");
  const [minSeverity, setMinSeverity] = useState<Severity>("high");
  const [url, setUrl] = useState("");

  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setChannels(await listChannels());
    } catch (error) {
      toast.error(errorMessage(error, "Could not load channels"));
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function add() {
    try {
      await createChannel({
        name,
        type,
        min_severity: minSeverity,
        config: type === "webhook" || type === "slack" ? { url } : {},
      });
      toast.success(`Created channel ${name}`);
      setName("");
      setUrl("");
      setAdding(false);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not create channel"));
    }
  }

  async function test(channel: NotificationChannel) {
    try {
      const result = await testChannel(channel.id);
      if (result.status === "sent") toast.success(`${channel.name}: ${result.detail}`);
      else toast.error(`${channel.name}: ${result.detail}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Test send failed"));
    }
  }

  async function toggle(channel: NotificationChannel) {
    try {
      await updateChannel(channel.id, { enabled: !channel.enabled });
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not update channel"));
    }
  }

  async function remove(channel: NotificationChannel) {
    try {
      await deleteChannel(channel.id);
      toast.success(`Deleted ${channel.name}`);
      refresh();
    } catch (error) {
      toast.error(errorMessage(error, "Could not delete channel"));
    }
  }

  return (
    <Panel
      title="Notification channels"
      actions={
        <Button tone="primary" onClick={() => setAdding(!adding)}>
          {adding ? "Cancel" : "Add channel"}
        </Button>
      }
    >
      {adding && (
        <div className="mb-4 grid gap-3 rounded border border-aegis-border bg-aegis-bg p-3 sm:grid-cols-4">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="channel name"
            className={inputClass}
            aria-label="Channel name"
          />
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className={inputClass}
            aria-label="Channel type"
          >
            {CHANNEL_TYPES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <select
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value as Severity)}
            className={inputClass}
            aria-label="Minimum severity"
          >
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                min: {value}
              </option>
            ))}
          </select>
          <div className="flex gap-2">
            {(type === "webhook" || type === "slack") && (
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://hooks…"
                className={`${inputClass} flex-1`}
                aria-label="Webhook URL"
              />
            )}
            <Button tone="primary" onClick={add}>
              Create
            </Button>
          </div>
        </div>
      )}

      {loading ? (
        <Loading />
      ) : channels.length === 0 ? (
        <EmptyState
          message="No notification channels configured."
          hint="Without a channel, alerts are recorded but nobody is told."
        />
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-slate-500">
            <tr className="border-b border-aegis-border">
              <th className="py-2">Name</th>
              <th className="py-2">Type</th>
              <th className="py-2">Min severity</th>
              <th className="py-2">Enabled</th>
              <th className="py-2" />
            </tr>
          </thead>
          <tbody>
            {channels.map((channel) => (
              <tr key={channel.id} className="border-b border-aegis-border/50">
                <td className="py-2 text-slate-200">{channel.name}</td>
                <td className="py-2 text-slate-400">{channel.type}</td>
                <td className="py-2">
                  <StatusBadge value={channel.min_severity} />
                </td>
                <td className="py-2">
                  <span className={channel.enabled ? "text-emerald-400" : "text-slate-500"}>
                    {channel.enabled ? "yes" : "no"}
                  </span>
                </td>
                <td className="py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <Button onClick={() => test(channel)}>Send test</Button>
                    <Button onClick={() => toggle(channel)}>
                      {channel.enabled ? "Disable" : "Enable"}
                    </Button>
                    <Button tone="danger" onClick={() => remove(channel)}>
                      Delete
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="mt-3 text-xs text-slate-500">
        Only <code>http</code> and <code>https</code> webhook URLs are accepted — other schemes are
        rejected before the request is made.
      </p>
    </Panel>
  );
}

function DeliveryLog() {
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  useEffect(() => {
    listDeliveries({ limit: 100 })
      .then((page) => setDeliveries(page.items))
      .catch((error) => toast.error(errorMessage(error, "Could not load delivery history")))
      .finally(() => setLoading(false));
  }, [toast]);

  if (loading) return <Loading />;

  return (
    <Panel title="Delivery history">
      <p className="mb-3 text-xs text-slate-500">
        Proof of whether a page actually went out. Every dispatch attempt is recorded, including the ones
        that were skipped for being below a channel severity floor.
      </p>
      {deliveries.length === 0 ? (
        <EmptyState message="No notifications have been dispatched yet." />
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-slate-500">
            <tr className="border-b border-aegis-border">
              <th className="py-2">Time</th>
              <th className="py-2">Channel</th>
              <th className="py-2">Subject</th>
              <th className="py-2">Status</th>
              <th className="py-2">Detail</th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((delivery) => (
              <tr key={delivery.id} className="border-b border-aegis-border/50">
                <td className="py-2 text-xs text-slate-400">{formatDateTime(delivery.attempted_at)}</td>
                <td className="py-2 text-slate-200">
                  {delivery.channel_name}
                  <span className="ml-1 text-xs text-slate-500">({delivery.channel_type})</span>
                </td>
                <td className="py-2 text-xs text-slate-400">
                  {delivery.subject_type}
                  {delivery.subject_id ? ` #${delivery.subject_id}` : ""}
                </td>
                <td className="py-2">
                  <StatusBadge value={delivery.status} />
                </td>
                <td className="py-2 text-xs text-slate-400">{delivery.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
