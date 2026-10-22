import { useState, type FormEvent } from "react";
import { api, type AdminRow } from "../api";
import { useConfirm } from "../components";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBanner,
  Field,
  Input,
  Modal,
  Notice,
  Table,
  Td,
  Th,
  fmtAgo,
  fmtDate,
  statusTone,
  useAction,
  useLoader,
} from "../ui";

const MIN_PASSWORD_LEN = 12;

export default function Settings({ username }: { username: string }) {
  const admins = useLoader(() => api.admins());
  const audit = useLoader(() => api.audit(100));

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [changed, setChanged] = useState(false);
  const changePassword = useAction();

  const [createOpen, setCreateOpen] = useState(false);
  const [newAdmin, setNewAdmin] = useState("");
  const [newAdminPassword, setNewAdminPassword] = useState("");
  const createAdmin = useAction(async () => {
    await admins.reload();
    setCreateOpen(false);
    setNewAdmin("");
    setNewAdminPassword("");
  });

  const [resetFor, setResetFor] = useState<AdminRow | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const resetAction = useAction(async () => {
    await admins.reload();
    setResetFor(null);
    setResetPassword("");
  });

  const adminAction = useAction(async () => {
    await admins.reload();
  });
  const { confirm, dialog } = useConfirm();

  const localError =
    next && repeat && next !== repeat ? "The two passwords do not match." : null;

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setChanged(false);
    const result = await changePassword.run(() => api.changePassword(current, next));
    if (result !== undefined) {
      setChanged(true);
      setCurrent("");
      setNext("");
      setRepeat("");
    }
  }

  return (
    <div className="space-y-4">
      {dialog}
      {createOpen && (
        <Modal
          title="New admin"
          onClose={() => setCreateOpen(false)}
          footer={
            <>
              <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button
                variant="primary"
                form="new-admin-form"
                type="submit"
                disabled={createAdmin.busy}
              >
                Create
              </Button>
            </>
          }
        >
          <ErrorBanner error={createAdmin.error} />
          <form
            id="new-admin-form"
            className="space-y-3"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              void createAdmin.run(() => api.createAdmin(newAdmin, newAdminPassword));
            }}
          >
            <Field label="Username">
              <Input
                value={newAdmin}
                onChange={(e) => setNewAdmin(e.target.value)}
                required
                autoFocus
              />
            </Field>
            <Field label="Password" hint={`At least ${MIN_PASSWORD_LEN} characters.`}>
              <Input
                type="password"
                value={newAdminPassword}
                onChange={(e) => setNewAdminPassword(e.target.value)}
                required
              />
            </Field>
          </form>
        </Modal>
      )}
      {resetFor && (
        <Modal
          title={`Reset password · ${resetFor.username}`}
          onClose={() => setResetFor(null)}
          footer={
            <>
              <Button onClick={() => setResetFor(null)}>Cancel</Button>
              <Button
                variant="primary"
                form="reset-form"
                type="submit"
                disabled={resetAction.busy}
              >
                Reset
              </Button>
            </>
          }
        >
          <ErrorBanner error={resetAction.error} />
          <form
            id="reset-form"
            className="space-y-3"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              void resetAction.run(() => api.resetAdminPassword(resetFor.id, resetPassword));
            }}
          >
            <Field
              label="New password"
              hint="Every session of that account is signed out."
            >
              <Input
                type="password"
                value={resetPassword}
                onChange={(e) => setResetPassword(e.target.value)}
                required
                autoFocus
              />
            </Field>
          </form>
        </Modal>
      )}

      <h1 className="text-lg font-semibold text-neutral-900">Settings</h1>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={`Change password · ${username}`}>
          <ErrorBanner
            error={changePassword.error}
            onDismiss={() => changePassword.setError(null)}
          />
          {changed && (
            <p className="mb-3 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
              Password changed. Other sessions of this account were signed out.
            </p>
          )}
          <form className="space-y-3" onSubmit={submitPassword}>
            <Field label="Current password">
              <Input
                type="password"
                autoComplete="current-password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                required
              />
            </Field>
            <Field
              label="New password"
              hint={`At least ${MIN_PASSWORD_LEN} characters; the change signs out other sessions.`}
            >
              <Input
                type="password"
                autoComplete="new-password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                required
                minLength={MIN_PASSWORD_LEN}
              />
            </Field>
            <Field label="Repeat new password">
              <Input
                type="password"
                autoComplete="new-password"
                value={repeat}
                onChange={(e) => setRepeat(e.target.value)}
                required
              />
            </Field>
            {localError && <p className="text-xs text-red-700">{localError}</p>}
            <Button
              variant="primary"
              type="submit"
              disabled={changePassword.busy || next.length < MIN_PASSWORD_LEN || !!localError}
            >
              {changePassword.busy ? "Changing…" : "Change password"}
            </Button>
          </form>
        </Card>

        <Card
          title="Admins"
          actions={
            <Button size="sm" variant="primary" onClick={() => setCreateOpen(true)}>
              New admin
            </Button>
          }
        >
          <ErrorBanner error={adminAction.error} onDismiss={() => adminAction.setError(null)} />
          <Table>
            <thead>
              <tr>
                <Th>Admin</Th>
                <Th>Status</Th>
                <Th>Sessions</Th>
                <Th>Last login</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {(admins.data ?? []).map((admin) => (
                <tr key={admin.id}>
                  <Td>
                    <span className="font-medium text-neutral-900">{admin.username}</span>
                    <span className="block text-xs text-neutral-500">
                      created {fmtDate(admin.created_at)}
                    </span>
                  </Td>
                  <Td>
                    <Badge tone={statusTone(admin.status)}>{admin.status}</Badge>
                  </Td>
                  <Td>{admin.sessions}</Td>
                  <Td>{fmtAgo(admin.last_login)}</Td>
                  <Td>
                    <div className="flex flex-wrap justify-end gap-1">
                      <Button
                        size="sm"
                        title="Set a new password for this admin"
                        onClick={() => setResetFor(admin)}
                      >
                        Reset
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() =>
                          confirm({
                            title: "Delete admin?",
                            body: `“${admin.username}” loses access immediately. Their audit entries stay.`,
                            onConfirm: () => adminAction.run(() => api.deleteAdmin(admin.id)),
                          })
                        }
                      >
                        Delete
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>

        <Card title="Server integration">
          <div className="space-y-3 text-sm text-neutral-700">
            <p>
              Servers push session deltas to this panel. Set <code>BPROTO_INTERNAL_TOKEN</code> on
              both sides, then:
            </p>
            <pre className="overflow-x-auto rounded border border-neutral-200 bg-neutral-50 p-3 text-xs text-neutral-700">
{`curl -sS -X POST "$PANEL/internal/v1/sessions/report" \\
  -H "Authorization: Bearer $BPROTO_INTERNAL_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"server_id":"de1","sessions":[
        {"tag":"0011223344556677","started_at":0,"ended_at":null,
         "bytes_rx":4096,"bytes_tx":2048,"peer_ip":"198.51.100.7"}]}'`}
            </pre>
            <Notice>
              Bytes are deltas since the previous report. A session with{" "}
              <code>ended_at: null</code> is live; the panel keeps one open row per device and
              closes rows that stop being refreshed.
            </Notice>
            <p>
              The endpoint stays disabled until <code>BPROTO_INTERNAL_TOKEN</code> is set, and it is
              never routed through the public Caddy vhost.
            </p>
          </div>
        </Card>
      </div>

      <Card
        title="Audit log"
        actions={
          <Button size="sm" onClick={() => void audit.reload()}>
            Refresh
          </Button>
        }
      >
        {audit.data && audit.data.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Admin</Th>
                <Th>Action</Th>
                <Th>Target</Th>
                <Th>IP</Th>
              </tr>
            </thead>
            <tbody>
              {audit.data.map((entry) => (
                <tr key={entry.id}>
                  <Td className="whitespace-nowrap">{fmtDate(entry.at)}</Td>
                  <Td>{entry.admin ?? `#${entry.admin_id ?? "?"}`}</Td>
                  <Td>
                    <code className="text-xs">{entry.action}</code>
                  </Td>
                  <Td>{entry.target || "—"}</Td>
                  <Td>{entry.ip ?? "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty>No audit entries yet.</Empty>
        )}
      </Card>
    </div>
  );
}
