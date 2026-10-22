// Shared dialogs and small building blocks used by more than one page:
// the inbound editor, the client editor (access + devices + subscription
// sources), the new-client form, the config/QR preview and a confirm hook.

import { useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  type Client,
  type Inbound,
  type KeyConfig,
  type RemoteSub,
} from "./api";
import {
  Badge,
  Button,
  CopyButton,
  ErrorBanner,
  Field,
  Input,
  Modal,
  Notice,
  QrCode,
  Select,
  Textarea,
  bytesToGbInput,
  dayToTs,
  fmtAgo,
  fmtDate,
  fmtLimit,
  gbToBytes,
  statusTone,
  tsToDayInput,
  useAction,
  useLoader,
} from "./ui";

/** What `POST /api/inbounds/{id}/clients` hands back. */
export type NewClientResult = KeyConfig & {
  user_id: number;
  sub_id: string;
  sub_url: string;
};

// ---------------------------------------------------------------------------
// Config + QR preview
// ---------------------------------------------------------------------------

export function ConfigPreview({
  config,
  subUrl,
  onClose,
}: {
  config: KeyConfig;
  subUrl?: string;
  onClose: () => void;
}) {
  return (
    <Modal title="Device config" onClose={onClose} wide>
      <div className="flex flex-col gap-4 sm:flex-row">
        <QrCode svg={config.qr_svg} />
        <div className="min-w-0 flex-1 space-y-3">
          <Field
            label="bproto:// config"
            hint="This string contains the pre-shared key. Anyone who has it can use the tunnel."
          >
            <Textarea readOnly rows={4} value={config.config_uri} className="font-mono text-xs" />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            <CopyButton value={config.config_uri} label="Copy config" />
            {subUrl && <CopyButton value={subUrl} label="Copy subscription URL" />}
            {subUrl && (
              <a href={subUrl} target="_blank" rel="noreferrer">
                <Button size="sm">Open subscription</Button>
              </a>
            )}
          </div>
          <Notice>
            Import it in the bProto client by scanning the QR or pasting the URI. Revoke the device
            from this dialog if the config leaks.
          </Notice>
        </div>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Confirm dialog
// ---------------------------------------------------------------------------

interface ConfirmRequest {
  title: string;
  body: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  /** Anything awaitable; the result is ignored. */
  onConfirm: () => unknown;
}

/** `const { confirm, dialog } = useConfirm();` then render `{dialog}`. */
export function useConfirm() {
  const [request, setRequest] = useState<ConfirmRequest | null>(null);
  const [busy, setBusy] = useState(false);

  const dialog = request ? (
    <Modal
      title={request.title}
      onClose={() => setRequest(null)}
      footer={
        <>
          <Button onClick={() => setRequest(null)} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={request.danger === false ? "primary" : "danger"}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await request.onConfirm();
                setRequest(null);
              } finally {
                setBusy(false);
              }
            }}
          >
            {request.confirmLabel ?? "Delete"}
          </Button>
        </>
      }
    >
      <div className="text-sm text-neutral-700">{request.body}</div>
    </Modal>
  ) : null;

  return { confirm: setRequest, dialog };
}

// ---------------------------------------------------------------------------
// Inbound editor
// ---------------------------------------------------------------------------

const FINGERPRINTS = [
  "chrome112",
  "chrome120",
  "chrome131",
  "firefox120",
  "firefox133",
  "safari17",
  "edge120",
  "random",
];

export function InboundDialog({
  inbound,
  onClose,
  onSaved,
}: {
  inbound: Inbound | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [remark, setRemark] = useState(inbound?.remark ?? "");
  const [server, setServer] = useState(inbound?.server ?? "");
  const [sni, setSni] = useState(inbound?.donor_sni ?? "www.cloudflare.com");
  const [fingerprint, setFingerprint] = useState(inbound?.fingerprint ?? "chrome112");
  const [port, setPort] = useState(inbound?.listen_port ? String(inbound.listen_port) : "443");
  const [note, setNote] = useState(inbound?.note ?? "");
  const { run, busy, error } = useAction();

  async function submit(e: FormEvent) {
    e.preventDefault();
    const payload = {
      remark,
      server,
      donor_sni: sni,
      fingerprint,
      listen_port: port ? Number(port) : null,
      note,
    };
    const result = await run(() =>
      inbound ? api.updateInbound(inbound.id, payload) : api.createInbound(payload),
    );
    if (result !== undefined) onSaved();
  }

  return (
    <Modal
      title={inbound ? `Edit inbound · ${inbound.remark}` : "New inbound"}
      onClose={onClose}
      wide
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" form="inbound-form" type="submit" disabled={busy}>
            {busy ? "Saving…" : inbound ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <ErrorBanner error={error} />
      <form id="inbound-form" onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
        <Field label="Remark" hint="Shown in the panel and in configs.">
          <Input value={remark} onChange={(e) => setRemark(e.target.value)} required autoFocus />
        </Field>
        <Field label="Server" hint="IP:port the clients dial. No hostnames: configs carry the address.">
          <Input
            value={server}
            onChange={(e) => setServer(e.target.value)}
            placeholder="203.0.113.10:443"
            required
          />
        </Field>
        <Field label="Donor SNI" hint="Site whose TLS identity the handshake borrows.">
          <Input value={sni} onChange={(e) => setSni(e.target.value)} required />
        </Field>
        <Field label="ClientHello fingerprint">
          <Input
            value={fingerprint}
            onChange={(e) => setFingerprint(e.target.value)}
            list="bui-fingerprints"
          />
          <datalist id="bui-fingerprints">
            {FINGERPRINTS.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
        </Field>
        <Field label="Listen port" hint="Informational: what the server binds. UDP 443 looks like QUIC.">
          <Input
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </Field>
        <Field label="Note">
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="optional" />
        </Field>
      </form>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// New client
// ---------------------------------------------------------------------------

export function NewClientDialog({
  inbound,
  onClose,
  onCreated,
}: {
  inbound: Inbound;
  onClose: () => void;
  onCreated: (result: NewClientResult) => void;
}) {
  const [username, setUsername] = useState("");
  const [limitGb, setLimitGb] = useState("");
  const [expiry, setExpiry] = useState("");
  const [label, setLabel] = useState("device");
  const [note, setNote] = useState("");
  const { run, busy, error } = useAction();

  async function submit(e: FormEvent) {
    e.preventDefault();
    const result = await run(() =>
      api.createClient(inbound.id, {
        username,
        traffic_limit_bytes: gbToBytes(limitGb),
        expires_at: dayToTs(expiry),
        label,
        note: note || undefined,
      }),
    );
    if (result) onCreated(result as NewClientResult);
  }

  return (
    <Modal
      title={`New client in ${inbound.remark}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" form="client-form" type="submit" disabled={busy}>
            {busy ? "Creating…" : "Create and show config"}
          </Button>
        </>
      }
    >
      <ErrorBanner error={error} />
      <form id="client-form" onSubmit={submit} className="space-y-3">
        <Field label="Username" hint="A label for the person or device owner.">
          <Input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="alice"
            required
            autoFocus
          />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Traffic limit, GB" hint="Empty or 0 means unlimited.">
            <Input
              type="number"
              min={0}
              step="0.1"
              value={limitGb}
              onChange={(e) => setLimitGb(e.target.value)}
              placeholder="unlimited"
            />
          </Field>
          <Field label="Expires" hint="Empty means never.">
            <Input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
          </Field>
        </div>
        <Field label="First device label" hint="One config is issued now; more devices can be added later.">
          <Input value={label} onChange={(e) => setLabel(e.target.value)} />
        </Field>
        <Field label="Note">
          <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="optional" />
        </Field>
      </form>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Client editor: access, devices, subscription sources
// ---------------------------------------------------------------------------

export function ClientDialog({
  clientId,
  onClose,
  onChanged,
}: {
  clientId: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { data, error, loading, reload } = useLoader(() => api.client(clientId), [clientId]);

  return (
    <Modal title={data ? `Client · ${data.username}` : "Client"} onClose={onClose} wide>
      <ErrorBanner error={error} />
      {loading && <p className="text-sm text-neutral-500">Loading…</p>}
      {data && (
        <ClientEditor
          client={data}
          onChanged={async () => {
            await reload();
            onChanged();
          }}
        />
      )}
    </Modal>
  );
}

function ClientEditor({ client, onChanged }: { client: Client; onChanged: () => Promise<void> }) {
  const [username, setUsername] = useState(client.username);
  const [inboundId, setInboundId] = useState<number | null>(client.inbound_id);
  const [limitGb, setLimitGb] = useState(bytesToGbInput(client.traffic_limit_bytes));
  const [expiry, setExpiry] = useState(tsToDayInput(client.expires_at));
  const [status, setStatus] = useState(client.status);
  const [note, setNote] = useState(client.note ?? "");
  const [newLabel, setNewLabel] = useState("device");
  const [config, setConfig] = useState<KeyConfig | null>(null);

  const inbounds = useLoader(() => api.inbounds(), []);
  const sources = useLoader(() => api.remoteSubs(), []);
  const attached = useLoader(() => api.clientRemoteSubs(client.id), [client.id]);

  const save = useAction(onChanged);
  const device = useAction(onChanged);
  const source = useAction(async () => {
    await attached.reload();
    await onChanged();
  });
  const { confirm, dialog } = useConfirm();

  async function saveAccess(e: FormEvent) {
    e.preventDefault();
    await save.run(() =>
      api.updateClient(client.id, {
        username,
        ...(inboundId !== null ? { inbound_id: inboundId } : {}),
        traffic_limit_bytes: gbToBytes(limitGb),
        expires_at: dayToTs(expiry),
        status,
        note,
      }),
    );
  }

  async function addDevice() {
    const result = await device.run(() => api.createKey(client.id, newLabel));
    if (result) setConfig(result as KeyConfig);
  }

  const attachedIds = new Set((attached.data ?? []).map((s) => s.id));
  const keys = client.key_list ?? [];

  return (
    <div className="space-y-5">
      {dialog}
      {config && (
        <ConfigPreview config={config} subUrl={client.sub_url} onClose={() => setConfig(null)} />
      )}

      {/* --- access ------------------------------------------------------- */}
      <section className="space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Access</h3>
        <ErrorBanner error={save.error} onDismiss={() => save.setError(null)} />
        <form onSubmit={saveAccess} className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Username">
              <Input value={username} onChange={(e) => setUsername(e.target.value)} required />
            </Field>
            <Field label="Inbound" hint="Where this client connects.">
              <Select
                value={inboundId ?? ""}
                onChange={(e) => setInboundId(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">— none —</option>
                {(inbounds.data ?? []).map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.remark} ({i.server})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Traffic limit, GB" hint="Empty or 0 means unlimited.">
              <Input
                type="number"
                min={0}
                step="0.1"
                value={limitGb}
                onChange={(e) => setLimitGb(e.target.value)}
              />
            </Field>
            <Field label="Expires" hint="Empty means never.">
              <Input type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
            </Field>
            <Field label="Status" hint="Disabled and revoked clients get no configs from the subscription.">
              <Select value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="active">active</option>
                <option value="disabled">disabled</option>
                <option value="revoked">revoked</option>
              </Select>
            </Field>
            <Field label="Note">
              <Input value={note} onChange={(e) => setNote(e.target.value)} />
            </Field>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs text-neutral-500">
              <span>Used: {fmtLimit(client.traffic_used_bytes)}</span>
              {client.online > 0 && <Badge tone="ok">online</Badge>}
            </div>
            <Button variant="primary" type="submit" disabled={save.busy}>
              {save.busy ? "Saving…" : "Save"}
            </Button>
          </div>
        </form>
        <Field label="Subscription URL">
          <div className="flex items-center gap-2">
            <Input readOnly value={client.sub_url} className="font-mono text-xs" />
            <CopyButton value={client.sub_url} />
            <a href={client.sub_url} target="_blank" rel="noreferrer">
              <Button size="sm">Open</Button>
            </a>
          </div>
        </Field>
      </section>

      {/* --- devices ------------------------------------------------------ */}
      <section className="space-y-3 border-t border-neutral-200 pt-4">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          Devices ({keys.length})
        </h3>
        <ErrorBanner error={device.error} onDismiss={() => device.setError(null)} />
        {keys.length === 0 ? (
          <p className="text-sm text-neutral-500">No devices yet.</p>
        ) : (
          <ul className="divide-y divide-neutral-100 rounded border border-neutral-200">
            {keys.map((key) => (
              <li key={key.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                <div className="min-w-0">
                  <p className="text-sm text-neutral-800">
                    {key.label}{" "}
                    <Badge tone={statusTone(key.status)}>{key.status}</Badge>
                  </p>
                  <p className="text-xs text-neutral-500">
                    created {fmtDate(key.created_at)}
                    {key.last_seen_ip ? ` · last seen ${key.last_seen_ip} (${fmtAgo(key.created_at)})` : ""}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    onClick={async () => {
                      const result = await device.run(() => api.keyConfig(key.id));
                      if (result) setConfig(result as KeyConfig);
                    }}
                  >
                    Config
                  </Button>
                  {key.status === "active" && (
                    <Button
                      size="sm"
                      onClick={() =>
                        confirm({
                          title: "Revoke device?",
                          body: `“${key.label}” stops working immediately; the config cannot be re-used.`,
                          confirmLabel: "Revoke",
                          onConfirm: () => device.run(() => api.revokeKey(key.id)),
                        })
                      }
                    >
                      Revoke
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() =>
                      confirm({
                        title: "Delete device?",
                        body: `“${key.label}” and its session history are removed.`,
                        onConfirm: () => device.run(() => api.deleteKey(key.id)),
                      })
                    }
                  >
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap items-end gap-2">
          <Field label="New device label" className="grow sm:grow-0">
            <Input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} />
          </Field>
          <Button onClick={addDevice} disabled={device.busy}>
            Add device
          </Button>
        </div>
      </section>

      {/* --- sources ------------------------------------------------------ */}
      <section className="space-y-3 border-t border-neutral-200 pt-4">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          Subscription sources
        </h3>
        <Notice>
          Attach a source from another bProto panel to include its configs in this client's
          subscription. The client then gets those credentials too.
        </Notice>
        <ErrorBanner error={source.error} onDismiss={() => source.setError(null)} />
        {(sources.data ?? []).length === 0 ? (
          <p className="text-sm text-neutral-500">
            No sources configured. Add one on the Subscriptions page.
          </p>
        ) : (
          <ul className="divide-y divide-neutral-100 rounded border border-neutral-200">
            {(sources.data ?? []).map((s: RemoteSub) => (
              <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate text-sm text-neutral-800">
                    {s.name}{" "}
                    <Badge tone={s.last_status === "error" ? "bad" : "neutral"}>
                      {s.entry_count} configs
                    </Badge>
                  </p>
                  <p className="truncate text-xs text-neutral-500">{s.url}</p>
                </div>
                {attachedIds.has(s.id) ? (
                  <Button
                    size="sm"
                    onClick={() =>
                      source.run(() => api.detachRemoteSub(client.id, s.id))
                    }
                  >
                    Detach
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    onClick={() => source.run(() => api.attachRemoteSub(client.id, s.id))}
                  >
                    Attach
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
