import { useState } from "react";
import { api, type Client, type Inbound, type KeyConfig } from "../api";
import {
  ClientDialog,
  ConfigPreview,
  InboundDialog,
  NewClientDialog,
  useConfirm,
} from "../components";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  Empty,
  ErrorBanner,
  Table,
  Td,
  Th,
  fmtBytes,
  fmtExpiry,
  fmtLimit,
  statusTone,
  useAction,
  useLoader,
} from "../ui";

export default function Inbounds() {
  const inbounds = useLoader(() => api.inbounds());
  const [editing, setEditing] = useState<Inbound | null>(null);
  const [creating, setCreating] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [newClientFor, setNewClientFor] = useState<Inbound | null>(null);
  const [config, setConfig] = useState<{ config: KeyConfig; subUrl?: string } | null>(null);
  const [editClientId, setEditClientId] = useState<number | null>(null);

  const action = useAction(inbounds.reload);
  const { confirm, dialog } = useConfirm();

  return (
    <div className="space-y-4">
      {dialog}
      {creating && (
        <InboundDialog
          inbound={null}
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            void inbounds.reload();
          }}
        />
      )}
      {editing && (
        <InboundDialog
          inbound={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void inbounds.reload();
          }}
        />
      )}
      {newClientFor && (
        <NewClientDialog
          inbound={newClientFor}
          onClose={() => setNewClientFor(null)}
          onCreated={(result) => {
            setNewClientFor(null);
            void inbounds.reload();
            setConfig({ config: result, subUrl: result.sub_url });
          }}
        />
      )}
      {config && (
        <ConfigPreview
          config={config.config}
          subUrl={config.subUrl}
          onClose={() => setConfig(null)}
        />
      )}
      {editClientId !== null && (
        <ClientDialog
          clientId={editClientId}
          onClose={() => setEditClientId(null)}
          onChanged={() => void inbounds.reload()}
        />
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold text-neutral-900">Inbounds</h1>
        <div className="flex gap-2">
          <Button onClick={() => void inbounds.reload()}>Refresh</Button>
          <Button variant="primary" onClick={() => setCreating(true)}>
            New inbound
          </Button>
        </div>
      </div>

      <ErrorBanner
        error={action.error ?? inbounds.error}
        onDismiss={() => {
          action.setError(null);
          inbounds.setError(null);
        }}
      />

      <Card>
        {inbounds.data && inbounds.data.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>Inbound</Th>
                <Th>Endpoint</Th>
                <Th>Donor / fingerprint</Th>
                <Th>Status</Th>
                <Th>Clients</Th>
                <Th>Online</Th>
                <Th className="text-right">Traffic</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {inbounds.data.map((inbound) => (
                <InboundRow
                  key={inbound.id}
                  inbound={inbound}
                  expanded={expanded === inbound.id}
                  onToggle={() => setExpanded(expanded === inbound.id ? null : inbound.id)}
                  onEdit={() => setEditing(inbound)}
                  onAddClient={() => setNewClientFor(inbound)}
                  onEditClient={setEditClientId}
                  onToggleStatus={() =>
                    action.run(() =>
                      api.updateInbound(inbound.id, {
                        status: inbound.status === "active" ? "disabled" : "active",
                      }),
                    )
                  }
                  onReset={() =>
                    confirm({
                      title: "Reset traffic?",
                      body: `Zero the traffic counters of all ${inbound.clients} clients of “${inbound.remark}”. Session history stays.`,
                      confirmLabel: "Reset",
                      danger: false,
                      onConfirm: () => action.run(() => api.resetInboundTraffic(inbound.id)),
                    })
                  }
                  onDelete={() =>
                    confirm({
                      title: "Delete inbound?",
                      body:
                        inbound.clients > 0
                          ? `“${inbound.remark}” and its ${inbound.clients} clients (with their keys and history) are removed. This cannot be undone.`
                          : `Delete “${inbound.remark}”?`,
                      onConfirm: () => action.run(() => api.deleteInbound(inbound.id, true)),
                    })
                  }
                />
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty>
            No inbounds yet. An inbound is one bProto endpoint: the address clients dial, the donor
            SNI and the ClientHello fingerprint.
          </Empty>
        )}
      </Card>
    </div>
  );
}

function InboundRow({
  inbound,
  expanded,
  onToggle,
  onEdit,
  onAddClient,
  onEditClient,
  onToggleStatus,
  onReset,
  onDelete,
}: {
  inbound: Inbound;
  expanded: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onAddClient: () => void;
  onEditClient: (id: number) => void;
  onToggleStatus: () => void;
  onReset: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <tr className={expanded ? "bg-neutral-50" : undefined}>
        <Td>
          <span className="font-medium text-neutral-900">{inbound.remark}</span>
          {inbound.note && <span className="block text-xs text-neutral-500">{inbound.note}</span>}
        </Td>
        <Td>
          <span className="font-mono text-xs">{inbound.server}</span>
          <span className="block text-xs text-neutral-500">udp/{inbound.listen_port ?? "?"}</span>
        </Td>
        <Td>
          <span className="text-xs">{inbound.donor_sni}</span>
          <span className="block text-xs text-neutral-500">{inbound.fingerprint}</span>
        </Td>
        <Td>
          <Badge tone={statusTone(inbound.status)}>{inbound.status}</Badge>
        </Td>
        <Td>
          {inbound.active_clients}/{inbound.clients}
          <span className="block text-xs text-neutral-500">{inbound.active_keys} keys</span>
        </Td>
        <Td>{inbound.online > 0 ? <Badge tone="ok">{inbound.online}</Badge> : "—"}</Td>
        <Td className="text-right">{fmtBytes(inbound.traffic_used_bytes)}</Td>
        <Td>
          <div className="flex flex-wrap justify-end gap-1">
            <Button size="sm" onClick={onToggle}>
              {expanded ? "Hide" : "Clients"}
            </Button>
            <Button size="sm" onClick={onAddClient}>
              + Client
            </Button>
            <Button size="sm" onClick={onEdit}>
              Edit
            </Button>
            <Button size="sm" onClick={onToggleStatus}>
              {inbound.status === "active" ? "Disable" : "Enable"}
            </Button>
            <Button size="sm" onClick={onReset}>
              Reset traffic
            </Button>
            <Button size="sm" variant="danger" onClick={onDelete}>
              Delete
            </Button>
          </div>
        </Td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8} className="bg-neutral-50 px-3 pb-4">
            <InboundClients inbound={inbound} onEditClient={onEditClient} />
          </td>
        </tr>
      )}
    </>
  );
}

function InboundClients({
  inbound,
  onEditClient,
}: {
  inbound: Inbound;
  onEditClient: (id: number) => void;
}) {
  const clients = useLoader(() => api.clients(inbound.id), [inbound.id]);
  const action = useAction(clients.reload);
  const { confirm, dialog } = useConfirm();

  return (
    <div className="rounded-md border border-neutral-200 bg-white p-3">
      {dialog}
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
          Clients of {inbound.remark}
        </h3>
        <Button size="sm" onClick={() => void clients.reload()}>
          Refresh
        </Button>
      </div>
      <ErrorBanner error={action.error} onDismiss={() => action.setError(null)} />
      {clients.data && clients.data.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Client</Th>
              <Th>Status</Th>
              <Th>Used / limit</Th>
              <Th>Expires</Th>
              <Th>Devices</Th>
              <Th>Sources</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {clients.data.map((client: Client) => (
              <tr key={client.id}>
                <Td>
                  <span className="font-medium text-neutral-900">{client.username}</span>
                  {client.online > 0 && <Badge tone="ok">online</Badge>}
                </Td>
                <Td>
                  <Badge tone={statusTone(client.status)}>{client.status}</Badge>
                </Td>
                <Td>
                  {fmtLimit(client.traffic_used_bytes)} / {fmtLimit(client.traffic_limit_bytes)}
                  <UsageBar used={client.traffic_used_bytes} limit={client.traffic_limit_bytes} />
                </Td>
                <Td>{fmtExpiry(client.expires_at)}</Td>
                <Td>
                  {client.active_keys}/{client.keys}
                </Td>
                <Td>{client.remote_subs}</Td>
                <Td>
                  <div className="flex flex-wrap justify-end gap-1">
                    <Button size="sm" onClick={() => onEditClient(client.id)}>
                      Manage
                    </Button>
                    <CopyButton value={client.sub_url} label="Sub URL" />
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() =>
                        confirm({
                          title: "Delete client?",
                          body: `“${client.username}” and its devices are removed.`,
                          onConfirm: () => action.run(() => api.deleteClient(client.id)),
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
      ) : (
        <Empty>No clients in this inbound yet.</Empty>
      )}
      <p className="mt-2 text-xs text-neutral-500">
        Adding a client happens from the row's <em>+ Client</em> button; per-device configs live
        under <em>Manage</em>.
      </p>
    </div>
  );
}

/** Traffic bar, red once the client is over its limit. */
function UsageBar({ used, limit }: { used: number; limit: number | null }) {
  if (!limit) return null;
  const percent = Math.min(100, Math.round((used / limit) * 100));
  const over = used >= limit;
  return (
    <span className="mt-1 block h-1 w-24 overflow-hidden rounded bg-neutral-200">
      <span
        className={`block h-full ${over ? "bg-red-500" : "bg-neutral-700"}`}
        style={{ width: `${percent}%` }}
      />
    </span>
  );
}
