import { useMemo, useState } from "react";
import { api, type Client, type Inbound, type KeyConfig } from "../api";
import { ClientDialog, ConfigPreview, NewClientDialog, useConfirm } from "../components";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  Empty,
  ErrorBanner,
  Field,
  Input,
  Modal,
  Select,
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

export default function Clients() {
  const [inboundFilter, setInboundFilter] = useState<number | undefined>(undefined);
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [pickingInbound, setPickingInbound] = useState(false);
  const [newClientFor, setNewClientFor] = useState<Inbound | null>(null);
  const [editClientId, setEditClientId] = useState<number | null>(null);
  const [config, setConfig] = useState<{ config: KeyConfig; subUrl?: string } | null>(null);

  const inbounds = useLoader(() => api.inbounds());
  const clients = useLoader(() => api.clients(inboundFilter), [inboundFilter]);
  const action = useAction(clients.reload);
  const { confirm, dialog } = useConfirm();

  const filtered = useMemo(() => {
    const list = clients.data ?? [];
    const needle = search.trim().toLowerCase();
    return list.filter((client) => {
      if (statusFilter !== "all" && client.status !== statusFilter) return false;
      if (needle && !client.username.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [clients.data, search, statusFilter]);

  return (
    <div className="space-y-4">
      {dialog}
      {pickingInbound && (
        <Modal title="New client" onClose={() => setPickingInbound(false)}>
          <p className="text-sm text-neutral-700">
            A client lives inside an inbound. Pick where this one connects:
          </p>
          {(inbounds.data ?? []).length === 0 ? (
            <p className="text-sm text-neutral-500">
              There are no inbounds yet. Create one on the Inbounds page first.
            </p>
          ) : (
            <ul className="divide-y divide-neutral-100 rounded border border-neutral-200">
              {(inbounds.data ?? []).map((inbound) => (
                <li key={inbound.id} className="flex items-center justify-between gap-2 px-3 py-2">
                  <div>
                    <p className="text-sm text-neutral-800">{inbound.remark}</p>
                    <p className="font-mono text-xs text-neutral-500">{inbound.server}</p>
                  </div>
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => {
                      setNewClientFor(inbound);
                      setPickingInbound(false);
                    }}
                  >
                    Choose
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Modal>
      )}
      {newClientFor && (
        <NewClientDialog
          inbound={newClientFor}
          onClose={() => setNewClientFor(null)}
          onCreated={(result) => {
            setNewClientFor(null);
            void clients.reload();
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
          onChanged={() => void clients.reload()}
        />
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold text-neutral-900">Clients</h1>
        <div className="flex gap-2">
          <Button onClick={() => void clients.reload()}>Refresh</Button>
          <Button variant="primary" onClick={() => setPickingInbound(true)}>
            New client
          </Button>
        </div>
      </div>

      <ErrorBanner
        error={action.error ?? clients.error}
        onDismiss={() => {
          action.setError(null);
          clients.setError(null);
        }}
      />

      <Card>
        <div className="mb-3 grid gap-2 sm:grid-cols-3">
          <Field label="Inbound">
            <Select
              value={inboundFilter ?? ""}
              onChange={(e) => setInboundFilter(e.target.value ? Number(e.target.value) : undefined)}
            >
              <option value="">All inbounds</option>
              {(inbounds.data ?? []).map((inbound) => (
                <option key={inbound.id} value={inbound.id}>
                  {inbound.remark}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Status">
            <Select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">All</option>
              <option value="active">active</option>
              <option value="disabled">disabled</option>
              <option value="revoked">revoked</option>
            </Select>
          </Field>
          <Field label="Search">
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="username"
            />
          </Field>
        </div>

        {filtered.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>Client</Th>
                <Th>Inbound</Th>
                <Th>Status</Th>
                <Th>Used / limit</Th>
                <Th>Expires</Th>
                <Th>Devices</Th>
                <Th>Subscription</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {filtered.map((client: Client) => (
                <tr key={client.id}>
                  <Td>
                    <span className="font-medium text-neutral-900">{client.username}</span>
                    {client.online > 0 && <Badge tone="ok">online</Badge>}
                    {client.note && (
                      <span className="block text-xs text-neutral-500">{client.note}</span>
                    )}
                  </Td>
                  <Td>{client.inbound_remark ?? "—"}</Td>
                  <Td>
                    <Badge tone={statusTone(client.status)}>{client.status}</Badge>
                  </Td>
                  <Td>
                    {fmtBytes(client.traffic_used_bytes)} / {fmtLimit(client.traffic_limit_bytes)}
                    <UsageBar used={client.traffic_used_bytes} limit={client.traffic_limit_bytes} />
                  </Td>
                  <Td>{fmtExpiry(client.expires_at)}</Td>
                  <Td>
                    {client.active_keys}/{client.keys}
                    {client.remote_subs > 0 && (
                      <span className="block text-xs text-neutral-500">
                        +{client.remote_subs} source{client.remote_subs > 1 ? "s" : ""}
                      </span>
                    )}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      <CopyButton value={client.sub_url} label="Copy" />
                      <a href={client.sub_url} target="_blank" rel="noreferrer">
                        <Button size="sm">Open</Button>
                      </a>
                    </div>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap justify-end gap-1">
                      <Button size="sm" onClick={() => setEditClientId(client.id)}>
                        Manage
                      </Button>
                      <Button
                        size="sm"
                        onClick={() =>
                          action.run(() => api.resetClientTraffic(client.id))
                        }
                        title="Zero this client's traffic counter"
                      >
                        Reset
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() =>
                          confirm({
                            title: "Delete client?",
                            body: `“${client.username}”, its devices and its session history are removed.`,
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
          <Empty>
            {clients.loading ? "Loading…" : "No clients match. Create one with “New client”."}
          </Empty>
        )}
      </Card>
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
