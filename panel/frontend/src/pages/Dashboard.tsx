import { api } from "../api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorBanner,
  Notice,
  Stat,
  Table,
  Td,
  Th,
  TrafficChart,
  fmtAgo,
  fmtBytes,
  fmtLimit,
  fmtUptime,
  useAction,
  useLoader,
} from "../ui";

export default function Dashboard() {
  const overview = useLoader(() => api.overview());
  const inbounds = useLoader(() => api.statsInbounds());
  const top = useLoader(() => api.topClients(10));
  const sessions = useLoader(() => api.sessions(25));
  const system = useLoader(() => api.system());

  const demo = useAction(async () => {
    await overview.reload();
    await sessions.reload();
    await top.reload();
  });

  async function refresh() {
    await Promise.all([
      overview.reload(),
      inbounds.reload(),
      top.reload(),
      sessions.reload(),
      system.reload(),
    ]);
  }

  const data = overview.data;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold text-neutral-900">Dashboard</h1>
        <div className="flex flex-wrap gap-2">
          <Button onClick={refresh}>Refresh</Button>
          <Button
            onClick={() => demo.run(() => api.seedDemo(48))}
            disabled={demo.busy}
            title="Insert demo sessions over the last 24h, for looking at the graphs"
          >
            Add demo traffic
          </Button>
          <Button
            variant="danger"
            onClick={() => demo.run(() => api.clearDemo())}
            disabled={demo.busy}
          >
            Clear demo
          </Button>
        </div>
      </div>

      <ErrorBanner
        error={overview.error ?? demo.error}
        onDismiss={() => {
          overview.setError(null);
          demo.setError(null);
        }}
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Online now"
          value={data?.online ?? "—"}
          hint={`${data?.active_keys ?? 0} active configs`}
        />
        <Stat
          label="Clients"
          value={data?.clients ?? "—"}
          hint={`${data?.active_clients ?? 0} active · ${data?.admins ?? 0} admins`}
        />
        <Stat
          label="Inbounds"
          value={data?.inbounds ?? "—"}
          hint={`${data?.active_inbounds ?? 0} enabled`}
        />
        <Stat
          label="Traffic, last 24h"
          value={data ? fmtBytes(data.bytes_rx_24h + data.bytes_tx_24h) : "—"}
          hint={
            data ? `↑ ${fmtBytes(data.bytes_rx_24h)} · ↓ ${fmtBytes(data.bytes_tx_24h)}` : undefined
          }
        />
        <Stat
          label="Traffic, lifetime"
          value={data ? fmtBytes(data.bytes_rx + data.bytes_tx) : "—"}
          hint={data ? `↑ ${fmtBytes(data.bytes_rx)} · ↓ ${fmtBytes(data.bytes_tx)}` : undefined}
        />
        <Stat
          label="Counted against limits"
          value={data ? fmtLimit(data.traffic_used_bytes) : "—"}
          hint="Sum of client counters; resets clear them"
        />
        <Stat label="Sessions" value={data?.sessions ?? "—"} hint="Closed and open rows" />
        <Stat
          label="Remote sources"
          value={data?.remote_subs ?? "—"}
          hint="Subscriptions from other bProto panels"
        />
      </div>

      <Card title="Traffic, last 24 hours">
        {data ? <TrafficChart series={data.series_24h} /> : <p className="text-sm text-neutral-500">Loading…</p>}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="By inbound">
          {inbounds.data && inbounds.data.length > 0 ? (
            <Table>
              <thead>
                <tr>
                  <Th>Inbound</Th>
                  <Th>Clients</Th>
                  <Th>Online</Th>
                  <Th className="text-right">Traffic</Th>
                </tr>
              </thead>
              <tbody>
                {inbounds.data.map((inbound) => (
                  <tr key={inbound.id}>
                    <Td>
                      <span className="font-medium text-neutral-900">{inbound.remark}</span>
                      <span className="block text-xs text-neutral-500">{inbound.server}</span>
                    </Td>
                    <Td>
                      {inbound.active_clients}/{inbound.clients}
                    </Td>
                    <Td>
                      {inbound.online > 0 ? (
                        <Badge tone="ok">{inbound.online} online</Badge>
                      ) : (
                        <span className="text-neutral-400">—</span>
                      )}
                    </Td>
                    <Td className="text-right">{fmtBytes(inbound.traffic_used_bytes)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Empty>No inbounds yet.</Empty>
          )}
        </Card>

        <Card title="Top clients">
          {top.data && top.data.length > 0 ? (
            <Table>
              <thead>
                <tr>
                  <Th>Client</Th>
                  <Th>Inbound</Th>
                  <Th className="text-right">Used</Th>
                  <Th className="text-right">Limit</Th>
                </tr>
              </thead>
              <tbody>
                {top.data.map((client) => (
                  <tr key={client.id}>
                    <Td>
                      <span className="font-medium text-neutral-900">{client.username}</span>
                      {client.online && <Badge tone="ok">online</Badge>}
                    </Td>
                    <Td>{client.inbound_remark ?? "—"}</Td>
                    <Td className="text-right">{fmtBytes(client.traffic_used_bytes)}</Td>
                    <Td className="text-right">{fmtLimit(client.traffic_limit_bytes)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <Empty>No clients yet.</Empty>
          )}
        </Card>
      </div>

      <Card title="Recent sessions">
        {sessions.data && sessions.data.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>Client</Th>
                <Th>Device</Th>
                <Th>Server</Th>
                <Th>Started</Th>
                <Th className="text-right">Up</Th>
                <Th className="text-right">Down</Th>
                <Th>Peer</Th>
                <Th>State</Th>
              </tr>
            </thead>
            <tbody>
              {sessions.data.map((session) => (
                <tr key={session.id}>
                  <Td>{session.username}</Td>
                  <Td>{session.key_label}</Td>
                  <Td>{session.server_id ?? "—"}</Td>
                  <Td className="whitespace-nowrap">{fmtAgo(session.started_at)}</Td>
                  <Td className="text-right">{fmtBytes(session.bytes_rx)}</Td>
                  <Td className="text-right">{fmtBytes(session.bytes_tx)}</Td>
                  <Td>{session.peer_ip ?? "—"}</Td>
                  <Td>
                    {session.online ? <Badge tone="ok">live</Badge> : <Badge>closed</Badge>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty>
            No sessions reported yet. Servers post to <code>/internal/v1/sessions/report</code>.
          </Empty>
        )}
      </Card>

      <Card title="Panel host">
        {system.data ? (
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Version</dt>
              <dd className="text-neutral-800">
                {system.data.panel} {system.data.version}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Uptime</dt>
              <dd className="text-neutral-800">{fmtUptime(system.data.uptime_secs)}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Load</dt>
              <dd className="text-neutral-800">
                {system.data.load.length ? system.data.load.join(" / ") : "—"} ({system.data.cpus} cpus)
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Memory free</dt>
              <dd className="text-neutral-800">
                {fmtBytes(system.data.mem_available)} / {fmtBytes(system.data.mem_total)}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Database</dt>
              <dd className="text-neutral-800">{fmtBytes(system.data.db_bytes)}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Online keys</dt>
              <dd className="text-neutral-800">{system.data.clients_online}</dd>
            </div>
          </dl>
        ) : (
          <p className="text-sm text-neutral-500">Loading…</p>
        )}
        <div className="mt-3">
          <Notice>
            Client expiry comes from the panel; the last column of <em>Top clients</em> uses the
            same “0 = unlimited” convention as everywhere else.
          </Notice>
        </div>
      </Card>
    </div>
  );
}
