import { useState, type FormEvent } from "react";
import { api, type RemoteEntry, type RemoteSub, type SubItem } from "../api";
import { ClientDialog, useConfirm } from "../components";
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
  Notice,
  Table,
  Td,
  Th,
  fmtAgo,
  fmtBytes,
  fmtExpiry,
  fmtLimit,
  statusTone,
  useAction,
  useLoader,
} from "../ui";

interface PreviewItem {
  uri: string;
  server: string | null;
  sni: string | null;
  label: string | null;
}

interface PreviewData {
  title: string;
  sub_id: string;
  username: string;
  count: number;
  clients: PreviewItem[];
}

export default function Subscriptions() {
  const subs = useLoader(() => api.subscriptions());
  const sources = useLoader(() => api.remoteSubs());
  const settings = useLoader(() => api.subSettings());
  const [baseUrl, setBaseUrl] = useState<string | null>(null);
  const [title, setTitle] = useState<string | null>(null);
  const [preview, setPreview] = useState<SubItem | null>(null);
  const [entriesFor, setEntriesFor] = useState<RemoteSub | null>(null);
  const [manageClient, setManageClient] = useState<number | null>(null);
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");

  const saveSettings = useAction(async () => {
    await subs.reload();
  });
  const addSource = useAction(async () => {
    await sources.reload();
    setNewName("");
    setNewUrl("");
  });
  const sourceAction = useAction(async () => {
    await sources.reload();
    await subs.reload();
  });
  const { confirm, dialog } = useConfirm();

  const effectiveBase = baseUrl ?? settings.data?.sub_base_url ?? "";
  const effectiveTitle = title ?? settings.data?.sub_title ?? "";

  return (
    <div className="space-y-4">
      {dialog}
      {preview && <SubPreview item={preview} onClose={() => setPreview(null)} />}
      {entriesFor && <SourceEntries source={entriesFor} onClose={() => setEntriesFor(null)} />}
      {manageClient !== null && (
        <ClientDialog
          clientId={manageClient}
          onClose={() => setManageClient(null)}
          onChanged={() => {
            void subs.reload();
            void sources.reload();
          }}
        />
      )}

      <h1 className="text-lg font-semibold text-neutral-900">Subscriptions</h1>

      <Card title="Subscription settings">
        <ErrorBanner
          error={saveSettings.error}
          onDismiss={() => saveSettings.setError(null)}
        />
        <form
          className="grid gap-3 sm:grid-cols-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            void saveSettings.run(() =>
              api.updateSubSettings({ sub_base_url: effectiveBase, sub_title: effectiveTitle }),
            );
          }}
        >
          <Field
            label="Public base URL"
            hint="How clients reach this panel. Empty falls back to the request's Host header."
          >
            <Input
              value={effectiveBase}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://panel.example.com"
            />
          </Field>
          <Field label="Profile title" hint="Shown by importers; defaults to bUI · <username>.">
            <Input
              value={effectiveTitle}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="bUI"
            />
          </Field>
          <div className="sm:col-span-2">
            <Button variant="primary" type="submit" disabled={saveSettings.busy}>
              {saveSettings.busy ? "Saving…" : "Save settings"}
            </Button>
          </div>
        </form>
      </Card>

      <Card title="Client subscriptions">
        {subs.data && subs.data.items.length > 0 ? (
          <Table>
            <thead>
              <tr>
                <Th>Client</Th>
                <Th>Subscription URL</Th>
                <Th>Status</Th>
                <Th>Used / limit</Th>
                <Th>Expires</Th>
                <Th>Configs</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {subs.data.items.map((item) => (
                <tr key={item.user_id}>
                  <Td>
                    <span className="font-medium text-neutral-900">{item.username}</span>
                    {item.inbound_remark && (
                      <span className="block text-xs text-neutral-500">{item.inbound_remark}</span>
                    )}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap items-center gap-1">
                      <CopyButton value={item.sub_url} label="Copy" />
                      <a href={item.sub_url} target="_blank" rel="noreferrer">
                        <Button size="sm">Open</Button>
                      </a>
                    </div>
                  </Td>
                  <Td>
                    <Badge tone={statusTone(item.status)}>{item.status}</Badge>
                  </Td>
                  <Td>
                    {fmtBytes(item.traffic_used_bytes)} / {fmtLimit(item.traffic_limit_bytes)}
                  </Td>
                  <Td>{fmtExpiry(item.expires_at)}</Td>
                  <Td>
                    {item.active_keys} local
                    {item.remote_subs > 0 && (
                      <span className="block text-xs text-neutral-500">
                        +{item.remote_subs} source{item.remote_subs > 1 ? "s" : ""}
                      </span>
                    )}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap justify-end gap-1">
                      <Button size="sm" onClick={() => setPreview(item)}>
                        Preview
                      </Button>
                      <Button size="sm" onClick={() => setManageClient(item.user_id)}>
                        Manage
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty>No clients yet, so nothing subscribes here.</Empty>
        )}
      </Card>

      <Card title="Sources from other bProto servers">
        <div className="space-y-3">
          <Notice>
            Point bUI at another panel's <code>/sub/&lt;id&gt;</code> and it pulls that config list
            here. Attach a source to a client and its subscription serves those configs too. The
            fetched URIs contain the other deployment's keys, so this table is a secret.
          </Notice>
          <ErrorBanner error={addSource.error} onDismiss={() => addSource.setError(null)} />
          <form
            className="grid gap-3 sm:grid-cols-[1fr_2fr_auto] sm:items-end"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              void addSource.run(() => api.createRemoteSub(newName, newUrl));
            }}
          >
            <Field label="Name">
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="lab-b"
              />
            </Field>
            <Field label="Subscription URL">
              <Input
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                placeholder="https://other-panel.example.com/sub/abc123"
                required
              />
            </Field>
            <Button variant="primary" type="submit" disabled={addSource.busy}>
              {addSource.busy ? "Fetching…" : "Add source"}
            </Button>
          </form>

          <ErrorBanner
            error={sourceAction.error}
            onDismiss={() => sourceAction.setError(null)}
          />

          {sources.data && sources.data.length > 0 ? (
            <Table>
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Last fetch</Th>
                  <Th>Configs</Th>
                  <Th>Enabled</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {sources.data.map((source) => (
                  <tr key={source.id}>
                    <Td>
                      <span className="font-medium text-neutral-900">{source.name}</span>
                      <span className="block break-all font-mono text-xs text-neutral-500">
                        {source.url}
                      </span>
                    </Td>
                    <Td>
                      {source.last_status === "ok" ? (
                        <Badge tone="ok">ok</Badge>
                      ) : source.last_status === "error" ? (
                        <Badge tone="bad">error</Badge>
                      ) : (
                        <Badge>never</Badge>
                      )}
                      <span className="block text-xs text-neutral-500">
                        {fmtAgo(source.last_fetch_at)}
                      </span>
                      {source.last_error && (
                        <span className="block max-w-xs text-xs text-red-700">
                          {source.last_error}
                        </span>
                      )}
                    </Td>
                    <Td>{source.entry_count}</Td>
                    <Td>
                      <Button
                        size="sm"
                        onClick={() =>
                          sourceAction.run(() =>
                            api.updateRemoteSub(source.id, { enabled: !source.enabled }),
                          )
                        }
                      >
                        {source.enabled ? "Disable" : "Enable"}
                      </Button>
                    </Td>
                    <Td>
                      <div className="flex flex-wrap justify-end gap-1">
                        <Button
                          size="sm"
                          onClick={() =>
                            sourceAction.run(() => api.refreshRemoteSub(source.id))
                          }
                        >
                          Refresh
                        </Button>
                        <Button size="sm" onClick={() => setEntriesFor(source)}>
                          Configs
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() =>
                            confirm({
                              title: "Delete source?",
                              body: `“${source.name}” and its ${source.entry_count} stored configs are removed; clients that had it attached lose those configs.`,
                              onConfirm: () => sourceAction.run(() => api.deleteRemoteSub(source.id)),
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
              No sources yet. Paste a subscription URL from another bProto panel above.
            </Empty>
          )}
        </div>
      </Card>
    </div>
  );
}

function SubPreview({ item, onClose }: { item: SubItem; onClose: () => void }) {
  const load = useLoader(
    async () => {
      const res = await fetch(`/sub/${item.sub_id}?format=json`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as PreviewData;
    },
    [item.sub_id],
  );

  return (
    <Modal title={`Subscription · ${item.username}`} onClose={onClose} wide>
      <ErrorBanner error={load.error} />
      {load.data ? (
        <>
          <p className="text-sm text-neutral-600">
            {load.data.count} config{load.data.count === 1 ? "" : "s"} — profile title{" "}
            <span className="font-medium">{load.data.title}</span>
          </p>
          {load.data.count === 0 ? (
            <Empty>Nothing to import yet: no active devices and no attached sources.</Empty>
          ) : (
            <ul className="divide-y divide-neutral-100 rounded border border-neutral-200">
              {load.data.clients.map((entry, index) => (
                <li key={`${index}-${entry.uri.slice(-16)}`} className="space-y-1 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm text-neutral-800">
                      {entry.label ?? "device"}
                      {entry.server && (
                        <span className="ml-2 font-mono text-xs text-neutral-500">
                          {entry.server}
                        </span>
                      )}
                    </p>
                    <CopyButton value={entry.uri} label="Copy URI" />
                  </div>
                  {entry.sni && <p className="text-xs text-neutral-500">donor SNI: {entry.sni}</p>}
                </li>
              ))}
            </ul>
          )}
          <Notice>
            Importers read the base64 form at <code>{item.sub_url}</code>; the panel also answers{" "}
            <code>?format=list</code> and <code>?format=json</code>.
          </Notice>
        </>
      ) : (
        <p className="text-sm text-neutral-500">Loading…</p>
      )}
    </Modal>
  );
}

function SourceEntries({ source, onClose }: { source: RemoteSub; onClose: () => void }) {
  const entries = useLoader(() => api.remoteEntries(source.id), [source.id]);

  return (
    <Modal title={`Configs · ${source.name}`} onClose={onClose} wide>
      <ErrorBanner error={entries.error} />
      {entries.data && entries.data.length > 0 ? (
        <ul className="divide-y divide-neutral-100 rounded border border-neutral-200">
          {entries.data.map((entry: RemoteEntry) => (
            <li key={entry.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
              <div className="min-w-0">
                <p className="text-sm text-neutral-800">
                  {entry.label ?? "config"}
                  {entry.server && (
                    <span className="ml-2 font-mono text-xs text-neutral-500">{entry.server}</span>
                  )}
                </p>
                <p className="text-xs text-neutral-500">
                  uid {entry.uid ?? "?"}
                  {entry.sni ? ` · sni ${entry.sni}` : ""}
                  {entry.fingerprint ? ` · ${entry.fingerprint}` : ""}
                </p>
              </div>
              <CopyButton value={entry.uri} label="Copy URI" />
            </li>
          ))}
        </ul>
      ) : (
        <Empty>{entries.loading ? "Loading…" : "This source has no stored configs."}</Empty>
      )}
    </Modal>
  );
}
