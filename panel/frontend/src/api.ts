// Typed client for the bUI panel API.
//
// The bearer token lives in sessionStorage: enough to survive a reload, gone
// when the tab closes, and never as long-lived as a cookie would be.

const TOKEN_KEY = "bui_token";

let token: string | null = sessionStorage.getItem(TOKEN_KEY);

/** Called when the API rejects our token, so the shell can return to login. */
let onUnauthorized: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  onUnauthorized = handler;
}

export function setToken(t: string | null) {
  token = t;
  if (t) sessionStorage.setItem(TOKEN_KEY, t);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export function hasToken(): boolean {
  return token !== null;
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  let body: unknown = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { error: text.slice(0, 200) };
  }
  if (!res.ok) {
    const message =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${res.status}`;
    if (res.status === 401) {
      setToken(null);
      onUnauthorized?.();
    }
    throw new Error(message);
  }
  return body as T;
}

const post = <T>(path: string, body?: unknown) =>
  req<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) =>
  req<T>(path, { method: "PATCH", body: JSON.stringify(body) });
const del = <T>(path: string) => req<T>(path, { method: "DELETE" });

// --- types -----------------------------------------------------------------

export interface Me {
  user_id: number;
  username: string;
  panel: string;
}

export interface Inbound {
  id: number;
  remark: string;
  server: string;
  donor_sni: string;
  fingerprint: string;
  protocol: string;
  transport: string;
  listen_port: number | null;
  status: string;
  note: string | null;
  created_at: number;
  clients: number;
  active_clients: number;
  active_keys: number;
  traffic_used_bytes: number;
  online: number;
}

export interface KeyRow {
  id: number;
  label: string;
  status: string;
  created_at: number;
  revoked_at: number | null;
  last_seen_ip: string | null;
}

export interface Client {
  id: number;
  username: string;
  status: string;
  inbound_id: number | null;
  inbound_remark: string | null;
  traffic_limit_bytes: number | null;
  traffic_used_bytes: number;
  expires_at: number | null;
  note: string | null;
  created_at: number;
  sub_id: string;
  sub_url: string;
  keys: number;
  active_keys: number;
  online: number;
  last_seen_at: number | null;
  remote_subs: number;
  key_list?: KeyRow[];
}

export interface KeyConfig {
  key_id: number;
  config_uri: string;
  qr_svg: string;
  key_status?: string;
  client_status?: string;
}

export interface SeriesPoint {
  ts: number;
  rx: number;
  tx: number;
}

export interface Overview {
  panel: string;
  clients: number;
  active_clients: number;
  admins: number;
  inbounds: number;
  active_inbounds: number;
  active_keys: number;
  online: number;
  sessions: number;
  remote_subs: number;
  traffic_used_bytes: number;
  bytes_rx: number;
  bytes_tx: number;
  bytes_rx_24h: number;
  bytes_tx_24h: number;
  series_24h: SeriesPoint[];
}

export interface TopClient {
  id: number;
  username: string;
  status: string;
  inbound_remark: string | null;
  traffic_used_bytes: number;
  traffic_limit_bytes: number | null;
  expires_at: number | null;
  online: boolean;
}

export interface SessionRow {
  id: number;
  key_id: number;
  key_label: string;
  username: string;
  server_id: string | null;
  started_at: number;
  ended_at: number | null;
  bytes_rx: number;
  bytes_tx: number;
  peer_ip: string | null;
  updated_at: number | null;
  online: boolean;
}

export interface SystemInfo {
  panel: string;
  version: string;
  uptime_secs: number | null;
  load: number[];
  cpus: number;
  mem_total: number | null;
  mem_available: number | null;
  db_bytes: number | null;
  clients_online: number;
}

export interface AdminRow {
  id: number;
  username: string;
  status: string;
  created_at: number;
  sessions: number;
  last_login: number | null;
}

export interface AuditRow {
  id: number;
  admin_id: number | null;
  admin: string | null;
  action: string;
  target: string | null;
  at: number;
  ip: string | null;
}

export interface SubItem {
  user_id: number;
  username: string;
  status: string;
  inbound_remark: string | null;
  sub_id: string;
  sub_url: string;
  traffic_limit_bytes: number | null;
  traffic_used_bytes: number;
  expires_at: number | null;
  active_keys: number;
  remote_subs: number;
}

export interface SubSettings {
  sub_base_url: string;
  sub_title: string;
  panel: string;
}

export interface RemoteSub {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  last_fetch_at: number | null;
  last_status: string | null;
  last_error: string | null;
  entry_count: number;
  created_at: number;
}

export interface RemoteEntry {
  id: number;
  uri: string;
  server: string | null;
  sni: string | null;
  uid: number | null;
  label: string | null;
  fingerprint: string | null;
  fetched_at: number;
}

// --- payloads --------------------------------------------------------------

export interface InboundPayload {
  remark: string;
  server: string;
  donor_sni: string;
  fingerprint?: string;
  listen_port?: number | null;
  note?: string;
}

export interface ClientPayload {
  username: string;
  inbound_id: number;
  traffic_limit_bytes?: number;
  expires_at?: number;
  note?: string;
  label?: string;
}

export interface ClientUpdate {
  username?: string;
  inbound_id?: number;
  traffic_limit_bytes?: number;
  expires_at?: number;
  note?: string;
  status?: string;
}

// --- api -------------------------------------------------------------------

export const api = {
  login: (username: string, password: string) =>
    post<{ token: string; expires_at: number }>("/api/auth/login", { username, password }),
  me: () => req<Me>("/api/me"),
  logout: () => post<{ logged_out: boolean }>("/api/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    post<{ changed: boolean }>("/api/auth/password", { current_password, new_password }),

  admins: () => req<{ admins: AdminRow[] }>("/api/admins").then((r) => r.admins),
  createAdmin: (username: string, password: string) =>
    post<{ id: number }>("/api/admins", { username, password }),
  deleteAdmin: (id: number) => del<{ deleted: boolean }>(`/api/admins/${id}`),
  resetAdminPassword: (id: number, password: string) =>
    post<{ reset: boolean }>(`/api/admins/${id}/password`, { password }),

  inbounds: () => req<{ inbounds: Inbound[] }>("/api/inbounds").then((r) => r.inbounds),
  createInbound: (payload: InboundPayload) =>
    post<{ id: number }>("/api/inbounds", payload),
  updateInbound: (id: number, payload: Partial<InboundPayload> & { status?: string }) =>
    patch<{ updated: boolean }>(`/api/inbounds/${id}`, payload),
  deleteInbound: (id: number, withClients: boolean) =>
    del<{ deleted: boolean; clients_deleted: number }>(
      `/api/inbounds/${id}${withClients ? "?with_clients=1" : ""}`,
    ),
  resetInboundTraffic: (id: number) =>
    post<{ clients_reset: number }>(`/api/inbounds/${id}/reset-traffic`),

  clients: (inboundId?: number) =>
    req<{ clients: Client[] }>(
      `/api/users${inboundId === undefined ? "" : `?inbound_id=${inboundId}`}`,
    ).then((r) => r.clients),
  client: (id: number) => req<{ client: Client }>(`/api/users/${id}`).then((r) => r.client),
  createClient: (inboundId: number, payload: Omit<ClientPayload, "inbound_id">) =>
    post<KeyConfig & { user_id: number; sub_id: string; sub_url: string }>(
      `/api/inbounds/${inboundId}/clients`,
      { ...payload, inbound_id: inboundId },
    ),
  updateClient: (id: number, payload: ClientUpdate) =>
    patch<{ updated: boolean }>(`/api/users/${id}`, payload),
  deleteClient: (id: number) => del<{ deleted: boolean }>(`/api/users/${id}`),
  resetClientTraffic: (id: number) =>
    post<{ reset: boolean }>(`/api/users/${id}/reset-traffic`),

  keys: (userId: number) =>
    req<{ keys: KeyRow[] }>(`/api/users/${userId}/keys`).then((r) => r.keys),
  createKey: (userId: number, label: string) =>
    post<KeyConfig>(`/api/users/${userId}/keys`, { label }),
  keyConfig: (keyId: number) => req<KeyConfig>(`/api/keys/${keyId}/config`),
  revokeKey: (keyId: number) => post<{ revoked: boolean }>(`/api/keys/${keyId}/revoke`),
  deleteKey: (keyId: number) => del<{ deleted: boolean }>(`/api/keys/${keyId}`),

  subscriptions: () =>
    req<{ sub_base_url: string; items: SubItem[] }>("/api/subscriptions"),
  subSettings: () => req<SubSettings>("/api/subscriptions/settings"),
  updateSubSettings: (payload: { sub_base_url?: string; sub_title?: string }) =>
    patch<SubSettings>("/api/subscriptions/settings", payload),

  remoteSubs: () => req<{ items: RemoteSub[] }>("/api/remote-subs").then((r) => r.items),
  createRemoteSub: (name: string, url: string) =>
    post<RemoteSub>("/api/remote-subs", { name, url }),
  updateRemoteSub: (id: number, payload: { name?: string; url?: string; enabled?: boolean }) =>
    patch<RemoteSub>(`/api/remote-subs/${id}`, payload),
  deleteRemoteSub: (id: number) => del<{ deleted: boolean }>(`/api/remote-subs/${id}`),
  refreshRemoteSub: (id: number) => post<RemoteSub>(`/api/remote-subs/${id}/refresh`),
  remoteEntries: (id: number) =>
    req<{ entries: RemoteEntry[] }>(`/api/remote-subs/${id}/entries`).then((r) => r.entries),
  clientRemoteSubs: (userId: number) =>
    req<{ items: RemoteSub[] }>(`/api/users/${userId}/remote-subs`).then((r) => r.items),
  attachRemoteSub: (userId: number, remoteSubId: number) =>
    post<unknown>(`/api/users/${userId}/remote-subs`, { remote_sub_id: remoteSubId }),
  detachRemoteSub: (userId: number, remoteSubId: number) =>
    del<unknown>(`/api/users/${userId}/remote-subs/${remoteSubId}`),

  overview: () => req<Overview>("/api/stats/overview"),
  statsInbounds: () => req<{ inbounds: Inbound[] }>("/api/stats/inbounds").then((r) => r.inbounds),
  topClients: (limit = 10) =>
    req<{ clients: TopClient[] }>(`/api/stats/top?limit=${limit}`).then((r) => r.clients),
  sessions: (limit = 50) =>
    req<{ sessions: SessionRow[] }>(`/api/stats/sessions?limit=${limit}`).then((r) => r.sessions),
  system: () => req<SystemInfo>("/api/stats/system"),
  seedDemo: (count = 48) => post<{ inserted: number }>(`/api/stats/demo?count=${count}`),
  clearDemo: () => del<{ deleted: number }>("/api/stats/demo"),
  audit: (limit = 100) =>
    req<{ entries: AuditRow[] }>(`/api/audit?limit=${limit}`).then((r) => r.entries),
};
