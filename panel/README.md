# bUI — the bProto control panel

`bUI` is the web control panel for a bProto deployment. It follows 3x-ui's
vocabulary: you define **inbounds** (the endpoints clients connect to), put
**clients** inside them, hand each device a `bproto://` config or a
**subscription URL**, and watch traffic on a dashboard.

```
panel/
  backend/     axum + SQLite API server (binary: `panel`)
  frontend/    React 19 + Vite + Tailwind single-page app (`bUI`)
  Caddyfile    HTTPS terminator, static file server, reverse proxy
  docker-compose.yml
```

Two processes: the backend listens on `127.0.0.1:8080` and is never exposed
directly; Caddy terminates TLS and serves both the API and the static bundle.

## Concepts

| Term | Meaning |
| --- | --- |
| **Inbound** | One bProto endpoint: `server` (`ip:port` clients dial), `donor_sni` (the TLS identity the handshake borrows), the ClientHello `fingerprint`, and an informational `listen_port`. |
| **Client** | A `users` row with `inbound_id` set. It owns **keys** — one per device a config was imported on. |
| **Key** | A device credential: pre-shared key + routing tag. Revoking it stops that device without touching the rest. |
| **Subscription** | `/sub/<sub_id>` for one client: every active config of its keys, plus the configs of any attached remote sources. |
| **Remote source** | A subscription URL hosted by *another* bProto panel, fetched server-side and re-served (see below). |
| **Session** | One reported connection of a key on a server, with rx/tx byte deltas. |

A client's config is built **from its inbound at request time**, so editing an
inbound (or re-assigning a client to another one) re-issues configs on the next
fetch. `server` must therefore be an IP:port literal — the panel refuses
hostnames, because the config carries an address, not a name.

### Routing tags and `K_tag`

The server routes a packet by its 8-byte tag, computed as

```
tag = HMAC-SHA256(K_tag, "bproto-tag" ‖ user_id_be)[0..8]
```

`K_tag` (`BPROTO_TAG_KEY`) must be **byte-identical** to `tag_key` in the
server's `server.toml`, or every session lands nowhere. The panel stores a
fingerprint of the key in `settings.tag_key_fingerprint`; when it changes, the
panel recomputes `keys.tag` for every key on startup and logs a warning. Use the
same `K_tag` for every server and panel in one deployment.

## Quick start (development)

```sh
cd panel/backend
BPROTO_TAG_KEY=$(openssl rand -hex 32) \
BPROTO_ADMIN_PASSWORD='a-long-panel-password' \
  cargo run                     # migrations run automatically, listens on 127.0.0.1:8080
```

```sh
cd panel/frontend
pnpm install
pnpm dev                        # http://127.0.0.1:5173, proxies /api and /sub to :8080
```

The `just` targets are `just panel` (backend, release), `just frontend` (build
the SPA) and `just migrate`.

### Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `BPROTO_DB` | `sqlite://panel.db?mode=rwc` | SQLite URL. WAL and foreign keys are enabled on every pooled connection. |
| `BPROTO_LISTEN` | `127.0.0.1:8080` | Bind address. Keep it on loopback; Caddy fronts it. |
| `BPROTO_TAG_KEY` | *required* | 32 bytes hex. Must match the server's `tag_key`. |
| `BPROTO_ADMIN_PASSWORD` | random, printed once | Used only when the first admin is created. |
| `BPROTO_INTERNAL_TOKEN` | unset | Bearer token for `POST /internal/v1/sessions/report`. While unset the endpoint answers `503`. |
| `BPROTO_ALLOW_PRIVATE_SUBS` | unset | `1`/`true` disables the remote-subscription SSRF guard. **Lab only.** |
| `RUST_LOG` | `info` | `tracing` filter. |

## API

All routes below `/api/*` require `Authorization: Bearer <token>`; the public
exceptions are `GET /api/health`, `POST /api/auth/login` and `GET /sub/{sub_id}`.

```
POST   /api/auth/login             {username, password} -> {token, expires_at}
POST   /api/auth/logout
POST   /api/auth/password          {current_password, new_password}
GET    /api/me
GET    /api/admins                 POST /api/admins        DELETE /api/admins/{id}
POST   /api/admins/{id}/password

GET    /api/inbounds               POST /api/inbounds
PATCH  /api/inbounds/{id}          DELETE /api/inbounds/{id}[?with_clients=1]
POST   /api/inbounds/{id}/reset-traffic
GET    /api/inbounds/{id}/clients  POST /api/inbounds/{id}/clients

GET    /api/users[?inbound_id=]    POST /api/users
GET    /api/users/{id}             PATCH /api/users/{id}   DELETE /api/users/{id}
POST   /api/users/{id}/reset-traffic
GET    /api/users/{id}/keys        POST /api/users/{id}/keys
GET    /api/keys/{id}/config       POST /api/keys/{id}/revoke   DELETE /api/keys/{id}

GET    /api/subscriptions          GET|PATCH /api/subscriptions/settings
GET    /api/remote-subs            POST /api/remote-subs
PATCH  /api/remote-subs/{id}       DELETE /api/remote-subs/{id}
POST   /api/remote-subs/{id}/refresh        GET /api/remote-subs/{id}/entries
GET    /api/users/{id}/remote-subs          POST /api/users/{id}/remote-subs
DELETE /api/users/{id}/remote-subs/{remote_sub_id}

GET    /api/stats/overview         GET /api/stats/inbounds
GET    /api/stats/top?limit=       GET /api/stats/sessions?limit=
GET    /api/stats/system           POST|DELETE /api/stats/demo?count=
GET    /api/audit?limit=

GET    /api/health                 POST /internal/v1/sessions/report
GET    /sub/{sub_id}[?format=]
```

Request bodies are capped at 256 KiB. Login is rate-limited (burst 5, then one
attempt every 20 s per IP); `/sub/*` allows a burst of 90 and then 1/s per IP,
because importers poll.

### Authentication

Admin passwords are hashed with **argon2id** and must be at least 12 characters.
A successful login creates a row in `admin_sessions` and returns an opaque
token; the token's TTL is 30 minutes and **slides forward on every request**, so
an idle tab signs itself out while an active one stays in. Sessions live in the
database, which makes revocation a `DELETE` — changing a password invalidates
that account's other sessions.

Clients never log in: a client row stores an unusable password hash and its
credential is its subscription URL.

## Subscriptions

`GET /sub/{sub_id}` returns the client's configs. It is `403` when the client is
not `active`, is expired, or has reached its traffic limit, and `404` for an
unknown id. Responses are `cache-control: no-store`.

| `?format=` | Body |
| --- | --- |
| *(default)* | base64 of the newline-joined `bproto://` URIs |
| `list`, `text` | the newline-joined URIs, plain |
| `json` | `{title, sub_id, username, userinfo{upload,download,total,expire}, count, clients[{uri,server,sni,label}]}` |

Headers on every response:

```
subscription-userinfo: upload=<rx>; download=<tx>; total=<limit|0>; expire=<ts|0>
profile-title: base64:<b64(profile title)>
profile-update-interval: 12
```

The profile title comes from the `sub_title` setting, defaulting to
`bUI · <username>`. The URL prefix comes from `sub_base_url`; when that is
empty the panel uses the request's `Host` header, so set it explicitly once the
panel sits behind a proxy. Both are edited on the Subscriptions page.

A config URI is
`bproto://import/<base64url({v,server,sni,uid,psk,tag_key,fp,label})>` — it
contains the pre-shared key, so treat it, the QR code and
`remote_sub_entries.uri` as secrets.

## Remote subscription sources

Adding a source (`POST /api/remote-subs`) makes the panel fetch that URL
server-side, parse it, and store one `remote_sub_entries` row per config. The
panel accepts the three formats listed above (base64, plain list, JSON).
`POST /api/remote-subs/{id}/refresh` re-fetches; entries of a disabled source are
skipped when serving a subscription.

Attaching a source to a client (`POST /api/users/{id}/remote-subs`) merges its
entries into that client's `/sub/<sub_id>` response. This is how one client can
carry configs from several bProto deployments.

Fetch guard, unless `BPROTO_ALLOW_PRIVATE_SUBS=1`:

* scheme must be `http`/`https`;
* the host is resolved and **every** resolved address is checked — private,
  loopback, link-local and otherwise reserved ranges are refused, which blocks
  `169.254.169.254`-style metadata endpoints and internal panels;
* 15 s timeout, at most 3 redirects, response body capped at 1 MiB.

Because the fetch happens on the server, an allow-listed URL can still reach
whatever the panel host can. Keep the source list admin-only (it is) and prefer
the flag only on a lab machine.

## Session reporting (server → panel)

Servers push traffic to the panel. The endpoint is disabled until
`BPROTO_INTERNAL_TOKEN` is set, then requires a bearer token compared in
constant time. It is **not** routed by the shipped Caddyfile, so it is only
reachable on the panel's loopback/compose network.

```sh
curl -sS -X POST "http://127.0.0.1:8080/internal/v1/sessions/report" \
  -H "Authorization: Bearer $BPROTO_INTERNAL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server_id":"de1","sessions":[
        {"tag":"0011223344556677","started_at":0,"ended_at":null,
         "bytes_rx":4096,"bytes_tx":2048,"peer_ip":"198.51.100.7"}]}'
```

* `bytes_rx`/`bytes_tx` are **deltas** since the previous report, not totals.
* A key is identified by `tag` (8 bytes hex — what the server holds) or by
  `key_id`. Unknown tags are collected in the response instead of failing the
  batch.
* `ended_at: null` means the session is live: the panel keeps at most one open
  row per `(key, server_id)` and adds the deltas to it. A non-null `ended_at`
  closes that row.
* Rows that stop being refreshed for **300 s** are closed automatically, so a
  server that dies mid-session does not leave an open row forever.
* Every accepted report also adds `bytes_rx + bytes_tx` to the owning client's
  `traffic_used_bytes` and refreshes `keys.last_seen_ip`.

Response: `{"accepted": <n>, "unknown": ["<tag>", …]}`.

## Dashboard

`GET /api/stats/overview` returns the counters and a 24-hour hourly rx/tx
series; `/api/stats/inbounds` rolls clients, keys, online and traffic up per
inbound; `/api/stats/top` and `/api/stats/sessions` show the busiest clients and
the most recent sessions; `/api/stats/system` reports uptime, load, memory and
the SQLite file size.

`POST /api/stats/demo?count=N` inserts plausible sessions (with
`server_id = "demo"`) so the charts can be explored before any server reports;
`DELETE /api/stats/demo` removes exactly those rows and subtracts their bytes
again. Both are admin-only and meant for demos, not production.

## Security posture

* argon2id password hashes; opaque, revocable, sliding sessions; login and
  subscription rate limits; constant-time comparison for the internal token.
* `/internal/*` is off by default and absent from the Caddy config.
* Inbound endpoints and SNI/fingerprint are validated (IP:port literal,
  no empty values) before a client can be issued a config.
* The panel stores PSKs and remote credentials, so `panel.db` is a secret: keep
  it readable only by the `panel` user.
* Serving the panel over plaintext HTTP or on a public interface is unsupported.
  Put it behind HTTPS (the shipped Caddyfile does this) and prefer restricting
  the login to a known IP range at the edge.

## Deployment

```sh
cd panel
BPROTO_DOMAIN=panel.example.com \
BPROTO_TAG_KEY=$(openssl rand -hex 32) \
BPROTO_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
BPROTO_INTERNAL_TOKEN=$(openssl rand -hex 32) \
  docker compose up -d --build
```

`docker-compose.yml` builds the backend, builds the SPA into a volume Caddy
serves from, and runs Caddy for TLS plus proxying. The backend has no published
ports. Adding `BPROTO_INTERNAL_TOKEN` to the `panel` service environment is what
lets servers report traffic.

## Tests

```sh
cd panel/backend && cargo test        # 37 tests, incl. router-level API tests
cd panel/frontend && pnpm build       # tsc + vite build
```

`src/api_tests.rs` drives the real router against a temporary SQLite database
(inbounds → clients → keys → subscription → reporting → password rotation).

`panel/smoke.sh` covers the same ground end to end with `curl` and `jq` against a
running instance. It needs `bash`, `curl`, `jq` and `python3`, and it expects a
**fresh, throwaway** database (it asserts exact counts and rotates the admin
password). See the header comment in the script for the exact environment.
