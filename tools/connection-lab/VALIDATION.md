# Connection lab validation — 2026-11-17

Branch: `test/connection-lab`, based on bProto v2.0.0 (`8b21399`).

| Check | Result |
| --- | --- |
| Native server/client debug build, locked dependencies | Passed |
| Native loopback positive handshake | Passed, address `10.66.0.2` |
| Valid configuration with incorrect PSK | Handshake failed as expected; server stayed alive |
| Existing real-UDP transport tests | 5 passed: both packet directions, two users, wrong key, quiet session |
| Python installer + lab contracts | 9 passed |
| Docker Compose configuration | Valid |
| Docker server/probe image build | Passed |
| Docker binary startup | `bproto 2.0.0` |
| Separate-container kernel TUN probe | Passed, 3/3 ICMP replies to `10.66.0.1` through client TUN |
| Server namespace NAT initialization | Logged successfully for `eth0` |
| Reconnection through published local Docker UDP port | Passed, address `10.66.0.2` |
| Secrets excluded from Git | Verified for server/client configurations and lab metadata |

## Environment-specific corrections

The first Docker build failed TLS verification of the session proxy certificate.
The corrected build mounts the host's trusted CA bundle as a BuildKit secret and
sets Cargo's CA bundle for that build step. TLS/checksum verification stays on;
no certificate file is committed or copied into image layers.

The first container launch could not read the private, uid-1000 fixture files
with all capabilities dropped. Adding `DAC_READ_SEARCH` permits reading the
readonly test-fixture mount without making the host's private keys world-readable.
The corrected full TUN probe was rerun and passed.

Direct executor access has no TUN device or CAP_NET_ADMIN. The managed Docker
daemon has its own namespace/device access, which made the real kernel TUN
verification possible. Do not infer Docker availability solely from native doctor output.

## Running local instance

A datapath-enabled server is running in Compose project `bproto-connection-android`,
service `server`, with local UDP publication `127.0.0.1:4443`. Private fixtures
are in the ignored `.connection-lab/` directory. The earlier handshake-only
native server was stopped. These are current-instance processes, not a guarantee
that they survive environment suspension or recreation.

Inspect/stop only this project's server:

```bash
docker compose -p bproto-connection-android -f tools/connection-lab/compose.yaml ps
docker compose -p bproto-connection-android -f tools/connection-lab/compose.yaml logs --tail 100 server
docker compose -p bproto-connection-android -f tools/connection-lab/compose.yaml down
```

## External Android connectivity is blocked

The user intends to connect from their own Android phone and does not provide
or rent a VPS. Current platform status exposes an SSH portal only (port 22),
with no public UDP portal and no callable tool to allocate one. Docker's local
port publication is not a public Internet endpoint. No externally reachable
Android key/address has therefore been provided or claimed to work.

Completing that external-phone test requires a platform-supported public UDP
endpoint or an authorized hosting/relay resource. No hosting account, billing
resource or external cloud identity is configured in this task. The tested local
server does not satisfy that external connectivity requirement by itself.

Internet egress through the VPN, physical Android behavior, public-network
reachability, censorship bypass and a public UDP relay were not tested.
