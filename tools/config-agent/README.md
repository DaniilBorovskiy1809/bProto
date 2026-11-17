# Experimental configuration agent

The panel's authenticated `POST /api/config-agent` endpoint forwards apply,
health and rollback operations to one fixed operator-configured HTTPS destination.
Client certificates are required by the agent. The panel validates the agent
certificate/hostname and does not follow redirects.

Panel environment:
- BPROTO_CONFIG_AGENT_URL: https://agent.example.com:9443
- BPROTO_CONFIG_AGENT_IDENTITY: PEM file containing client certificate and key
- BPROTO_CONFIG_AGENT_CA: PEM CA used to validate the agent server

Run: `python3 tools/config-agent/agent.py /etc/bproto/agent.json`.

Operator-owned agent settings example (paths are illustrative):
```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 9443,
  "cert": "/etc/bproto/agent/server.pem",
  "key": "/etc/bproto/agent/server.key",
  "client_ca": "/etc/bproto/agent/panel-ca.pem",
  "target": "/etc/bproto/tls-server.json",
  "validate": ["/usr/local/libexec/bproto-validate-config"],
  "reload": ["/usr/bin/systemctl", "restart", "bproto-tls"],
  "health": ["/usr/local/libexec/bproto-check-tunnel"]
}
```

The operator must provision these executables. The validator reads the candidate
JSON path from BPROTO_CANDIDATE_CONFIG and must reject unsupported configuration,
invalid certificates and unsafe paths. The health executable must test the service,
not merely return success. Command arguments are fixed at agent startup, never
supplied by panel users. No shell is invoked. Each command has a 15-second timeout.

The existing target must be provisioned first. Apply validates a private staged
file, saves the old configuration, atomically replaces the target with mode 600,
restarts the service and checks health. Failure restores the old file, restarts
and checks again. A failed recovery is explicitly reported. Rollback restores the
previous saved JSON via the same pipeline. Requests use {"version":1,"config":{...}}.
Incompatible versions and unknown fields are rejected.

The Settings TLS editor has Apply/Health/Rollback buttons. These affect the single
configured TLS service and interrupt its connections. Export remains available.

## Tests and operational limits

Seven Python tests cover file replacement, permissions, invalid versions,
validation failures, health rollback, explicit rollback, failed recovery and a
real mTLS connection rejecting a client without a certificate. Statement coverage
is 75%. Panel tests verify administrator access and reject arbitrary destinations.
Service commands are mocked in transaction tests: actual systemd deployment and
full panel-to-agent-to-service e2e have not been exercised.

Use a dedicated management network and dedicated client CA. Every certificate
signed by this CA has apply authority. This single-threaded experimental agent
serializes operations but has no cross-process lock or crash-recovery journal;
run exactly one process. It is not a public Internet management API. Protect
settings/private-key/config directories; backups can contain secrets. File mode
600 means the service must run as the file owner/root, or an operator must arrange
appropriate access. No certificate rotation or automatic service installation
is provided. 100% RKN bypass is not guaranteed.
