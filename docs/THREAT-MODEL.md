# bProto threat model

Be precise about what bProto does and does not defend against. Most of the bad
decisions in this space come from assuming a property that was never there.

## Assets

* Session confidentiality and integrity of the tunneled traffic.
* The fact that a given client is using bProto at all (traffic-analysis
  resistance against a passive observer).
* Server availability and the secrecy of its long-term material.

## Adversary

* **Passive DPI** on the path: sees packet sizes, timings, and cleartext of any
  handshake; can fingerprint TLS and QUIC.
* **Active prober**: replays ClientHellos, sends random ones, connects and measures
  response length and content, compares with a direct connection to the donor.
* **On-path attacker** who can drop, delay, duplicate and modify datagrams.
* **Compromised panel** is *out of scope* for confidentiality (it holds the PSKs);
  it is in scope for integrity of config distribution and is a separate hardening
  task.

## What bProto protects

| Property | Mechanism |
|---|---|
| Confidentiality/integrity of tunneled data | ChaCha20-Poly1305 with per-direction keys, header as AAD |
| Replay | 40-bit monotonic packet numbers + 4096-bit sliding window; `session_id` MAC over a 5-minute window |
| Unauthorized use | PSK-derived label in `session_id`; nothing else is accepted |
| Passive fingerprinting of the *handshake* | craftls browser fingerprint, unchanged ClientHello length |
| Active probing (Aparecium-style), vector 1 | no HMAC over handshake frames, so `ServerFinished` keeps its real length |
| Active probing (Aparecium-style), vector 2 | donor `NewSessionTicket` messages are forwarded or faithfully synthesized |
| Unknown probes | any ClientHello that fails label verification is relayed to the donor, which then serves the prober the real site |

## What bProto does NOT protect

* **Traffic analysis of the data plane.** Sizes and timings are only partially
  shaped; a strong statistical observer can still separate an interactive SSH
  session from a bulk download. Bucket padding raises the cost, it does not
  eliminate it.
* **An adversary who knows the donor and the deployment.** A prober that already
  knows your server IP can measure the response behaviour of many probes and look
  for statistical anomalies. This is the hard, unsolved part of the whole
  genre.
* **Harvest-now-decrypt-later, for the first session.** The MVP handshake is
  X25519-only. A recorded session whose key later leaks is readable. The planned
  ML-KEM-768 rekey helps future sessions, not the first one. If this matters,
  the hybrid KEX must be in the handshake itself, not after it; that is a
  documented trade-off, not an oversight.
* **A compromised client device.** The PSK is on the device; malware wins.
* **Legal/abuse exposure.** Borrowing a donor's certificate is legitimate from a
  crypto standpoint (we do not forge a signature) but it makes the server look
  like a high-volume client of the donor. Keep a donor pool and honour their ToS.
* **Server identity by certificate.** Authentication is the PSK label, not a
  certificate. Ed25519 in the config signs *configuration and updates only*. Do
  not describe bProto as "certificate-based" server authentication.

## Mobile-specific reality

* Android exposes `TRANSPORT_VPN` in `NetworkCapabilities`. A bank app can see
  that a VPN is up regardless of our marketing. We reduce secondary heuristics
  and offer per-app bypass; we do not promise invisibility.
* iOS requires the `packet-tunnel-provider` entitlement and a user-approved
  system extension. "No admin rights" is false; "minimal, one-time, auditable
  privilege" is true.
* Windows requires a one-time Wintun driver install by an administrator. Same
  framing: a small privileged service, a never-privileged GUI.

## Crypto hygiene

* Only RustCrypto primitives: `chacha20poly1305`, `x25519-dalek`, `hkdf`, `sha2`,
  `hmac`. No hand-rolled cipher, no custom mode.
* Key material is zeroized on drop (`zeroize`), and `SessionKeys` has no `Debug`
  that prints bytes.
* Constant-time comparisons for the label MAC (`subtle`).
* The server refuses to ship the Aparecium-vulnerable `NewSessionTicket` policy in
  release builds (see `crates/vpn-server/src/nst.rs`).

## Open items

* Formal statement and testing of the traffic-analysis resistance claim. Until
  then it is "raises cost", not "unlinkable".
* Induction of the hybrid post-quantum KEX into the handshake rather than the
  rekey, subject to the ClientHello-size constraint.
* Provenance of donor selection and health, to avoid a donor that quietly changes
  its TLS stack and breaks the mask.
