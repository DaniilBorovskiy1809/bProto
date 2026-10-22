# craftls fork: the `session_id` patch

`craftls` (https://github.com/3andne/craftls) is a fork of `rustls` that adds
ClientHello fingerprinting (`ClientConfig::with_fingerprint(CHROME_112)` and
friends). It is a drop-in replacement, so it is wired in with a cargo patch:

```toml
# workspace Cargo.toml
[patch.crates-io]
rustls = { git = "https://github.com/3andne/craftls", rev = "<PIN>" }
```

We keep it as a git submodule at `crates/craftls` and pin a rev. The patch below
is the *only* change we make on top of upstream craftls. It is about six lines in
two files and it does not alter the length of the ClientHello — that is the whole
point, since a length change is exactly what Aparecium detects in ShadowTLS v3.

## Rationale

The TLS 1.3 ClientHello has a `session_id` field. A browser in middlebox
compatibility mode sends 32 random bytes there. We send 32 bytes that are a
verifiable authentication label instead:

```
session_id[0..8]  = HMAC-SHA256(K_tag, user_id)[0..8]              // routing tag
session_id[8..32] = HMAC-SHA256(psk, tag ‖ client_random ‖
                                x25519_pub ‖ T)[0..24]             // label MAC
T = floor(unix_time / 300)
```

The server reads the tag, looks the user up, verifies the MAC, and either
intercepts the handshake or relays it transparently to the donor. Nothing else in
the handshake changes.

## Patch part 1 — `src/client/client_conn.rs`

Add an optional override and a builder method to `ClientConfig`:

```rust
// in `pub struct ClientConfig`
pub(crate) session_id_override: Option<[u8; 32]>,

// in `impl ClientConfig`
/// Set the exact 32-byte session id sent in the ClientHello.
pub fn with_session_id(mut self, sid: [u8; 32]) -> Self {
    self.session_id_override = Some(sid);
    self
}
```

(Remember to add `session_id_override: None` to every `ClientConfig { .. }`
constructor in the fork; the compiler will list them.)

## Patch part 2 — `src/client/hs.rs`, `emit_client_hello_for_retry`

The function that builds `ClientHelloPayload`. Replace the generated session id
with our override when present:

```diff
             cipher_suites: cipher_suites.clone(),
             compression_methods: CompressionMethods::from_vec(vec![CompressionMethod::Null]),
-            session_id: SessionId::new(session_id_or_empty),
+            session_id: SessionId::new(
+                self.config
+                    .session_id_override
+                    .map(|s| s.to_vec())
+                    .unwrap_or_else(|| session_id_or_empty.to_vec()),
+            ),
```

Exact anchoring depends on the pinned rustls version inside the fork; the shape
above is stable across the 0.23 line. Because the replacement is always exactly
32 bytes, `ClientHelloPayload::get_encoding_length()` is unchanged.

## Maintenance obligation

Staying on a fork means staying behind rustls security patches. The rule is:

* review the upstream diff against our pin at least quarterly;
* keep the patch to these two hunks so rebasing is mechanical;
* the CI job `cargo xtask verify-craftls-pin` fails if the pinned rev is more than
  120 days behind upstream.

## ClientHello fingerprint check

`cargo test -p vpn-core --test censor_gets_real_site -- --ignored` compares the
emitted ClientHello against a captured Chrome ClientHello for the configured
fingerprint. Any drift (extension order, GREASE, padding) fails the build.
