// C-ABI surface of libbproto.a, as seen from Swift.
//
// This header is hand-written to match crates/vpn-ffi/src/lib.rs. Swift imports
// it through the bridging header of the packet-tunnel target; the linking step
// is the part that needs a real Xcode project (see README.md).

#ifndef BPROTO_H
#define BPROTO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque tunnel handle.
typedef struct BprotoTunnel BprotoTunnel;

/// Stats snapshot. Layout must match `BprotoStats` in Rust.
typedef struct {
    uint64_t rtt_us;
    uint64_t cwnd_bytes;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t dropped;
    uint64_t uptime_s;
} BprotoStats;

/// Library version. Borrowed, never freed.
const char *bproto_version(void);

/// Last error on this thread. Borrowed, never freed.
const char *bproto_last_error(void);

/// Connect from a `bproto://import/...` key or a JSON config. NULL on failure.
/// Blocks until the handshake completes or times out.
BprotoTunnel *bproto_connect(const char *config);

/// Copy the leased address into `out` (4 bytes). 0 on success.
int bproto_assigned_ip(BprotoTunnel *tunnel, uint8_t *out);

/// UDP descriptor of the server link (Android `protect`). -1 on failure.
int bproto_socket_fd(BprotoTunnel *tunnel);

/// Send one IP packet. Returns the byte count, or -1 on failure.
int bproto_send(BprotoTunnel *tunnel, const uint8_t *buf, uintptr_t len);

/// Receive one IP packet. Returns the length, or -1 on failure. Blocks.
int bproto_recv(BprotoTunnel *tunnel, uint8_t *buf, uintptr_t cap);

/// Receive one IP packet, waiting at most `timeout_ms`.
/// Returns the length, -2 on timeout, -1 on failure.
int bproto_recv_timeout(BprotoTunnel *tunnel, uint8_t *buf, uintptr_t cap,
                        uint64_t timeout_ms);

/// Fill `out` with a stats snapshot. 0 on success.
int bproto_stats(BprotoTunnel *tunnel, BprotoStats *out);

/// Stage-2 stealth level. 0 for the MVP.

/// Compute the 32-byte ClientHello `session_id` label (stage 2). 0 on success.
int bproto_compute_session_id(const char *psk_hex,
                              const char *tag_key_hex,
                              uint64_t user_id,
                              const char *client_random_hex,
                              const char *x25519_pub_hex,
                              uint64_t unix_secs,
                              uint8_t *out);

/// Release a handle. Safe with NULL.
void bproto_free(BprotoTunnel *tunnel);

#ifdef __cplusplus
}
#endif

#endif /* BPROTO_H */
