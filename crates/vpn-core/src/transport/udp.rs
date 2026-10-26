//! Minimal UDP transport for the native (non-QUIC) datapath.
//!
//! The wire format is still bProto's own short-header datagram; this module only
//! wraps the tokio socket so the rest of the crate never touches `Result` types
//! from two crates. When the `quic` feature lands, `transport::quic` takes over
//! and this becomes the fallback used by tests.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};

/// Bind a socket appropriate for talking to `peer`: any local port, matching
/// address family.
///
/// IP options are pinned to the shape a real HTTP/3 client's socket has (the
/// Firefox capture shows `tos 0x0, ttl 64, flags [DF]` on every datagram):
/// DF is enabled via `IP_MTU_DISCOVER` on Linux, TTL is set to 64. Both steps
/// are best-effort — failing option sets never break the tunnel itself.
pub async fn bind_for(peer: SocketAddr) -> Result<UdpSocket> {
    let local: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid literal")
    } else {
        "[::]:0".parse().expect("valid literal")
    };
    let bound = std::net::UdpSocket::bind(local)
        .map_err(|e| Error::Transport(format!("bind {local}: {e}")))?;
    if peer.is_ipv4() {
        // Browser-socket IP shape. FF keeps whole datagrams; TTL 64 is the
        // Linux default, pinned so exotic boxes that ship another default
        // still produce the familiar header.
        let _ = bound.set_ttl(64);
        let _ = ipopts::set_df_v4(&bound);
    }
    bound
        .set_nonblocking(true)
        .map_err(|e| Error::Transport(format!("nonblocking: {e}")))?;
    UdpSocket::from_std(bound).map_err(|e| Error::Transport(format!("tokio socket: {e}")))
}

/// Send one datagram.
pub async fn send(sock: &UdpSocket, datagram: &[u8], peer: SocketAddr) -> Result<()> {
    let n = sock
        .send_to(datagram, peer)
        .await
        .map_err(|e| Error::Transport(format!("send to {peer}: {e}")))?;
    if n != datagram.len() {
        return Err(Error::Transport(format!(
            "short send: {n}/{} bytes",
            datagram.len()
        )));
    }
    Ok(())
}

/// Receive one datagram, returning bytes read and the source address.
pub async fn recv(sock: &UdpSocket, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
    sock.recv_from(buf)
        .await
        .map_err(|e| Error::Transport(format!("recv: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_roundtrip() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        send(&a, b"ping", b_addr).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = recv(&b, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a_addr);
    }

    #[tokio::test]
    async fn bind_for_matches_family() {
        let s4 = bind_for("127.0.0.1:443".parse().unwrap()).await.unwrap();
        assert!(s4.local_addr().unwrap().is_ipv4());
    }
}
