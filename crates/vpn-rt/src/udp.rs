//! UDP socket helpers.
//!
//! The whole transport is one datagram socket. This module exists so the rest of
//! the runtime never has to name `tokio`'s error types.

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use vpn_core::{Error, Result};

/// Bind a socket appropriate for talking to `peer`: any local port, matching
/// address family.
pub async fn bind_for(peer: SocketAddr) -> Result<UdpSocket> {
    let local: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid literal")
    } else {
        "[::]:0".parse().expect("valid literal")
    };
    UdpSocket::bind(local)
        .await
        .map_err(|e| Error::Transport(format!("bind {local}: {e}")))
}

/// Bind a socket to a specific address (the server's listening port).
pub async fn bind(addr: SocketAddr) -> Result<UdpSocket> {
    UdpSocket::bind(addr)
        .await
        .map_err(|e| Error::Transport(format!("bind {addr}: {e}")))
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

/// Receive one datagram, returning the number of bytes read and the source.
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
