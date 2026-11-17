//! Native HTTP/3 carrier. Bind, protect the UDP socket, then connect.
use crate::error::{Error, Result};
use bytes::{Buf, Bytes};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::Mutex, task::JoinHandle};
const MAX_PACKET: usize = 2048;
fn failure(e: impl std::fmt::Display) -> Error {
    Error::Transport(format!("HTTP3: {e}"))
}

/// Bound external socket. No packets are emitted until connect.
#[derive(Debug)]
pub struct QuicTransport {
    socket: std::net::UdpSocket,
}
impl QuicTransport {
    pub fn bind(local: SocketAddr) -> Result<Self> {
        let socket = std::net::UdpSocket::bind(local).map_err(failure)?;
        socket.set_nonblocking(true).map_err(failure)?;
        Ok(Self { socket })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(failure)
    }
    /// Borrowed descriptor. Never close it.
    #[cfg(unix)]
    pub fn socket_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket.as_raw_fd()
    }
    /// Optional DER CA for private deployments; verification remains enabled.
    pub async fn connect(
        self,
        server: SocketAddr,
        hostname: &str,
        token: &str,
        ca_der: Option<Vec<u8>>,
    ) -> Result<QuicBridge> {
        if hostname.is_empty()
            || hostname.len() > 253
            || !hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            || token.len() != 64
            || !token.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Config("invalid HTTP3 hostname or token".into()));
        }
        tokio::time::timeout(
            Duration::from_secs(10),
            self.connect_inner(server, hostname, token, ca_der),
        )
        .await
        .map_err(|_| failure("connection timeout"))?
    }
    async fn connect_inner(
        self,
        server: SocketAddr,
        hostname: &str,
        token: &str,
        ca_der: Option<Vec<u8>>,
    ) -> Result<QuicBridge> {
        let mut roots =
            quinn::rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(der) = ca_der {
            roots.add(der.into()).map_err(failure)?;
        }
        let mut tls = quinn::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(failure)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.version(1);
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(failure)?));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.receive_window(65536u32.into());
        transport.stream_receive_window(16384u32.into());
        transport.send_window(65536);
        client.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::new(
            Default::default(),
            None,
            self.socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(failure)?;
        endpoint.set_default_client_config(client);
        let connection = endpoint
            .connect(server, hostname)
            .map_err(failure)?
            .await
            .map_err(failure)?;
        let (mut driver, mut requests) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(failure)?;
        let driver = AbortTask(tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await
        }));
        let result = async {
            let request = http::Request::builder()
                .method("POST")
                .uri(format!("https://{hostname}/bproto"))
                .header("authorization", format!("Bearer {token}"))
                .body(())
                .map_err(failure)?;
            let mut stream = requests.send_request(request).await.map_err(failure)?;
            let response = stream.recv_response().await.map_err(failure)?;
            if response.status() != http::StatusCode::OK
                || response
                    .headers()
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    != Some("application/octet-stream")
            {
                return Err(failure("authentication rejected"));
            }
            let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.map_err(failure)?);
            let port = local.local_addr().map_err(failure)?.port();
            let (mut send, mut recv) = stream.split();
            let peer = Arc::new(Mutex::new(None::<SocketAddr>));
            let socket = Arc::clone(&local);
            let output_peer = Arc::clone(&peer);
            let request_guard = requests.clone();
            let task = tokio::spawn(async move {
                let _request_guard = request_guard;
                let outgoing = async {
                    let mut packet = [0u8; MAX_PACKET + 1];
                    loop {
                        let (size, source) =
                            socket.recv_from(&mut packet).await.map_err(failure)?;
                        let mut peer = output_peer.lock().await;
                        if peer.is_none() {
                            *peer = Some(source);
                        }
                        if *peer != Some(source) {
                            continue;
                        }
                        drop(peer);
                        if size == 0 || size > MAX_PACKET {
                            return Err(failure("invalid datagram length"));
                        }
                        let mut framed = Vec::with_capacity(size + 2);
                        framed.extend_from_slice(&(size as u16).to_be_bytes());
                        framed.extend_from_slice(&packet[..size]);
                        send.send_data(Bytes::from(framed)).await.map_err(failure)?;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                };
                let incoming = async {
                    let mut decoder = Decoder::default();
                    while let Some(mut data) = recv.recv_data().await.map_err(failure)? {
                        while data.has_remaining() {
                            for packet in decoder.feed(data.chunk())? {
                                if let Some(peer) = *peer.lock().await {
                                    local.send_to(&packet, peer).await.map_err(failure)?;
                                }
                            }
                            let count = data.chunk().len();
                            data.advance(count);
                        }
                    }
                    Err::<(), Error>(failure("stream closed"))
                };
                tokio::select! { result = outgoing => result, result = incoming => result }
            });
            Ok((port, task))
        }
        .await;
        match result {
            Ok((port, task)) => Ok(QuicBridge {
                port,
                task,
                driver,
                endpoint,
                connection,
            }),
            Err(error) => {
                driver.0.abort();
                connection.close(0u32.into(), b"");
                endpoint.close(0u32.into(), b"");
                Err(error)
            }
        }
    }
}
/// Running local UDP bridge. Drop cancels both directions and QUIC.
#[derive(Debug)]
pub struct QuicBridge {
    port: u16,
    task: JoinHandle<Result<()>>,
    driver: AbortTask<h3::error::ConnectionError>,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}
impl QuicBridge {
    pub fn local_port(&self) -> u16 {
        self.port
    }
    pub fn is_finished(&self) -> bool {
        self.task.is_finished() || self.driver.0.is_finished()
    }
}
impl Drop for QuicBridge {
    fn drop(&mut self) {
        self.task.abort();
        self.driver.0.abort();
        self.connection.close(0u32.into(), b"");
        self.endpoint.close(0u32.into(), b"");
    }
}
#[derive(Default)]
struct Decoder {
    buffer: Vec<u8>,
}
impl Decoder {
    fn feed(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for &byte in data {
            self.buffer.push(byte);
            if self.buffer.len() >= 2 {
                let size = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
                if size == 0 || size > MAX_PACKET {
                    return Err(failure("invalid frame length"));
                }
                if self.buffer.len() == size + 2 {
                    result.push(self.buffer[2..].to_vec());
                    self.buffer.clear();
                }
            }
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_frames() {
        let mut decoder = Decoder::default();
        assert!(decoder.feed(&[0]).unwrap().is_empty());
        assert!(decoder.feed(&[3, 1]).unwrap().is_empty());
        assert_eq!(
            decoder.feed(&[2, 3, 0, 1, 9]).unwrap(),
            vec![vec![1, 2, 3], vec![9]]
        );
    }
    #[test]
    fn invalid_lengths() {
        for bytes in [[0, 0], [255, 255]] {
            assert!(Decoder::default().feed(&bytes).is_err());
        }
    }
    #[test]
    fn bind_allocates_a_real_socket() {
        let socket = QuicTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_ne!(socket.local_addr().unwrap().port(), 0);
    }
}

#[derive(Debug)]
struct AbortTask<T>(JoinHandle<T>);
impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
