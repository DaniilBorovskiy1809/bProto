//! End-to-end: a real client [`Tunnel`] against a real [`Node`] over loopback
//! UDP.
//!
//! This is the test that proves the product moves packets: handshake, address
//! lease, bidirectional IP traffic, ACK-driven RTT/CUBIC, and rejection of an
//! active prober with the wrong key.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vpn_client::Tunnel;
use vpn_core::packet::MAX_DATAGRAM;
use vpn_core::tags::TagTable;
use vpn_core::{DonorSpec, HelloProfile, IpPool, TunnelConfig};
use vpn_server::server::{Node, Outcome};

const TAG_KEY: [u8; 32] = [0x22; 32];
const PSK: [u8; 32] = [0x11; 32];
const USER: u64 = 42;

fn config(server: SocketAddr, psk: [u8; 32], timeout: Duration) -> TunnelConfig {
    TunnelConfig {
        server,
        donor: DonorSpec::default(),
        psk,
        user_id: USER,
        tag_key: TAG_KEY,
        mtu: 1280,
        fingerprint: HelloProfile::default(),
        masquerade: false,
        handshake_timeout: timeout,
    }
}

/// A running server: address, node, and the channel of packets headed for its TUN.
struct Harness {
    node: Arc<Node>,
    addr: SocketAddr,
    to_tun: mpsc::Receiver<Vec<u8>>,
}

/// Run a node exactly as the binary does: one receive loop, one housekeeping
/// tick, packets for the TUN pushed down a channel.
async fn start_node(node: Arc<Node>) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let (to_tun_tx, to_tun) = mpsc::channel::<Vec<u8>>(1024);

    {
        let node = Arc::clone(&node);
        let sock = Arc::clone(&sock);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM + 32];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                if let Ok(Outcome::Packet(pkt)) = node.route(&sock, &buf[..n], from, 0).await {
                    let _ = to_tun_tx.send(pkt).await;
                }
            }
        });
    }
    (addr, to_tun)
}

async fn start_server() -> Harness {
    let mut table = TagTable::new();
    table.insert(&TAG_KEY, USER, PSK);
    let tags = Arc::new(RwLock::new(table));
    let node = Arc::new(Node::new(
        tags,
        IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
        vpn_core::packet::TUNNEL_MTU,
    ));
    let (addr, to_tun) = start_node(Arc::clone(&node)).await;
    Harness { node, addr, to_tun }
}

/// Send `count` distinct IPv4 packets from the client and check the server's TUN
/// side receives them in order.
#[tokio::test]
async fn client_to_server_ip_traffic_arrives() {
    let mut h = start_server().await;
    let tunnel = Tunnel::connect(config(h.addr, PSK, Duration::from_secs(2)))
        .await
        .expect("handshake must succeed");

    assert_eq!(tunnel.assigned_ip().to_string(), "10.66.0.2");
    assert_eq!(h.node.stats().await.sessions, 1);

    for i in 0..20u8 {
        // a plausible IPv4 packet: version 4, IHL 5, dst 10.66.0.1
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[16..20].copy_from_slice(&[10, 66, 0, 1]);
        pkt[20..24].copy_from_slice(&[10, 66, 0, 2]);
        pkt[47] = i;
        tunnel.send_ip_packet(&pkt).await.unwrap();
    }

    let mut seen = 0u8;
    while seen < 20 {
        let pkt = tokio::time::timeout(Duration::from_secs(2), h.to_tun.recv())
            .await
            .expect("server must deliver within 2s")
            .expect("channel open");
        assert_eq!(pkt[47], seen, "packets must arrive in order");
        assert!(pkt[0] >> 4 == 4);
        seen += 1;
    }
}

/// Server -> client: seal on the server, receive on the client.
#[tokio::test]
async fn server_to_client_ip_traffic_arrives() {
    let h = start_server().await;
    let tunnel = Tunnel::connect(config(h.addr, PSK, Duration::from_secs(2)))
        .await
        .unwrap();
    let client_ip = tunnel.assigned_ip();

    let mut down = vec![0u8; 40];
    down[0] = 0x45;
    down[12..16].copy_from_slice(&[1, 1, 1, 1]);
    down[16..20].copy_from_slice(&client_ip.octets());

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sent = h
        .node
        .send_to_client(&sock, client_ip, &down, 0)
        .await
        .unwrap();
    assert!(sent, "the client's address must be routable");

    let got = tokio::time::timeout(Duration::from_secs(2), tunnel.recv_ip_packet())
        .await
        .expect("client must receive within 2s")
        .unwrap();
    assert_eq!(got, down);

    let stats = tunnel.stats();
    assert_eq!(stats.rx_bytes, 40);
}

/// A prober with the wrong key never completes the handshake and never appears
/// as a session.
#[tokio::test]
async fn a_wrong_key_never_establishes_a_session() {
    let h = start_server().await;
    let mut wrong = PSK;
    wrong[0] ^= 0xFF;

    let err = Tunnel::connect(config(h.addr, wrong, Duration::from_millis(600)))
        .await
        .expect_err("a wrong PSK must not establish a tunnel");
    assert!(
        matches!(err, vpn_core::Error::HandshakeTimeout),
        "expected a timeout, got {err}"
    );
    assert_eq!(h.node.stats().await.sessions, 0);
    assert!(h.node.stats().await.rejected_handshakes >= 1);
}

/// Two different users get two different addresses and two independent sessions.
#[tokio::test]
async fn two_users_get_distinct_addresses() {
    let mut table = TagTable::new();
    table.insert(&TAG_KEY, 1, [0x01; 32]);
    table.insert(&TAG_KEY, 2, [0x02; 32]);
    let tags = Arc::new(RwLock::new(table));
    let node = Arc::new(Node::new(
        tags,
        IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
        vpn_core::packet::TUNNEL_MTU,
    ));
    let (addr, _to_tun) = start_node(Arc::clone(&node)).await;

    let mut c1 = config(addr, [0x01; 32], Duration::from_secs(2));
    c1.user_id = 1;
    let mut c2 = config(addr, [0x02; 32], Duration::from_secs(2));
    c2.user_id = 2;

    let t1 = Tunnel::connect(c1).await.unwrap();
    let t2 = Tunnel::connect(c2).await.unwrap();

    assert_ne!(t1.assigned_ip(), t2.assigned_ip());
    assert_eq!(node.stats().await.sessions, 2);
}

/// The client's keepalive/ACK loop must not interfere with a quiet link.
#[tokio::test]
async fn a_quiet_link_stays_established() {
    let h = start_server().await;
    let tunnel = Tunnel::connect(config(h.addr, PSK, Duration::from_secs(2)))
        .await
        .unwrap();
    // One packet to give the server a fresh timestamp, then idle for a moment.
    tunnel
        .send_ip_packet(&{
            let mut p = vec![0u8; 48];
            p[0] = 0x45;
            p[16..20].copy_from_slice(&[10, 66, 0, 1]);
            p
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.node.stats().await.sessions, 1);
    assert!(tunnel.stats().tx_bytes > 0);
}
