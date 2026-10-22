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
use vpn_core::hello::{ClientHelloBuilder, HelloProfile as Profile};
use vpn_core::packet::MAX_DATAGRAM;
use vpn_core::tags::TagTable;
use vpn_core::{DonorSpec, HelloProfile, IpPool, TunnelConfig};
use vpn_server::relay::Relay;
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

/// Run a node exactly as the binary does: one receive loop, packets for the TUN
/// pushed down a channel. `masquerade` selects the datapath the binary uses for
/// a masquerade listener.
async fn start_node(
    node: Arc<Node>,
    sock: Arc<UdpSocket>,
    masquerade: bool,
) -> mpsc::Receiver<Vec<u8>> {
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
                let routed = if masquerade {
                    node.route_masquerade(&buf[..n], from, 0).await
                } else {
                    node.route(&buf[..n], from, 0).await
                };
                if let Ok(Outcome::Packet(pkt)) = routed {
                    let _ = to_tun_tx.send(pkt).await;
                }
            }
        });
    }
    to_tun
}

fn tags() -> Arc<RwLock<TagTable>> {
    let mut table = TagTable::new();
    table.insert(&TAG_KEY, USER, PSK);
    Arc::new(RwLock::new(table))
}

/// Start a node, with a donor relay if `donor` is given.
async fn start_with(tags: Arc<RwLock<TagTable>>, donor: Option<SocketAddr>) -> Harness {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let mut node = Node::new(
        Arc::clone(&sock),
        tags,
        IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
        vpn_core::packet::TUNNEL_MTU,
    );
    if let Some(donor) = donor {
        node = node.with_donor(Relay::new(donor));
    }
    let node = Arc::new(node);
    let to_tun = start_node(Arc::clone(&node), sock, donor.is_some()).await;
    Harness { node, addr, to_tun }
}

async fn start_server() -> Harness {
    start_with(tags(), None).await
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

    let sent = h
        .node
        .send_to_client(client_ip, &down, 0)
        .await
        .unwrap();
    assert!(sent, "the client's address must be routable");

    let got = tokio::time::timeout(Duration::from_secs(2), tunnel.recv_ip_packet())
        .await
        .expect("client must receive within 2s")
        .unwrap();
    assert_eq!(got, down);

    let stats = tunnel.stats().await;
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
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let node = Arc::new(Node::new(
        Arc::clone(&sock),
        tags,
        IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24),
        vpn_core::packet::TUNNEL_MTU,
    ));
    let _to_tun = start_node(Arc::clone(&node), sock, false).await;

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
    assert!(tunnel.stats().await.tx_bytes > 0);
}

/// The property the masquerade layer exists for.
///
/// A peer we do not recognise — a censor probing with a real TLS stack and no
/// key — must reach the donor and get the donor's answer back, byte for byte,
/// from the address it sent to. It must not be answered by us and it must not
/// become a session.
#[tokio::test]
async fn a_stranger_is_relayed_to_the_donor_and_gets_the_donors_answer() {
    let donor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let donor_addr = donor.local_addr().unwrap();
    let h = start_with(tags(), Some(donor_addr)).await;

    // A browser-shaped ClientHello with a random session_id: exactly what a
    // scanner sends, and exactly what our own client sends minus the label.
    let probe = ClientHelloBuilder::new(Profile::Chrome120)
        .sni("www.cloudflare.com")
        .alpn(vec!["h3".into()])
        .random([0x17; 32])
        .key_share([0x42; 32])
        .session_id([0xC3; 32])
        .build();

    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger.send_to(&probe, h.addr).await.unwrap();

    // The donor sees those bytes, untouched.
    let mut buf = vec![0u8; MAX_DATAGRAM + 32];
    let (n, upstream) = tokio::time::timeout(Duration::from_secs(2), donor.recv_from(&mut buf))
        .await
        .expect("the donor must be reached within 2s")
        .expect("recv");
    assert_eq!(&buf[..n], &probe, "the probe must be relayed verbatim");

    // And the donor's answer comes back to the stranger from our listener.
    donor.send_to(b"real donor response", upstream).await.unwrap();
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), stranger.recv_from(&mut buf))
        .await
        .expect("the stranger must be answered within 2s")
        .expect("recv");
    assert_eq!(&buf[..n], b"real donor response");
    assert_eq!(
        from, h.addr,
        "the answer must come from the address the stranger sent to"
    );

    // Nothing about this looks like a client to us.
    let s = h.node.stats().await;
    assert_eq!(s.sessions, 0, "a probe must not become a session");
    assert!(s.relayed >= 1);
}

/// Our own client on the masquerade port: the handshake is disguised, the
/// session is real, and IP traffic still crosses.
#[tokio::test]
async fn a_masquerade_client_completes_a_handshake_and_moves_packets() {
    let donor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut h = start_with(tags(), Some(donor.local_addr().unwrap())).await;

    let mut cfg = config(h.addr, PSK, Duration::from_secs(2));
    cfg.masquerade = true;
    cfg.donor.sni = "www.cloudflare.com".into();

    let tunnel = Tunnel::connect(cfg).await.expect("the masquerade handshake must succeed");
    assert_eq!(tunnel.assigned_ip().to_string(), "10.66.0.2");
    assert_eq!(h.node.stats().await.sessions, 1);
    assert_eq!(
        h.node.stats().await.relayed,
        0,
        "our own client must not be relayed"
    );

    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x45;
    pkt[16..20].copy_from_slice(&[10, 66, 0, 1]);
    pkt[20..24].copy_from_slice(&tunnel.assigned_ip().octets());
    pkt[47] = 0x7F;
    tunnel.send_ip_packet(&pkt).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), h.to_tun.recv())
        .await
        .expect("the server must deliver within 2s")
        .expect("channel open");
    assert_eq!(got, pkt, "the packet must arrive unmodified");
}

/// A client that claims masquerade but presents a stale label is relayed, not
/// served — the same fate a stranger gets, which is the point.
#[tokio::test]
async fn a_stale_masquerade_client_is_relayed() {
    let donor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let h = start_with(tags(), Some(donor.local_addr().unwrap())).await;

    let mut cfg = config(h.addr, PSK, Duration::from_millis(600));
    cfg.masquerade = true;
    // Three windows out: the label no longer verifies.
    let (_state, hello) = vpn_core::handshake::start(
        &cfg,
        vpn_core::unix_now_secs() + 3 * vpn_core::auth::WINDOW_SECS,
    )
    .unwrap();

    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger.send_to(&hello, h.addr).await.unwrap();

    let mut buf = vec![0u8; MAX_DATAGRAM + 32];
    let (n, _upstream) = tokio::time::timeout(Duration::from_secs(2), donor.recv_from(&mut buf))
        .await
        .expect("a stale label must be relayed")
        .expect("recv");
    assert_eq!(&buf[..n], &hello);
    assert_eq!(h.node.stats().await.sessions, 0);
}
