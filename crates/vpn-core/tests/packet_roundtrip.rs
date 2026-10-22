//! End-to-end framing + AEAD: two peers, both directions, plus negative cases.
//!
//! This exercises [`vpn_core::Session`] directly (no sockets): the crypto path
//! that both the client [`vpn_core::Tunnel`] and the server
//! [`vpn_core::ServerNode`] delegate to.

use vpn_core::crypto::derive_session_keys;
use vpn_core::packet::{HEADER_LEN, Header, MAX_DATAGRAM, TUNNEL_MTU};
use vpn_core::session::{Opened, Session};

fn pair() -> (Session, Session) {
    let shared = [0x5Au8; 32];
    let cr = [0x01u8; 32];
    let sr = [0x02u8; 32];
    let client = Session::new(
        derive_session_keys(&shared, &cr, &sr, true),
        0xCAFE,
        TUNNEL_MTU,
    );
    let server = Session::new(
        derive_session_keys(&shared, &cr, &sr, false),
        0xCAFE,
        TUNNEL_MTU,
    );
    (client, server)
}

#[tokio::test]
async fn datagrams_roundtrip_both_directions() {
    let (client, server) = pair();
    for i in 0..64u8 {
        let payload = vec![i; 40];
        let (pn, dg) = client.seal_ip(&payload).unwrap();
        assert!(dg.len() <= MAX_DATAGRAM);
        assert_eq!(pn, u64::from(i));
        assert_eq!(Header::decode(&dg).unwrap().packet_number, u64::from(i));
        let (rpn, opened) = server.open(&dg).await.unwrap();
        assert_eq!(rpn, u64::from(i));
        assert_eq!(opened, Opened::Ip(payload));
    }
}

#[tokio::test]
async fn traffic_flows_back_too() {
    let (client, server) = pair();
    let (_, up) = client.seal_ip(&[0x45; 30]).unwrap();
    assert!(matches!(server.open(&up).await.unwrap().1, Opened::Ip(_)));

    let (_, down) = server.seal_ip(&[0x46; 30]).unwrap();
    assert_eq!(
        client.open(&down).await.unwrap().1,
        Opened::Ip(vec![0x46; 30])
    );
}

#[tokio::test]
async fn header_is_12_bytes_and_first_byte_versioned() {
    let (client, _) = pair();
    let (_, dg) = client.seal_ip(&[0x45; 20]).unwrap();
    assert!(dg.len() > HEADER_LEN);
    assert_eq!(dg[0] >> 4, vpn_core::PROTOCOL_VERSION);
}

#[tokio::test]
async fn payload_at_mtu_ok_above_mtu_rejected() {
    let (client, _) = pair();
    assert!(client.seal_ip(&vec![0u8; TUNNEL_MTU]).is_ok());
    assert!(client.seal_ip(&vec![0u8; TUNNEL_MTU + 1]).is_err());
}

#[tokio::test]
async fn forged_ciphertext_is_rejected() {
    let (client, server) = pair();
    let (_, mut dg) = client.seal_ip(&[0x45; 20]).unwrap();
    let last = dg.len() - 1;
    dg[last] ^= 0x80;
    assert!(server.open(&dg).await.is_err());
}

#[tokio::test]
async fn replaying_a_datagram_is_rejected() {
    let (client, server) = pair();
    let (_, dg) = client.seal_ip(&[0x45; 20]).unwrap();
    server.open(&dg).await.unwrap();
    assert!(server.open(&dg).await.is_err());
    assert_eq!(server.dropped(), 1);
}

#[tokio::test]
async fn mtu_is_reported() {
    let (client, _) = pair();
    assert_eq!(client.mtu(), TUNNEL_MTU);
}
