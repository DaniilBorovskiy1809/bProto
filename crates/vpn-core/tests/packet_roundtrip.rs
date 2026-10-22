//! End-to-end framing + AEAD: two peers, both directions, plus negative cases.
//!
//! This drives [`vpn_core::Endpoint`] directly — no sockets, no async, no clock
//! beyond a `u64` the test supplies. `Endpoint` is the same machine the client
//! and the server run, so what is proven here is proven for both.

use vpn_core::crypto::derive_session_keys;
use vpn_core::endpoint::{Endpoint, EndpointParams, Opened, Role};
use vpn_core::packet::{HEADER_LEN, Header, MAX_DATAGRAM, TUNNEL_MTU};

fn pair() -> (Endpoint, Endpoint) {
    let shared = [0x5Au8; 32];
    let params = EndpointParams {
        mtu: TUNNEL_MTU,
        ..EndpointParams::default()
    };
    let client = Endpoint::established(
        Role::Client,
        derive_session_keys(&shared, &[1; 32], &[2; 32], true),
        0xCAFE,
        params,
        0,
    );
    let server = Endpoint::established(
        Role::Server,
        derive_session_keys(&shared, &[1; 32], &[2; 32], false),
        0xCAFE,
        params,
        0,
    );
    (client, server)
}

#[test]
fn datagrams_roundtrip_both_directions() {
    let (mut client, mut server) = pair();
    for i in 0..64u64 {
        let payload = vec![i as u8; 40];
        let dg = client.seal_ip(&payload, i).unwrap();
        assert!(dg.len() <= MAX_DATAGRAM);
        assert_eq!(Header::decode(&dg).unwrap().packet_number, i);
        assert_eq!(server.open(&dg, i).unwrap(), Opened::Ip(payload));
    }
}

#[test]
fn traffic_flows_back_too() {
    let (mut client, mut server) = pair();
    let payload = vec![0x45u8; 80];
    let dg = server.seal_ip(&payload, 0).unwrap();
    assert_eq!(client.open(&dg, 0).unwrap(), Opened::Ip(payload));
}

#[test]
fn header_is_12_bytes_and_first_byte_versioned() {
    let (mut client, _server) = pair();
    let dg = client.seal_ip(&[0x45; 20], 0).unwrap();
    assert!(dg.len() > HEADER_LEN);
    assert_eq!(dg[0] >> 4, vpn_core::PROTOCOL_VERSION);
    assert_eq!(Header::decode(&dg).unwrap().session_tag, 0xCAFE);
}

#[test]
fn replaying_a_datagram_is_rejected() {
    let (mut client, mut server) = pair();
    let dg = client.seal_ip(&[0x45; 20], 0).unwrap();
    server.open(&dg, 0).unwrap();
    assert!(server.open(&dg, 1).is_err());
}

#[test]
fn forged_ciphertext_is_rejected() {
    let (mut client, mut server) = pair();
    let mut dg = client.seal_ip(&[0x45; 20], 0).unwrap();
    let last = dg.len() - 1;
    dg[last] ^= 0x80;
    assert!(server.open(&dg, 0).is_err());
}

#[test]
fn payload_at_mtu_ok_above_mtu_rejected() {
    let (mut client, _server) = pair();
    assert!(client.seal_ip(&vec![0u8; TUNNEL_MTU], 0).is_ok());
    assert!(client.seal_ip(&vec![0u8; TUNNEL_MTU + 1], 0).is_err());
}

#[test]
fn mtu_is_reported() {
    let (client, _server) = pair();
    assert_eq!(client.mtu(), TUNNEL_MTU);
}
