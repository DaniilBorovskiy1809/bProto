//! Safer IPv4 socket-option helpers.
//!
//! `vpn-core` is `#![forbid(unsafe_code)]`, but shaping the tunnel socket to
//! look like a browser's HTTP/3 socket needs one setsockopt that no safe
//! wrapper crate exposes. The unsafe surface is isolated in this one-function
//! crate instead: this module never fails the tunnel.

#![allow(unsafe_code)]

/// Enable DF on an IPv4 UDP socket (`IP_MTU_DISCOVER = IP_PMTUDISC_DO`).
///
/// Returns `true` when the option stuck. Silent on failure: an unshaped socket
/// is a cosmetic regression against the Firefox traffic profile, not a bearer
/// for the tunnel, so callers never need to handle an error from this.
#[cfg(target_os = "linux")]
#[must_use]
pub fn set_df_v4(sock: &std::net::UdpSocket) -> bool {
    use std::os::fd::AsRawFd;

    const IPPROTO_IP: libc::c_int = 0;
    const IP_MTU_DISCOVER: libc::c_int = 10;
    const IP_PMTUDISC_DO: libc::c_int = 2;

    let one = IP_PMTUDISC_DO as libc::c_int;
    let ok = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    ok == 0
}

/// Non-Linux fallback: no DF knob available through this crate.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn set_df_v4(_sock: &std::net::UdpSocket) -> bool {
    false
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn df_option_applies_to_a_bound_socket() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(set_df_v4(&s));
    }
}
