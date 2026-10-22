//! The Linux TUN device.
//!
//! The interface is created with `TUNSETIFF` and addressed with the `ip`
//! command, which is present on every server and desktop image. `ip` is used
//! instead of a pile of `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCSIFMTU` ioctls so
//! this file stays small enough to audit in one sitting.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::Command;

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;

/// Size of the read buffer a caller should provide.
pub const READ_BUF: usize = vpn_core_max_datagram() + 4;

const fn vpn_core_max_datagram() -> usize {
    // Duplicated as a const to avoid a `vpn-core` dependency in this crate.
    1280
}

/// An open TUN interface.
#[derive(Debug)]
pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    /// Open (creating if needed) the named TUN interface. Does not configure it.
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> io::Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {name:?} is too long"),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let fd = file.as_raw_fd();

        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, b) in name.as_bytes().iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        // TUN (layer 3), no packet-information prefix: we want raw IP frames.
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: `req` is a fully initialized `ifreq` (zeroed then filled), and
        // `fd` is a live file descriptor for `/dev/net/tun`.
        let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            name: name.to_string(),
        })
    }

    /// Non-Linux placeholder.
    #[cfg(not(target_os = "linux"))]
    pub fn open(_name: &str) -> io::Result<Self> {
        Err(io::Error::other(
            "TUN devices are only implemented for Linux; other platforms pass an fd",
        ))
    }

    /// Interface name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The underlying file descriptor, for handing to another event loop.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// Read one IP packet. Takes `&self` so the device can be shared between a
    /// reader thread and the async writer.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.file).read(buf)
    }

    /// Write one IP packet.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        (&self.file).write_all(packet)
    }
}

fn ip(args: &[&str]) -> io::Result<()> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Whether this process may create and address network interfaces.
///
/// True for uid 0 **and** for any process holding `CAP_NET_ADMIN` — the shipped
/// systemd unit runs as an unprivileged user with exactly that capability, so a
/// `geteuid() == 0` check alone would refuse to start a perfectly capable server.
#[must_use]
pub fn can_configure_network() -> bool {
    is_root() || has_cap_net_admin()
}

#[cfg(unix)]
#[must_use]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
#[must_use]
fn is_root() -> bool {
    false
}

#[cfg(target_os = "linux")]
#[must_use]
fn has_cap_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .as_deref()
        .and_then(parse_cap_eff)
        .is_some_and(|bits| bits & (1 << CAP_NET_ADMIN) != 0)
}

#[cfg(not(target_os = "linux"))]
#[must_use]
fn has_cap_net_admin() -> bool {
    false
}

/// `CAP_NET_ADMIN` is bit 12 of the capability bitmask.
#[cfg(target_os = "linux")]
const CAP_NET_ADMIN: u64 = 12;

/// Parse the `CapEff:` line of `/proc/self/status` into a bitmask.
#[cfg(target_os = "linux")]
fn parse_cap_eff(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("CapEff:"))?;
    u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok()
}

/// Error to show when [`can_configure_network`] is false.
#[must_use]
pub fn permission_hint() -> String {
    "need root or CAP_NET_ADMIN to create and address a TUN device".to_string()
}

/// Assign an address in `CIDR` form (`10.66.0.2/24`).
pub fn add_addr(dev: &str, cidr: &str) -> io::Result<()> {
    ip(&["addr", "add", cidr, "dev", dev])
}

/// Set the interface MTU.
pub fn set_mtu(dev: &str, mtu: u16) -> io::Result<()> {
    ip(&["link", "set", "dev", dev, "mtu", &mtu.to_string()])
}

/// Bring the interface up.
pub fn link_up(dev: &str) -> io::Result<()> {
    ip(&["link", "set", "dev", dev, "up"])
}

/// Convenience: assign, size and bring up an interface.
pub fn configure(dev: &str, cidr: &str, mtu: u16) -> io::Result<()> {
    add_addr(dev, cidr)?;
    set_mtu(dev, mtu)?;
    link_up(dev)
}

/// Convert a dotted netmask to a prefix length.
#[must_use]
pub fn netmask_to_prefix(netmask: &str) -> u8 {
    match netmask {
        "255.255.255.255" => 32,
        "255.255.255.254" => 31,
        "255.255.255.252" => 30,
        "255.255.255.0" => 24,
        "255.255.0.0" => 16,
        "255.0.0.0" => 8,
        "0.0.0.0" => 0,
        _ => 24,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_mapping() {
        assert_eq!(netmask_to_prefix("255.255.255.0"), 24);
        assert_eq!(netmask_to_prefix("255.255.255.255"), 32);
        assert_eq!(netmask_to_prefix("0.0.0.0"), 0);
        assert_eq!(netmask_to_prefix("garbage"), 24);
    }

    #[test]
    fn read_buf_covers_the_datagram_plus_headroom() {
        const { assert!(READ_BUF >= 1284) };
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opening_a_bad_name_fails_before_ioctl() {
        let long = "x".repeat(64);
        assert!(TunDevice::open(&long).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cap_eff_is_parsed_from_proc_status() {
        let sample = "Name:\tcat\nState:\tR (running)\nCapEff:\t000001ffffffffff\n";
        assert_eq!(super::parse_cap_eff(sample), Some(0x0000_01ff_ffff_ffff));
        // CAP_NET_ADMIN (bit 12) must be inside that mask.
        assert!(super::parse_cap_eff(sample).unwrap() & (1 << 12) != 0);
        assert_eq!(super::parse_cap_eff("Name:\tcat\n"), None);
        assert_eq!(super::parse_cap_eff("CapEff:\tnot-hex\n"), None);
    }
}
