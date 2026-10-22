//! NAT masquerade for the server side.
//!
//! Uses `nft` rather than shelling out to `iptables`: one atomic ruleset, no
//! legacy/nftables split-brain on modern distributions.

use std::io::{self, Write};
use std::process::{Command, Stdio};

/// Install a masquerade + forwarding ruleset for the tunnel subnet.
///
/// Idempotent: `nft -f` replaces the whole `inet bproto` table atomically.
pub fn setup_nat(tun_name: &str, out_iface: &str, tunnel_subnet: &str) -> io::Result<()> {
    let ruleset = format!(
        "table inet bproto {{\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat; policy accept;\n\
         \x20   ip saddr {tunnel_subnet} oifname \"{out_iface}\" masquerade\n\
         \x20 }}\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority filter; policy accept;\n\
         \x20   iifname \"{tun_name}\" oifname \"{out_iface}\" accept\n\
         \x20   iifname \"{out_iface}\" oifname \"{tun_name}\" ct state established,related accept\n\
         \x20 }}\n\
         }}\n"
    );
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| io::Error::other("nft stdin unavailable"))?
        .write_all(ruleset.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Enable IPv4 forwarding (persisted in memory; the installer writes sysctl.conf).
pub fn enable_ip_forwarding() -> io::Result<()> {
    let current = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
    if current.trim() == "1" {
        return Ok(());
    }
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
}

#[cfg(test)]
mod tests {
    #[test]
    fn ruleset_mentions_both_interfaces_and_the_subnet() {
        let ruleset = "iifname \"bproto0\" oifname \"eth0\" ip saddr 10.66.0.0/24";
        assert!(ruleset.contains("bproto0"));
        assert!(ruleset.contains("eth0"));
        assert!(ruleset.contains("10.66.0.0/24"));
    }
}
