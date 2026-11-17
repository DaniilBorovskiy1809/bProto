//! NAT masquerade for the server side.
//!
//! Prefers `nft`: one atomic ruleset, no legacy/nftables split-brain on modern
//! distributions. When `nft` is not installed (minimal servers, Android), it
//! falls back to the `iptables` commands with the same rules.

use std::io::{self, Write};
use std::process::{Command, Stdio};

/// Install a masquerade + forwarding ruleset for the tunnel subnet.
///
/// Idempotent: `nft -f` replaces the whole `inet bproto` table atomically, and
/// the iptables fallback probes each rule with `-C` before appending.
pub fn setup_nat(tun_name: &str, out_iface: &str, tunnel_subnet: &str) -> io::Result<()> {
    match nft_ruleset(tun_name, out_iface, tunnel_subnet) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            iptables_ruleset(tun_name, out_iface, tunnel_subnet)
        }
        Err(e) => Err(e),
    }
}

fn nft_ruleset(tun_name: &str, out_iface: &str, tunnel_subnet: &str) -> io::Result<()> {
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

/// `iptables -C rule` returns success when the rule already exists.
fn iptables_has_rule(args: &[&str]) -> io::Result<bool> {
    let out = Command::new("iptables")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    Ok(out.status.success())
}

fn iptables_add_rule(args: &[&str]) -> io::Result<()> {
    if iptables_has_rule(args)? {
        return Ok(());
    }
    let mut add = args.to_vec();
    // Turn the `-C` existence probe into the `-A` append command, wherever
    // it sits in the argument list (e.g. after `-t nat`).
    match add.iter().position(|a| *a == "-C") {
        Some(i) => add[i] = "-A",
        None => return Err(io::Error::other("iptables rule has no -C probe")),
    }
    let out = Command::new("iptables")
        .args(&add)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "iptables failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn iptables_ruleset(tun_name: &str, out_iface: &str, tunnel_subnet: &str) -> io::Result<()> {
    // Mirror the nft ruleset: masquerade on the way out, accept both
    // directions on the forward path.
    iptables_add_rule(&[
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-s",
        tunnel_subnet,
        "-o",
        out_iface,
        "-j",
        "MASQUERADE",
    ])?;
    iptables_add_rule(&[
        "-C", "FORWARD", "-i", tun_name, "-o", out_iface, "-j", "ACCEPT",
    ])?;
    iptables_add_rule(&[
        "-C",
        "FORWARD",
        "-i",
        out_iface,
        "-o",
        tun_name,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
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
