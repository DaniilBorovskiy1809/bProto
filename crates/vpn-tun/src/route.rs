//! Client-side route takeover, with rollback.
//!
//! Bringing up a tunnel interface is not enough: the default route has to move
//! to it, *without* cutting the UDP flow that carries the tunnel itself. So the
//! order is:
//!
//! 1. pin a host route to the server through the current gateway,
//! 2. add a low-metric default route through the tunnel,
//! 3. on drop, remove both and let the original default route take over again.
//!
//! Everything is best-effort in `Drop`: a failed rollback is logged, never
//! panicked on, because panicking in a destructor can abort the process.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;

/// The machine's current IPv4 default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// Next hop, when the route is via a gateway.
    pub gateway: Option<Ipv4Addr>,
    /// Egress interface.
    pub dev: String,
}

/// Read the current IPv4 default route, if any.
pub fn default_route() -> io::Result<Option<DefaultRoute>> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip route show default: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(line) = text.lines().next() else {
        return Ok(None);
    };
    Ok(parse_default_route(line))
}

fn parse_default_route(line: &str) -> Option<DefaultRoute> {
    let mut it = line.split_whitespace();
    let mut gateway = None;
    let mut dev = None;
    while let Some(tok) = it.next() {
        match tok {
            "via" => {
                gateway = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok());
            }
            "dev" => dev = it.next().map(str::to_string),
            _ => {}
        }
    }
    dev.map(|dev| DefaultRoute { gateway, dev })
}

/// Metric used for the tunnel default route; below the usual 600 of DHCP/WiFi so
/// it wins while keeping the original route in the table.
pub const TUNNEL_METRIC: u32 = 50;

/// Installs the full-tunnel route set and undoes it on drop.
#[derive(Debug)]
pub struct FullTunnelGuard {
    undo: Vec<Vec<String>>,
    period_route_warning: Option<String>,
}

impl FullTunnelGuard {
    /// Move the default route through `tun`, protecting the path to `server_ip`.
    pub fn install(tun: &str, server_ip: Ipv4Addr) -> io::Result<Self> {
        let mut undo: Vec<Vec<String>> = Vec::new();
        let mut period_route_warning = None;

        match default_route()? {
            Some(orig) => {
                // 1. keep the tunnel's own transport reachable
                let host = format!("{server_ip}/32");
                let route_args: Vec<String> = match orig.gateway {
                    Some(gw) => vec![
                        "route".into(),
                        "add".into(),
                        host.clone(),
                        "via".into(),
                        gw.to_string(),
                        "dev".into(),
                        orig.dev.clone(),
                    ],
                    None => vec![
                        "route".into(),
                        "add".into(),
                        host.clone(),
                        "dev".into(),
                        orig.dev.clone(),
                    ],
                };
                run("route add", &route_args)?;
                undo.push(swap_verb(&route_args, "add", "del"));
            }
            None => {
                period_route_warning = Some(
                    "no IPv4 default route found; only the tunnel route was added".to_string(),
                );
            }
        }

        // 2. the tunnel default route
        let tunnel_args: Vec<String> = vec![
            "route".into(),
            "add".into(),
            "default".into(),
            "dev".into(),
            tun.into(),
            "metric".into(),
            TUNNEL_METRIC.to_string(),
        ];
        if let Err(e) = run("route add default", &tunnel_args) {
            // Roll back the host route we already added before returning.
            for args in undo.iter().rev() {
                let _ = run("rollback", args);
            }
            return Err(e);
        }
        undo.push(swap_verb(&tunnel_args, "add", "del"));

        Ok(Self {
            undo,
            period_route_warning,
        })
    }

    /// A human-readable note about anything that was skipped.
    #[must_use]
    pub fn warning(&self) -> Option<&str> {
        self.period_route_warning.as_deref()
    }
}

impl Drop for FullTunnelGuard {
    fn drop(&mut self) {
        for args in self.undo.iter().rev() {
            if let Err(e) = run("rollback", args) {
                tracing::warn!(args = ?args, error = %e, "route rollback failed");
            }
        }
    }
}

fn swap_verb(args: &[String], from: &str, to: &str) -> Vec<String> {
    args.iter()
        .map(|a| if a == from { to.to_string() } else { a.clone() })
        .collect()
}

fn run(what: &str, args: &[String]) -> io::Result<()> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip {} ({what}): {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_dhcp_default_route() {
        let r = parse_default_route(
            "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.50 metric 600",
        )
        .unwrap();
        assert_eq!(r.gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(r.dev, "wlan0");
    }

    #[test]
    fn parses_a_gatewayless_route() {
        let r = parse_default_route("default dev ppp0 scope link").unwrap();
        assert_eq!(r.gateway, None);
        assert_eq!(r.dev, "ppp0");
    }

    #[test]
    fn a_line_without_a_device_is_rejected() {
        assert_eq!(parse_default_route("default via 10.0.0.1"), None);
    }

    #[test]
    fn verb_swap_only_touches_the_verb() {
        let args = vec![
            "route".to_string(),
            "add".to_string(),
            "default".to_string(),
        ];
        assert_eq!(swap_verb(&args, "add", "del")[1], "del");
        assert_eq!(swap_verb(&args, "add", "del")[0], "route");
    }
}
