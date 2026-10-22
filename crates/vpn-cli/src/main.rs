//! The `bproto` CLI: a debug client and a no-frills Linux tunnel endpoint.
//!
//! * `check`   – validate the configuration file,
//! * `connect` – handshake and report, without touching the host network,
//! * `up`      – full tunnel: TUN device, address, default route (opt-out),
//! * `genkey`  – print a fresh PSK for the panel / `server.toml`.
//!
//! The desktop product builds on the same `vpn-core` API; this binary exists so
//! the protocol can be driven end to end without the GUI.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use vpn_core::{Tunnel, TunnelConfig};
use vpn_tun::{dev, route};

#[derive(Debug, Parser)]
#[command(name = "bproto", version, about = "bProto client")]
struct Cli {
    /// Path to the tunnel configuration (`client.toml`).
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,

    /// Use a `bproto://import/...` key URI instead of reading `--config`.
    #[arg(long, value_name = "URI")]
    uri: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration file and exit.
    Check,

    /// Establish a tunnel, print what was negotiated, and stay connected.
    Connect {
        /// Keep the tunnel up for this many seconds (0 = until Ctrl-C).
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },

    /// Full tunnel: create a TUN device, route traffic through the server.
    Up {
        /// TUN interface name.
        #[arg(long, default_value = vpn_tun::DEFAULT_IFACE)]
        iface: String,

        /// Do not move the default route (only configure the interface).
        #[arg(long)]
        no_default_route: bool,
    },

    /// Import a key URI (from the panel's QR code) and write a `client.toml`.
    Import {
        /// The `bproto://import/...` URI.
        uri: String,

        /// Write here instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Print a random 32-byte key as hex (for `server.toml` / the panel).
    Genkey,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn load(path: &Path) -> anyhow::Result<TunnelConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let cfg: TunnelConfig =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    cfg.validate()?;
    Ok(cfg)
}

/// The configuration for this run: `--uri` wins over `--config`.
fn resolve(uri: Option<&str>, config: &Path) -> anyhow::Result<TunnelConfig> {
    match uri {
        Some(uri) => vpn_core::config::from_import_uri(uri).map_err(|e| anyhow::anyhow!("{e}")),
        None => load(config),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    match cli.command {
        Command::Genkey => {
            println!("psk = \"{}\"", random_hex(32)?);
            Ok(())
        }
        Command::Import { uri, out } => {
            let (cfg, label) = vpn_core::config::from_import_uri_with_label(&uri)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let text = render_client_toml(&cfg);
            if let Some(label) = label {
                tracing::info!(label, "imported key");
            }
            match out {
                Some(path) => {
                    std::fs::write(&path, text)
                        .with_context(|| format!("write {}", path.display()))?;
                    println!("wrote {}", path.display());
                }
                None => print!("{text}"),
            }
            Ok(())
        }
        Command::Check => {
            let cfg = resolve(cli.uri.as_deref(), &cli.config)?;
            println!(
                "configuration OK: server={} donor={} mtu={} user_id={}",
                cfg.server,
                cfg.donor.sni,
                cfg.effective_mtu(),
                cfg.user_id
            );
            Ok(())
        }
        Command::Connect { seconds } => {
            let cfg = resolve(cli.uri.as_deref(), &cli.config)?;
            let tunnel = Tunnel::connect(cfg).await?;
            report(&tunnel);
            if seconds == 0 {
                println!("connected; Ctrl-C to exit");
                tokio::signal::ctrl_c().await?;
            } else {
                for _ in 0..seconds {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    print_stats(&tunnel);
                }
            }
            tunnel.close().await;
            Ok(())
        }
        Command::Up {
            iface,
            no_default_route,
        } => {
            let cfg = resolve(cli.uri.as_deref(), &cli.config)?;
            up(cfg, iface, no_default_route).await
        }
    }
}

/// Render a `client.toml` body.
///
/// Written by hand rather than through `toml::to_string` because TOML requires
/// every bare key/value to appear before any `[table]`, and `TunnelConfig`'s
/// field order interleaves them. Doing it here also lets the comments stay.
fn render_client_toml(cfg: &TunnelConfig) -> String {
    format!(
        "# Generated by `bproto import`. Secrets in this file are the account.\n\
         server = \"{server}\"\n\
         user_id = {uid}\n\
         psk = \"{psk}\"\n\
         tag_key = \"{tag_key}\"\n\
         mtu = {mtu}\n\
         fingerprint = \"{fp}\"\n\
         stealth = \"off\"\n\
         handshake_timeout = \"{timeout}ms\"\n\
         \n\
         [donor]\n\
         sni = \"{sni}\"\n",
        server = cfg.server,
        uid = cfg.user_id,
        psk = vpn_core::config::to_hex(&cfg.psk),
        tag_key = vpn_core::config::to_hex(&cfg.tag_key),
        mtu = cfg.mtu,
        fp = vpn_core::config::fingerprint_name(cfg.fingerprint),
        timeout = cfg.handshake_timeout.as_millis(),
        sni = cfg.donor.sni,
    )
}

async fn up(cfg: TunnelConfig, iface: String, no_default_route: bool) -> anyhow::Result<()> {
    if !vpn_tun::can_configure_network() {
        anyhow::bail!("`up` needs root or CAP_NET_ADMIN to create a TUN device and change routes");
    }

    let tunnel = Tunnel::connect(cfg).await?;
    report(&tunnel);

    let assigned = tunnel.assigned_ip();
    let device = dev::TunDevice::open(&iface).with_context(|| format!("open TUN {iface}"))?;
    // /24 inside the pool subnet so the server address is directly reachable.
    dev::configure(
        &iface,
        &format!("{assigned}/24"),
        tunnel.mtu().min(u16::MAX as usize) as u16,
    )
    .with_context(|| format!("configure TUN {iface}"))?;
    tracing::info!(%assigned, iface, "TUN up");

    let _guard = if no_default_route {
        None
    } else {
        let g = route::FullTunnelGuard::install(&iface, cfg_server_ip(&tunnel))
            .context("install full-tunnel routes")?;
        if let Some(w) = g.warning() {
            tracing::warn!(warning = w, "route setup");
        }
        Some(g)
    };

    let device = Arc::new(device);

    // Blocking TUN reads on a dedicated thread, forwarded to the async loop.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    {
        let device = Arc::clone(&device);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; dev::READ_BUF];
            loop {
                match device.read_packet(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => {
                        if tun_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TUN read failed");
                        break;
                    }
                }
            }
        });
    }

    let mut stats_tick = tokio::time::interval(Duration::from_secs(30));
    let mut down = false;
    loop {
        tokio::select! {
            inbound = tunnel.recv_ip_packet() => {
                match inbound {
                    Ok(pkt) => {
                        if let Err(e) = device.write_packet(&pkt) {
                            tracing::warn!(error = %e, "TUN write failed");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "tunnel closed");
                        down = true;
                        break;
                    }
                }
            }
            Some(pkt) = tun_rx.recv() => {
                if let Err(e) = tunnel.send_ip_packet(&pkt).await {
                    tracing::debug!(error = %e, "outbound packet dropped");
                }
            }
            _ = stats_tick.tick() => print_stats(&tunnel),
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }
    tunnel.close().await;
    if down {
        anyhow::bail!("session ended");
    }
    Ok(())
}

/// The server's tunnel-side address: the first host of the client's /24.
fn cfg_server_ip(tunnel: &Tunnel) -> std::net::Ipv4Addr {
    let o = tunnel.assigned_ip().octets();
    std::net::Ipv4Addr::new(o[0], o[1], o[2], 1)
}

fn report(tunnel: &Tunnel) {
    println!("tunnel up:");
    println!("  assigned address : {}", tunnel.assigned_ip());
    println!("  MTU              : {}", tunnel.mtu());
    print_stats(tunnel);
}

fn print_stats(tunnel: &Tunnel) {
    let s = tunnel.stats();
    tracing::info!(
        rtt_ms = s.rtt_us as f64 / 1000.0,
        cwnd = s.cwnd_bytes,
        rx = s.rx_bytes,
        tx = s.tx_bytes,
        dropped = s.dropped,
        uptime_s = s.uptime_s,
        "stats"
    );
}

fn random_hex(n: usize) -> anyhow::Result<String> {
    let mut f = std::fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    let mut bytes = vec![0u8; n];
    f.read_exact(&mut bytes).context("read /dev/urandom")?;
    Ok(vpn_core::config::to_hex(&bytes))
}
