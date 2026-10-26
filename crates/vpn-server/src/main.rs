//! bProto server binary.
//!
//! Lifecycle (`docs/PLAN.md` section 4):
//!
//! 1. load + validate `server.toml` (`--check-config` stops here),
//! 2. guard the post-handshake mask policy,
//! 3. build the in-memory tag table,
//! 4. bind the UDP listener and open the TUN device, install NAT,
//! 5. loop: TUN → encrypt → UDP; UDP → verify/decrypt → TUN.
//!
//! The protocol half is [`vpn_core::ServerNode`]; this file is only I/O and
//! lifecycle.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use vpn_core::server::{ServerNode, ServerParams};
use vpn_core::tags::TagTable;
use vpn_core::{IpPool, packet};
use vpn_server::config::ServerConfig;
use vpn_server::{admin, nst};
use vpn_tun::{dev, nat};

#[derive(Debug, Parser)]
#[command(name = "vpn-server", version, about = "bProto server")]
struct Cli {
    /// Path to the TOML configuration.
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check_config: bool,

    /// Bring up the TUN device and NAT, then serve. Without this the server
    /// still answers handshakes and logs traffic, but packets have nowhere to go.
    #[arg(long)]
    datapath: bool,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let cfg = ServerConfig::load(&cli.config)?;
    let (tun_addr, prefix) = cfg.tun.ipv4()?;
    let (network, pool_prefix) = cfg.tun.network()?;
    tracing::info!(
        listen = %cfg.listen_addr,
        donor = %cfg.donor.sni,
        users = cfg.users.len(),
        tunnel = %format!("{network}/{pool_prefix}"),
        "configuration loaded"
    );

    if cli.check_config {
        println!("configuration OK");
        return Ok(());
    }

    let policy = nst::PostHandshakePolicy::default();
    nst::assert_safe_policy(policy, !cfg!(debug_assertions)).map_err(|e| anyhow::anyhow!(e))?;
    if cfg!(debug_assertions) {
        assert!(
            nst::assert_safe_policy(nst::PostHandshakePolicy::Suppress, true).is_err(),
            "the Suppress policy must be rejected in release builds"
        );
        assert!(
            nst::must_forward(nst::PostHandshakePolicy::Relay, false),
            "the Relay policy must forward donor post-handshake messages"
        );
    }

    let tags: Arc<RwLock<TagTable>> = Arc::new(RwLock::new(cfg.tag_table()?));
    if tags.read().map(|t| t.is_empty()).unwrap_or(true) {
        tracing::warn!("tag table is empty: every handshake will be rejected");
    }

    {
        let admin_cfg = cfg.admin.clone();
        let tags = Arc::clone(&tags);
        tokio::spawn(async move {
            if let Err(e) = admin::serve(admin_cfg, tags).await {
                tracing::warn!(error = %e, "admin API not started");
            }
        });
    }

    let sock = Arc::new(
        tokio::net::UdpSocket::bind(cfg.listen_addr)
            .await
            .with_context(|| format!("bind UDP {}", cfg.listen_addr))?,
    );
    tracing::info!(addr = %sock.local_addr()?, "listener up");

    // The donor splice target: an explicit override wins, else resolve the
    // SNI once here (no per-flow lookups). No donor, no masquerade.
    let donor_addr = match cfg.donor.addr_override {
        Some(a) => Some(a),
        None => resolve_donor_v4(&cfg.donor.sni),
    };
    let splicer = match donor_addr {
        Some(addr) => {
            let s = vpn_server::splicer::Splicer::start(Arc::clone(&sock), addr, Arc::clone(&tags));
            tracing::info!(donor = %addr, "donor splice ready");
            Some(s)
        }
        None => {
            tracing::warn!(
                sni = %cfg.donor.sni,
                "donor address unresolvable; masquerade is OFF (native bProto only)"
            );
            None
        }
    };

    let params = ServerParams {
        mtu: cfg.tun.mtu.min(packet::MAX_DATAGRAM as u16) as usize,
        ..ServerParams::default()
    };
    let pool = IpPool::new(network, pool_prefix);
    let node = Arc::new(ServerNode::new(
        Arc::clone(&sock),
        Arc::clone(&tags),
        pool,
        params,
    ));

    let device = if cli.datapath {
        match bring_up_tun(&cfg, tun_addr, prefix) {
            Ok(d) => Some(Arc::new(d)),
            Err(e) => {
                tracing::error!(error = %e, "datapath requested but TUN setup failed");
                return Err(e);
            }
        }
    } else {
        tracing::warn!(
            "running without --datapath: handshakes are answered, IP packets are dropped"
        );
        None
    };

    serve(node, splicer, device).await
}

fn bring_up_tun(
    cfg: &ServerConfig,
    tun_addr: std::net::Ipv4Addr,
    prefix: u8,
) -> anyhow::Result<dev::TunDevice> {
    if !dev::can_configure_network() {
        anyhow::bail!("{}", dev::permission_hint());
    }
    let name = &cfg.tun.name;
    let tun = dev::TunDevice::open(name).with_context(|| format!("open TUN {name}"))?;
    dev::configure(name, &format!("{tun_addr}/{prefix}"), cfg.tun.mtu)
        .with_context(|| format!("configure TUN {name}"))?;
    tracing::info!(name, addr = %tun_addr, mtu = cfg.tun.mtu, "TUN up");

    if let Some(iface) = cfg.tun.nat_interface.as_deref() {
        // IPv4 forwarding is a prerequisite, normally set by
        // /etc/sysctl.d/99-bproto.conf. Try anyway, but a read-only /proc/sys
        // (ProtectKernelTunables) is a warning, not a fatal error.
        if let Err(e) = nat::enable_ip_forwarding() {
            tracing::warn!(
                error = %e,
                "could not enable net.ipv4.ip_forward; if it is 0 the tunnel will \
                 connect but carry no traffic. Set it persistently, see docs/INSTALL.md"
            );
        }
        let (network, pool_prefix) = cfg.tun.network()?;
        nat::setup_nat(name, iface, &format!("{network}/{pool_prefix}"))
            .with_context(|| format!("install NAT on {iface}"))?;
        tracing::info!(iface, "NAT ruleset installed");
    } else {
        tracing::warn!("tun.nat_interface is unset; clients will not reach the internet");
    }
    Ok(tun)
}

/// Resolve the donor hostname to its first IPv4 address for the splice.
fn resolve_donor_v4(host: &str) -> Option<SocketAddr> {
    // Startup-time resolution: one blocking lookup before the accept loop,
    // not per flow. Overrides (`addr_override`) beat this precisely to dodge
    // poisoning; see config docs.
    (host, 443).to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

async fn serve(
    node: Arc<ServerNode>,
    splicer: Option<vpn_server::splicer::Splicer>,
    device: Option<Arc<dev::TunDevice>>,
) -> anyhow::Result<()> {
    let sock = node.socket();
    let start = Instant::now();
    let now_us = move || start.elapsed().as_micros() as u64;

    // TUN reads are blocking, so they happen on a dedicated thread that hands
    // packets back over a channel.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(4096);
    if let Some(device) = &device {
        let device = Arc::clone(device);
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

    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut datagram = vec![0u8; packet::MAX_DATAGRAM + 32];
    let mut last_report = Instant::now();

    loop {
        tokio::select! {
            received = sock.recv_from(&mut datagram) => {
                let Ok((n, from)) = received else { continue };
                // Masquerade demux: QUIC Initial-shaped traffic is served by
                // the donor splice or (label verified) the bProto half; only
                // the native `0x1x` datagrams reach `node.handle` blindly.
                if let Some(splicer) = &splicer {
                    match splicer.on_datagram(from, &datagram[..n]).await {
                        vpn_server::splicer::Action::Spliced => continue,
                        vpn_server::splicer::Action::Drop => continue,
                        vpn_server::splicer::Action::Tunnel => {
                            // A labeled Initial is the masquerade handshake;
                            // the native HELLO follows in `0x1x` datagrams.
                            tracing::debug!(%from,
                                "masquerade Initial seen; tunnel takes over on native datagrams");
                            continue;
                        }
                        vpn_server::splicer::Action::Native => {}
                    }
                }
                match node.handle(&datagram[..n], from, now_us()).await {
                    Ok(Some(pkt)) => {
                        if let Some(device) = &device
                            && let Err(e) = device.write_packet(&pkt)
                        {
                            tracing::warn!(error = %e, "TUN write failed");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::debug!(error = %e, %from, "datagram rejected"),
                }
            }

            Some(pkt) = tun_rx.recv() => {
                match node.seal_packet(&pkt, now_us()).await {
                    Ok(true) => {}
                    Ok(false) => tracing::trace!(len = pkt.len(), "no route for outbound packet"),
                    Err(e) => tracing::debug!(error = %e, "outbound packet dropped"),
                }
            }

            _ = tick.tick() => {
                if let Err(e) = node.tick(now_us()).await {
                    tracing::warn!(error = %e, "tick failed");
                }
                if last_report.elapsed() >= Duration::from_secs(60) {
                    last_report = Instant::now();
                    let s = node.stats().await;
                    tracing::info!(
                        sessions = s.sessions,
                        handshakes = s.handshakes,
                        rejected = s.rejected_handshakes,
                        unknown = s.unknown_tags,
                        congestion_drops = s.congestion_drops,
                        "stats"
                    );
                }
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                return Ok(());
            }
        }
    }
}
