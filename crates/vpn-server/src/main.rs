//! bProto server binary.
//!
//! Lifecycle:
//!
//! 1. load and validate `server.toml` (`--check-config` stops here),
//! 2. build the tag table from the static users, then keep it refreshed from the
//!    panel if one is configured,
//! 3. bind the UDP listener and (with `--datapath`) open the TUN device and
//!    install NAT,
//! 4. loop: TUN → encrypt → UDP; UDP → verify/decrypt → TUN.
//!
//! There is no protocol logic in this file. It is I/O, lifecycle and reporting;
//! the node itself is [`vpn_server::server::Node`].

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use vpn_core::{IpPool, MAX_DATAGRAM, TagTable, packet, unix_now_secs};
use vpn_rt::{Clock, udp};
use vpn_tun::{dev, nat};

use vpn_server::config::ServerConfig;
use vpn_server::control::{PanelClient, SessionReport, apply_keys};
use vpn_server::server::{Node, Outcome};

#[derive(Debug, Parser)]
#[command(name = "vpn-server", version, about = "bProto server")]
struct Cli {
    /// Path to the TOML configuration.
    #[arg(short, long, default_value = "server.toml")]
    config: std::path::PathBuf,

    /// Validate the configuration and exit.
    #[arg(long)]
    check_config: bool,

    /// Bring up the TUN device and NAT, then serve. Without this the server
    /// still answers handshakes and accounts traffic, but packets have nowhere
    /// to go.
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
    let tag_key = cfg.tag_key_bytes()?;

    tracing::info!(
        listen = %cfg.listen_addr,
        donor = %cfg.donor.sni,
        users = cfg.users.len(),
        tunnel = %format!("{network}/{pool_prefix}"),
        panel = if cfg.panel.url.is_empty() {
            "disabled".to_string()
        } else {
            cfg.panel.url.clone()
        },
        "configuration loaded"
    );

    if cli.check_config {
        println!("configuration OK");
        return Ok(());
    }

    let tags: Arc<RwLock<TagTable>> = Arc::new(RwLock::new(cfg.tag_table()?));
    if cfg.panel.url.is_empty() && tags.read().map(|t| t.is_empty()).unwrap_or(true) {
        tracing::warn!(
            "tag table is empty and no panel is configured: every handshake will be rejected"
        );
    }

    let panel = PanelClient::new(&cfg.panel);
    match &panel {
        Some(p) => {
            tracing::info!(
                url = %cfg.panel.url,
                server_id = %p.server_id(),
                every = format!("{}s", cfg.panel.interval_secs),
                "control plane enabled: pulling keys, reporting traffic"
            );
            spawn_key_puller(p.clone(), Arc::clone(&tags), tag_key, cfg.panel.interval_secs);
        }
        None => tracing::warn!("no panel configured: keys are static, traffic is reported nowhere"),
    }

    let sock = Arc::new(
        udp::bind(cfg.listen_addr)
            .await
            .with_context(|| format!("bind UDP {}", cfg.listen_addr))?,
    );
    tracing::info!(addr = %sock.local_addr()?, "listener up");

    let node = Arc::new(Node::new(
        Arc::clone(&tags),
        IpPool::new(network, pool_prefix),
        (cfg.tun.mtu as usize).min(packet::TUNNEL_MTU),
    ));

    let device = if cli.datapath {
        Some(Arc::new(bring_up_tun(&cfg, tun_addr, prefix)?))
    } else {
        tracing::warn!(
            "running without --datapath: handshakes are answered, IP packets are dropped"
        );
        None
    };

    serve(ServeCtx {
        sock,
        node,
        device,
        panel,
        clock: Clock::new(),
        report_every: Duration::from_secs(cfg.panel.interval_secs.max(1)),
    })
    .await
}

/// Keep the in-memory tag table in step with the panel.
fn spawn_key_puller(
    panel: PanelClient,
    tags: Arc<RwLock<TagTable>>,
    tag_key: [u8; 32],
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match panel.pull_keys().await {
                Ok(keys) => match apply_keys(&tags, &tag_key, &keys) {
                    Ok(n) => tracing::debug!(users = n, "tag table refreshed from the panel"),
                    Err(e) => tracing::warn!(error = %e, "the panel sent a key list we cannot use"),
                },
                // Losing the panel must never disconnect existing clients: we
                // keep serving with the table we already have.
                Err(e) => tracing::warn!(error = %e, "could not pull keys from the panel"),
            }
        }
    });
}

fn bring_up_tun(
    cfg: &ServerConfig,
    tun_addr: Ipv4Addr,
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
        // /etc/sysctl.d/99-bproto.conf. Try anyway; a read-only /proc/sys
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

struct ServeCtx {
    sock: Arc<UdpSocket>,
    node: Arc<Node>,
    device: Option<Arc<dev::TunDevice>>,
    panel: Option<PanelClient>,
    clock: Clock,
    report_every: Duration,
}

async fn serve(ctx: ServeCtx) -> anyhow::Result<()> {
    let ServeCtx {
        sock,
        node,
        device,
        panel,
        clock,
        report_every,
    } = ctx;

    // TUN reads block, so they happen on a dedicated thread that hands packets
    // back over a channel.
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

    let mut tick = tokio::time::interval(vpn_server::server::TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut report_tick = tokio::time::interval(report_every);
    report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut stats_tick = tokio::time::interval(Duration::from_secs(60));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut datagram = vec![0u8; MAX_DATAGRAM + 32];

    loop {
        tokio::select! {
            received = sock.recv_from(&mut datagram) => {
                let Ok((n, from)) = received else { continue };
                match node.route(&sock, &datagram[..n], from, clock.now_us()).await {
                    Ok(Outcome::Packet(pkt)) => {
                        if let Some(device) = &device
                            && let Err(e) = device.write_packet(&pkt)
                        {
                            tracing::warn!(error = %e, "TUN write failed");
                        }
                    }
                    Ok(Outcome::Handshaked { user_id, ip }) => {
                        tracing::debug!(user_id, %ip, "accepted a client");
                    }
                    Ok(Outcome::Nothing) => {}
                    Err(e) => tracing::debug!(error = %e, %from, "datagram rejected"),
                }
            }

            Some(pkt) = tun_rx.recv() => {
                let Some(dst) = vpn_core::ip::dst_ipv4(&pkt) else { continue };
                match node.send_to_client(&sock, dst, &pkt, clock.now_us()).await {
                    Ok(true) => {}
                    Ok(false) => tracing::trace!(%dst, "no route, or congestion window full"),
                    Err(e) => tracing::debug!(error = %e, "outbound packet dropped"),
                }
            }

            _ = tick.tick() => {
                let closed = node.reap(&sock, clock.now_us()).await;
                if !closed.is_empty()
                    && let Some(panel) = &panel
                {
                    let finals = Node::final_deltas(&closed, unix_now_secs() as i64);
                    push(panel, finals).await;
                }
            }

            _ = report_tick.tick() => {
                if let Some(panel) = &panel {
                    let deltas = node.take_deltas(unix_now_secs() as i64).await;
                    push(panel, deltas).await;
                }
            }

            _ = stats_tick.tick() => {
                let s = node.stats().await;
                tracing::info!(
                    sessions = s.sessions,
                    handshakes = s.handshakes,
                    rejected = s.rejected_handshakes,
                    unknown_tags = s.unknown_tags,
                    "stats"
                );
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                if let Some(panel) = &panel {
                    // Close out live sessions so the panel does not show them
                    // as online for another five minutes.
                    let now = unix_now_secs() as i64;
                    let mut deltas = node.take_deltas(now).await;
                    for d in &mut deltas {
                        d.ended_at = Some(now);
                    }
                    push(panel, deltas).await;
                }
                return Ok(());
            }
        }
    }
}

async fn push(panel: &PanelClient, sessions: Vec<vpn_server::control::SessionDelta>) {
    if sessions.is_empty() {
        return;
    }
    let batch = SessionReport {
        server_id: panel.server_id().to_string(),
        sessions,
    };
    if let Err(e) = panel.report(&batch).await {
        tracing::warn!(error = %e, "could not report sessions to the panel");
    }
}
