//! Native interoperability test helper; token comes from the environment.
#[cfg(feature = "quic")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use vpn_core::transport::quic::QuicTransport;
    let args: Vec<String> = std::env::args().collect();
    let server: std::net::SocketAddr = args.get(1).ok_or("endpoint required")?.parse()?;
    let hostname = args.get(2).ok_or("hostname required")?;
    let ca = args.get(3).map(std::fs::read).transpose()?;
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let bridge = QuicTransport::bind(bind.parse()?)?
        .connect(server, hostname, &std::env::var("BPROTO_BRIDGE_TOKEN")?, ca)
        .await?;
    println!("{}", bridge.local_port());
    while !bridge.is_finished() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err("carrier stopped".into())
}
#[cfg(not(feature = "quic"))]
fn main() {
    eprintln!("requires --features quic");
    std::process::exit(1);
}
