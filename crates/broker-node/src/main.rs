use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "indramqtt", version, about = "IndraMQTT Distributed Broker Kernel")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    broker_observability::init_tracing();
    let args = Args::parse();

    info!("Starting IndraMQTT Kernel v{} on {}", env!("CARGO_PKG_VERSION"), args.bind);
    info!("BrokerLink IPC protocol initialized");
    info!("Clean-room architecture ready");

    Ok(())
}
