use anyhow::{Context, anyhow};
use axum::Router;
use cargo_metadata::{Message, TargetKind, camino::Utf8PathBuf};
use clap::Parser;
use mime::Mime;
use std::{
    env,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Command, Stdio},
    str::FromStr,
};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

/// Custom commands
#[derive(Parser)]
enum Subcommand {
    /// Run WASM benchmarks in a browser
    WasmBench {
        /// The name of a benchmark target
        bench: String,

        /// Build benchmarks with the specified profile
        #[clap(long)]
        #[arg(default_value = "release")]
        profile: String,

        /// Overrides the RUSTFLAGS environment variable when building
        #[clap(long)]
        rustflags: Option<String>,

        /// HTTP server IP address
        #[clap(long)]
        #[arg(default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
        address: IpAddr,

        /// HTTP server port number
        #[clap(long)]
        #[arg(default_value_t = 4000)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let subcommand = Subcommand::parse();
    match subcommand {
        Subcommand::WasmBench {
            bench,
            profile,
            rustflags,
            address,
            port,
        } => {
            run_benchmarks(
                &bench,
                &profile,
                rustflags.as_deref(),
                (address, port).into(),
            )
            .await?;
        }
    }
    Ok(())
}

/// Runs WASM benchmarks in the browser.
async fn run_benchmarks(
    bench: &str,
    profile: &str,
    rustflags: Option<&str>,
    socket_addr: SocketAddr,
) -> Result<(), anyhow::Error> {
    let (manifest_path, binary_path) = build_benchmark(bench, profile, rustflags)?;

    let listener = TcpListener::bind(socket_addr).await?;
    let router = make_router(manifest_path, binary_path)?;

    let authority = match socket_addr.ip() {
        IpAddr::V4(ipv4_addr) => format!("{ipv4_addr}:{}", socket_addr.port()),
        IpAddr::V6(ipv6_addr) => format!("[{ipv6_addr}]:{}", socket_addr.port()),
    };
    let url = axum::http::uri::Builder::new()
        .scheme("http")
        .authority(authority)
        .path_and_query("/")
        .build()?;
    webbrowser::open(&url.to_string())?;

    axum::serve(listener, router).await?;

    Ok(())
}

/// Compiles the benchmark target.
///
/// This returns the path to the main crate's manifest file, and the path to the resulting binary.
fn build_benchmark(
    bench: &str,
    profile: &str,
    rustflags: Option<&str>,
) -> Result<(Utf8PathBuf, Utf8PathBuf), anyhow::Error> {
    let cargo_path = env::var_os("CARGO").context("CARGO environment variable was not set")?;
    let mut cargo_command = Command::new(cargo_path);
    cargo_command.args([
        "bench",
        "--bench",
        bench,
        "--profile",
        profile,
        "--target=wasm32-wasip1",
        "--no-run",
        "--message-format=json",
    ]);
    cargo_command.stdout(Stdio::piped());
    if let Some(rustflags) = rustflags {
        cargo_command.env("RUSTFLAGS", rustflags);
    }
    let mut cargo_child = cargo_command.spawn()?;

    let reader = BufReader::new(cargo_child.stdout.take().unwrap());
    let mut bench_binaries = Message::parse_stream(reader)
        .filter_map(|result| {
            let artifact = match result {
                Ok(Message::CompilerArtifact(artifact)) => artifact,
                Ok(_) => return None,
                Err(e) => return Some(Err(e)),
            };
            if !artifact.target.kind.contains(&TargetKind::Bench) {
                return None;
            }
            let Some(executable) = artifact.executable else {
                return None;
            };
            Some(Ok((artifact.manifest_path, executable)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output = cargo_child.wait()?;
    if !output.success() {
        return Err(anyhow!("cargo command failed"));
    }

    if bench_binaries.len() > 1 {
        return Err(anyhow!("multiple benchmark binaries were produced"));
    }
    bench_binaries
        .pop()
        .ok_or_else(|| anyhow!("no benchmark target named {bench} was found"))
}

/// Constructs the HTTP application.
fn make_router(
    manifest_path: Utf8PathBuf,
    binary_path: Utf8PathBuf,
) -> Result<Router, anyhow::Error> {
    let wasm_mime = Mime::from_str("application/wasm").unwrap();
    let mut assets_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("invalid manifest path"))?
        .to_path_buf();
    assets_dir.push("xtask");
    assets_dir.push("assets");

    let wasm_file_service = ServeFile::new_with_mime(binary_path, &wasm_mime);
    let assets_service = ServeDir::new(assets_dir);

    let router = Router::new()
        .nest_service("/executable.wasm", wasm_file_service)
        .fallback_service(assets_service);

    Ok(router)
}
