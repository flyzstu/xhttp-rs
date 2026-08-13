use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use xhttp::{
    Server,
    config::{ServerConfig, ServerTlsConfig},
    singbox::SingBoxConfig,
};

#[derive(Parser)]
#[command(
    version,
    about = "XHTTP client/server compatible with sing-box configuration"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(short = 'c', long)]
        config: String,
    },
    Check {
        #[arg(short = 'c', long)]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { config } => {
            load(&config)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Run { config } => {
            let config = load(&config)?;
            let _log_guard = init_logging(config.log.as_ref())?;
            run(config).await
        }
    }
}

fn init_logging(
    log: Option<&xhttp::singbox::LogConfig>,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let level = if log.is_some_and(|value| value.disabled) {
        "off"
    } else {
        log.and_then(|value| value.level.as_deref()).unwrap_or("info")
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let timestamp = log.and_then(|value| value.timestamp).unwrap_or(true);
    if let Some(output) = log.and_then(|value| value.output.as_deref()) {
        let path = std::path::Path::new(output);
        let directory = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(directory)
            .with_context(|| format!("create log directory {}", directory.display()))?;
        let file = path.file_name().context("log output must name a file")?;
        let (writer, guard) =
            tracing_appender::non_blocking(tracing_appender::rolling::never(directory, file));
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(writer);
        if timestamp {
            subscriber
                .try_init()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        } else {
            subscriber
                .without_time()
                .try_init()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        Ok(Some(guard))
    } else {
        let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
        if timestamp {
            subscriber
                .try_init()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        } else {
            subscriber
                .without_time()
                .try_init()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        Ok(None)
    }
}
fn load(path: &str) -> Result<SingBoxConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read configuration {path}"))?;
    let config = SingBoxConfig::from_json(&text)?;
    config.validate_runtime()?;
    Ok(config)
}
async fn run(config: SingBoxConfig) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let clash_api = config
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.clash_api.clone());
    let shared_runtime = if clash_api.is_some() {
        Some(std::sync::Arc::new(
            xhttp::proxy::build_runtime(
                config.outbounds.clone(),
                config.route.clone(),
                config.dns.clone(),
                config.http_clients.clone(),
            )
            .await?,
        ))
    } else {
        None
    };
    for inbound in config.inbounds {
        if inbound.r#type == "tun" {
            let outbounds = config.outbounds.clone();
            let route = config.route.clone();
            let dns = config.dns.clone();
            let http_clients = config.http_clients.clone();
            tasks.spawn(async move { xhttp::tun::run(inbound, outbounds, route, dns, http_clients).await });
            continue;
        }
        if matches!(inbound.r#type.as_str(), "socks" | "http" | "mixed") {
            let outbounds = config.outbounds.clone();
            let route = config.route.clone();
            let dns = config.dns.clone();
            let http_clients = config.http_clients.clone();
            if let Some(runtime) = shared_runtime.clone() {
                tasks.spawn(async move { xhttp::proxy::run_socks_with_runtime(inbound, runtime).await });
            } else {
                tasks.spawn(
                    async move { xhttp::proxy::run_socks(inbound, outbounds, route, dns, http_clients).await },
                );
            }
            continue;
        }
        if inbound.r#type == "anytls" {
            let outbounds = config.outbounds.clone();
            let route = config.route.clone();
            let dns = config.dns.clone();
            let http_clients = config.http_clients.clone();
            tasks.spawn(
                async move { xhttp::anytls::run_inbound(inbound, outbounds, route, dns, http_clients).await },
            );
            continue;
        }
        if !(inbound.r#type == "vless"
            && inbound
                .transport
                .as_ref()
                .is_some_and(|t| t.r#type == "xhttp"))
        {
            continue;
        }
        let listen = socket(
            &inbound.listen.unwrap_or_else(|| "::".into()),
            inbound
                .listen_port
                .context("xhttp inbound requires listen_port")?,
        );
        let transport = inbound
            .transport
            .context("xhttp inbound requires transport")?
            .build()?;
        let users = inbound.users.into_iter().filter_map(|v| v.uuid).collect();
        let tls = inbound.tls.filter(|v| v.enabled).map(|v| ServerTlsConfig {
            http3: v.alpn.iter().any(|value| value == "h3"),
            certificate: v.certificate_path.unwrap_or_else(|| pem(v.certificate)),
            private_key: v.key_path.unwrap_or_else(|| pem(v.key)),
        });
        let server = Server::new(ServerConfig {
            listen,
            target: String::new(),
            users,
            transport,
            tls,
        })?;
        tasks.spawn(server.run());
    }
    if let (Some(clash_api), Some(runtime)) = (clash_api, shared_runtime) {
        tasks.spawn(async move { xhttp::clash::run(clash_api, (*runtime).clone()).await });
    }
    if tasks.is_empty() {
        bail!("no supported inbound found")
    }
    tokio::select! {
        result = tasks.join_next() => if let Some(value) = result { value?? },
        result = shutdown_signal() => result?,
    }
    tasks.abort_all();
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("wait for Ctrl-C")?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")
}

fn socket(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn pem(lines: Vec<String>) -> String {
    let mut value = lines.join("\n");
    if !value.ends_with('\n') {
        value.push('\n')
    }
    value
}
