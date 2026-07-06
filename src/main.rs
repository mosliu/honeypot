use anyhow::{Context, bail};
use clap::Parser;
use honeypot::{
    admin::run_admin_api,
    ban::BanManager,
    config::AppConfig,
    firewall::{Firewall, SystemCommandRunner, SystemFirewall, log_firewall_backend},
    honeypot::run_honeypot,
    logging::init_logging,
    webdav::spawn_sync_worker,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::mpsc, sync::watch, time::timeout};
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Configurable Rust honeypot for Debian/Ubuntu firewalls"
)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(&cli.config)?;
    let _logging_guard = init_logging(&config.logging)?;
    info!(config = %cli.config.display(), "honeypot starting");
    log_firewall_backend(&config.firewall);

    let (sync_sender, sync_receiver) = mpsc::channel(16);
    let sync_sender = config.webdav.enabled.then_some(sync_sender);
    let _webdav_worker = spawn_sync_worker(config.webdav.clone(), sync_receiver);

    let firewall: Arc<dyn Firewall> = Arc::new(SystemFirewall::new(
        config.firewall.clone(),
        SystemCommandRunner,
    ));
    let manager = BanManager::load(
        firewall,
        PathBuf::from(&config.state.banned_ips_path),
        sync_sender,
    )?;
    manager
        .setup_and_restore()
        .await
        .context("failed to initialize firewall and restore banned IPs")?;

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut honeypot_task = tokio::spawn(run_honeypot(
        config.honeypot.clone(),
        config.admin.clone(),
        manager.clone(),
        shutdown_receiver.clone(),
    ));
    let mut admin_task = if config.admin.inline_on_honeypot_port {
        info!(
            path_prefix = config.admin.inline_path_prefix,
            "admin API is enabled on the honeypot listener"
        );
        None
    } else {
        Some(tokio::spawn(run_admin_api(
            config.admin.clone(),
            manager.clone(),
            shutdown_receiver,
        )))
    };

    let completed = if let Some(admin_task) = admin_task.as_mut() {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl-C")?;
                info!("shutdown signal received");
                None
            }
            result = &mut honeypot_task => Some(("honeypot listener", result)),
            result = admin_task => Some(("admin API", result)),
        }
    } else {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for Ctrl-C")?;
                info!("shutdown signal received");
                None
            }
            result = &mut honeypot_task => Some(("honeypot listener", result)),
        }
    };

    let _ = shutdown_sender.send(true);

    if let Some((name, result)) = completed {
        if let Some(admin_task) = &admin_task {
            admin_task.abort();
        }
        honeypot_task.abort();
        match result {
            Ok(Ok(())) => bail!("{name} stopped unexpectedly"),
            Ok(Err(error)) => {
                error!(%error, "{name} failed");
                return Err(error).with_context(|| format!("{name} failed"));
            }
            Err(error) => return Err(error).with_context(|| format!("{name} task failed")),
        }
    }

    let _ = timeout(Duration::from_secs(5), async {
        let _ = honeypot_task.await;
        if let Some(admin_task) = admin_task {
            let _ = admin_task.await;
        }
    })
    .await;
    info!("honeypot stopped");
    Ok(())
}
