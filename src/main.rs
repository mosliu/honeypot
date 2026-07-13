use anyhow::{Context, anyhow};
use clap::Parser;
use honeypot::{
    admin::run_admin_api_with_readiness,
    ban::BanManager,
    config::AppConfig,
    firewall::{Firewall, SystemCommandRunner, SystemFirewall, log_firewall_backend},
    honeypot::run_honeypot_with_readiness,
    logging::{init_logging, spawn_cleanup_worker},
    webdav::{spawn_sync_worker, sync_channel},
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
};
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Configurable Rust honeypot for Debian/Ubuntu firewalls"
)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    #[arg(long, help = "Validate the configuration without starting the service")]
    check_config: bool,
}

enum StopTrigger {
    Signal,
    StartupFailure(String),
    Honeypot(Result<anyhow::Result<()>, tokio::task::JoinError>),
    Admin(Result<anyhow::Result<()>, tokio::task::JoinError>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(&cli.config)?;
    if cli.check_config {
        println!("configuration is valid: {}", cli.config.display());
        return Ok(());
    }

    let _logging_guard = init_logging(&config.logging)?;
    info!(config = %cli.config.display(), "honeypot starting");
    log_firewall_backend(&config.firewall);

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let logging_worker = spawn_cleanup_worker(config.logging.clone(), shutdown_receiver.clone());
    let (sync_sender, sync_receiver) = sync_channel();
    let sync_sender = config.webdav.enabled.then_some(sync_sender);
    let webdav_worker = spawn_sync_worker(config.webdav.clone(), sync_receiver);

    let firewall: Arc<dyn Firewall> = Arc::new(SystemFirewall::new(
        config.firewall.clone(),
        SystemCommandRunner::new(Duration::from_secs(config.firewall.command_timeout_seconds)),
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
    manager
        .compact_state()
        .await
        .context("failed to compact restored banned IP state")?;

    let (honeypot_ready_sender, honeypot_ready_receiver) = oneshot::channel();
    let mut honeypot_task = tokio::spawn(run_honeypot_with_readiness(
        config.honeypot.clone(),
        config.admin.clone(),
        manager.clone(),
        shutdown_receiver.clone(),
        Some(honeypot_ready_sender),
    ));
    let (mut admin_task, admin_ready_receiver) = if config.admin.inline_on_honeypot_port {
        info!(
            path_prefix = config.admin.inline_path_prefix,
            "admin API is enabled on the honeypot listener for allowlisted sources"
        );
        (None, None)
    } else {
        let (admin_ready_sender, admin_ready_receiver) = oneshot::channel();
        let task = tokio::spawn(run_admin_api_with_readiness(
            config.admin.clone(),
            manager.clone(),
            shutdown_receiver,
            Some(admin_ready_sender),
        ));
        (Some(task), Some(admin_ready_receiver))
    };

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let readiness = await_readiness(honeypot_ready_receiver, admin_ready_receiver);
    tokio::pin!(readiness);
    let startup_trigger = if let Some(admin_task) = admin_task.as_mut() {
        tokio::select! {
            signal = &mut shutdown => Some(signal_trigger(signal)),
            result = &mut honeypot_task => Some(StopTrigger::Honeypot(result)),
            result = admin_task => Some(StopTrigger::Admin(result)),
            result = &mut readiness => result.err().map(|error| {
                StopTrigger::StartupFailure(format!("service readiness failed: {error:#}"))
            }),
        }
    } else {
        tokio::select! {
            signal = &mut shutdown => Some(signal_trigger(signal)),
            result = &mut honeypot_task => Some(StopTrigger::Honeypot(result)),
            result = &mut readiness => result.err().map(|error| {
                StopTrigger::StartupFailure(format!("service readiness failed: {error:#}"))
            }),
        }
    };

    let mut notified_ready = false;
    let trigger = if let Some(trigger) = startup_trigger {
        trigger
    } else if let Err(error) = notify_ready() {
        StopTrigger::StartupFailure(format!("failed to notify service readiness: {error:#}"))
    } else {
        notified_ready = true;
        info!("all required listeners are ready");
        if let Some(admin_task) = admin_task.as_mut() {
            tokio::select! {
                signal = &mut shutdown => signal_trigger(signal),
                result = &mut honeypot_task => StopTrigger::Honeypot(result),
                result = admin_task => StopTrigger::Admin(result),
            }
        } else {
            tokio::select! {
                signal = &mut shutdown => signal_trigger(signal),
                result = &mut honeypot_task => StopTrigger::Honeypot(result),
            }
        }
    };
    if notified_ready && let Err(error) = notify_stopping() {
        warn!(%error, "failed to notify service manager that shutdown started");
    }
    let _ = shutdown_sender.send(true);

    let mut failures = Vec::new();
    match trigger {
        StopTrigger::StartupFailure(error) => {
            failures.push(error);
            collect_task_result(
                "honeypot listener",
                honeypot_task.await,
                false,
                &mut failures,
            );
            if let Some(admin_task) = admin_task {
                collect_task_result("admin API", admin_task.await, false, &mut failures);
            }
        }
        StopTrigger::Signal => {
            collect_task_result(
                "honeypot listener",
                honeypot_task.await,
                false,
                &mut failures,
            );
            if let Some(admin_task) = admin_task {
                collect_task_result("admin API", admin_task.await, false, &mut failures);
            }
        }
        StopTrigger::Honeypot(result) => {
            collect_task_result("honeypot listener", result, true, &mut failures);
            if let Some(admin_task) = admin_task {
                collect_task_result("admin API", admin_task.await, false, &mut failures);
            }
        }
        StopTrigger::Admin(result) => {
            collect_task_result("admin API", result, true, &mut failures);
            collect_task_result(
                "honeypot listener",
                honeypot_task.await,
                false,
                &mut failures,
            );
        }
    }

    if let Err(error) = manager.compact_state().await {
        failures.push(format!("failed to compact banned IP state: {error:#}"));
    }
    drop(manager);
    await_worker("WebDAV worker", webdav_worker, &mut failures).await;
    await_worker("log cleanup worker", Some(logging_worker), &mut failures).await;

    if !failures.is_empty() {
        let message = failures.join("; ");
        error!(%message, "honeypot stopped with errors");
        return Err(anyhow!(message));
    }

    info!("honeypot stopped");
    Ok(())
}

fn collect_task_result(
    name: &str,
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
    unexpected_stop: bool,
    failures: &mut Vec<String>,
) {
    match result {
        Ok(Ok(())) if unexpected_stop => failures.push(format!("{name} stopped unexpectedly")),
        Ok(Ok(())) => {}
        Ok(Err(error)) => failures.push(format!("{name} failed: {error:#}")),
        Err(error) => failures.push(format!("{name} task failed: {error}")),
    }
}

async fn await_worker(name: &str, worker: Option<JoinHandle<()>>, failures: &mut Vec<String>) {
    if let Some(worker) = worker
        && let Err(error) = worker.await
    {
        failures.push(format!("{name} task failed: {error}"));
    }
}

async fn await_readiness(
    honeypot: oneshot::Receiver<()>,
    admin: Option<oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    honeypot
        .await
        .context("honeypot listener stopped before reporting readiness")?;
    if let Some(admin) = admin {
        admin
            .await
            .context("admin API stopped before reporting readiness")?;
    }
    Ok(())
}

fn signal_trigger(result: anyhow::Result<()>) -> StopTrigger {
    match result {
        Ok(()) => {
            info!("shutdown signal received");
            StopTrigger::Signal
        }
        Err(error) => {
            StopTrigger::StartupFailure(format!("failed to listen for shutdown signal: {error:#}"))
        }
    }
}

#[cfg(unix)]
fn notify_ready() -> anyhow::Result<()> {
    sd_notify::notify(&[
        sd_notify::NotifyState::Ready,
        sd_notify::NotifyState::Status("honeypot listeners ready"),
    ])
    .context("failed to send READY=1 to the service manager")
}

#[cfg(not(unix))]
fn notify_ready() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn notify_stopping() -> anyhow::Result<()> {
    sd_notify::notify(&[
        sd_notify::NotifyState::Stopping,
        sd_notify::NotifyState::Status("honeypot shutting down"),
    ])
    .context("failed to send STOPPING=1 to the service manager")
}

#[cfg(not(unix))]
fn notify_stopping() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("failed to listen for SIGTERM")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("failed to listen for Ctrl-C"),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl-C")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_accepts_all_required_listeners() {
        let (honeypot_sender, honeypot_receiver) = oneshot::channel();
        let (admin_sender, admin_receiver) = oneshot::channel();
        honeypot_sender.send(()).unwrap();
        admin_sender.send(()).unwrap();

        await_readiness(honeypot_receiver, Some(admin_receiver))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn readiness_reports_the_listener_that_stopped_early() {
        let (honeypot_sender, honeypot_receiver) = oneshot::channel();
        drop(honeypot_sender);
        let error = await_readiness(honeypot_receiver, None).await.unwrap_err();
        assert!(error.to_string().contains("honeypot listener"));

        let (honeypot_sender, honeypot_receiver) = oneshot::channel();
        let (admin_sender, admin_receiver) = oneshot::channel();
        honeypot_sender.send(()).unwrap();
        drop(admin_sender);
        let error = await_readiness(honeypot_receiver, Some(admin_receiver))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("admin API"));
    }
}
