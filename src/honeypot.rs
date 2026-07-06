use crate::{
    ban::{BanManager, BanOutcome},
    config::{AdminConfig, HoneypotConfig},
    inline_admin::try_handle_inline_admin,
    tracker::{VisitDecision, VisitTracker},
};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug)]
struct BanRequest {
    ip: IpAddr,
    count: usize,
}

#[derive(Clone)]
struct ConnectionContext {
    banner: Arc<Vec<u8>>,
    tracker: Arc<Mutex<VisitTracker>>,
    allowlist: Arc<Vec<crate::allowlist::AllowlistEntry>>,
    ban_sender: mpsc::Sender<BanRequest>,
    manager: BanManager,
    admin_config: AdminConfig,
    read_after_banner_timeout: Duration,
    close_delay: Duration,
}

pub async fn run_honeypot(
    config: HoneypotConfig,
    admin_config: AdminConfig,
    manager: BanManager,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!(
        listen_addr = config.listen_addr,
        "honeypot listener started"
    );

    let tracker = Arc::new(Mutex::new(VisitTracker::new(
        Duration::from_secs(config.window_seconds),
        config.max_visits,
        config.max_tracked_ips,
    )));
    let allowlist = Arc::new(config.allowlist);
    let banner = Arc::new(config.banner.into_bytes());
    let read_after_banner_timeout = Duration::from_millis(config.read_after_banner_timeout_ms);
    let close_delay = Duration::from_millis(config.close_delay_ms);
    let (ban_sender, ban_receiver) = mpsc::channel(4096);
    tokio::spawn(run_ban_worker(manager.clone(), ban_receiver));
    let context = ConnectionContext {
        banner,
        tracker,
        allowlist,
        ban_sender,
        manager,
        admin_config,
        read_after_banner_timeout,
        close_delay,
    };

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() {
                    info!("honeypot listener shutting down");
                }
                break;
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted?;
                let ip = remote_addr.ip();
                let context = context.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, ip, context).await {
                        debug!(%error, %ip, "failed to handle honeypot connection");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    ip: IpAddr,
    context: ConnectionContext,
) -> anyhow::Result<()> {
    if try_handle_inline_admin(&mut stream, &context.manager, &context.admin_config).await? {
        return Ok(());
    }

    if context.allowlist.iter().any(|entry| entry.contains(ip)) {
        debug!(%ip, "honeypot visit ignored because IP is allowlisted");
    } else {
        let decision = {
            let mut tracker = context.tracker.lock().await;
            tracker.record(ip)
        };

        match decision {
            VisitDecision::Allow { count } => {
                debug!(%ip, count, "honeypot visit recorded");
            }
            VisitDecision::Ban { count } => {
                warn!(%ip, count, "honeypot threshold reached");
                let request = BanRequest { ip, count };
                if let Err(error) = context.ban_sender.try_send(request) {
                    error!(%error, %ip, "ban queue is full; failed to queue ban");
                }
            }
        }
    }

    if !context.banner.is_empty() {
        stream.write_all(&context.banner).await?;
    }
    if !context.read_after_banner_timeout.is_zero() {
        let mut client_identification = [0_u8; 256];
        let _ = timeout(
            context.read_after_banner_timeout,
            stream.read(&mut client_identification),
        )
        .await;
    }
    if !context.close_delay.is_zero() {
        sleep(context.close_delay).await;
    }
    stream.shutdown().await?;
    Ok(())
}

async fn run_ban_worker(manager: BanManager, mut receiver: mpsc::Receiver<BanRequest>) {
    while let Some(request) = receiver.recv().await {
        match manager.ban_ip(request.ip, "honeypot_rate_limit").await {
            Ok(BanOutcome::Banned) => info!(
                ip = %request.ip,
                count = request.count,
                "queued firewall ban completed"
            ),
            Ok(BanOutcome::AlreadyBanned) => debug!(
                ip = %request.ip,
                count = request.count,
                "ban request ignored because IP is already banned"
            ),
            Err(error) => error!(
                ip = %request.ip,
                count = request.count,
                %error,
                "queued firewall ban failed"
            ),
        }
    }
}
