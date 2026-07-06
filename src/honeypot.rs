use crate::{
    ban::{BanManager, BanOutcome},
    config::HoneypotConfig,
    tracker::{VisitDecision, VisitTracker},
};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
};
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug)]
struct BanRequest {
    ip: IpAddr,
    count: usize,
}

pub async fn run_honeypot(
    config: HoneypotConfig,
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
    let (ban_sender, ban_receiver) = mpsc::channel(4096);
    tokio::spawn(run_ban_worker(manager, ban_receiver));

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
                let banner = Arc::clone(&banner);
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, banner).await {
                        debug!(%error, %ip, "failed to write honeypot banner");
                    }
                });

                if allowlist.iter().any(|entry| entry.contains(ip)) {
                    debug!(%ip, "honeypot visit ignored because IP is allowlisted");
                    continue;
                }

                let decision = {
                    let mut tracker = tracker.lock().await;
                    tracker.record(ip)
                };

                match decision {
                    VisitDecision::Allow { count } => {
                        debug!(%ip, count, "honeypot visit recorded");
                    }
                    VisitDecision::Ban { count } => {
                        warn!(%ip, count, "honeypot threshold reached");
                        let request = BanRequest { ip, count };
                        if let Err(error) = ban_sender.try_send(request) {
                            error!(%error, %ip, "ban queue is full; failed to queue ban");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_connection(mut stream: TcpStream, banner: Arc<Vec<u8>>) -> anyhow::Result<()> {
    if !banner.is_empty() {
        stream.write_all(&banner).await?;
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
