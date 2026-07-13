use crate::{
    ban::{BanManager, BanOutcome},
    config::{AdminConfig, HoneypotConfig},
    inline_admin::try_handle_inline_admin,
    tracker::{VisitDecision, VisitTracker},
};
use anyhow::Context;
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug)]
struct BanRequest {
    ip: IpAddr,
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BanQueueOutcome {
    Queued,
    AlreadyPending,
}

#[derive(Clone)]
struct BanQueue {
    sender: mpsc::Sender<BanRequest>,
    pending: Arc<StdMutex<HashSet<IpAddr>>>,
}

impl BanQueue {
    async fn enqueue(&self, request: BanRequest) -> anyhow::Result<BanQueueOutcome> {
        {
            let pending = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("ban pending set lock was poisoned"))?;
            if pending.contains(&request.ip) {
                return Ok(BanQueueOutcome::AlreadyPending);
            }
        }

        let permit = self
            .sender
            .clone()
            .reserve_owned()
            .await
            .context("ban worker stopped before request could be queued")?;
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("ban pending set lock was poisoned"))?;
        if !pending.insert(request.ip) {
            return Ok(BanQueueOutcome::AlreadyPending);
        }
        permit.send(request);
        Ok(BanQueueOutcome::Queued)
    }
}

#[derive(Clone)]
struct ConnectionContext {
    banner: Arc<Vec<u8>>,
    tracker: Arc<Mutex<VisitTracker>>,
    allowlist: Arc<Vec<crate::allowlist::AllowlistEntry>>,
    ban_queue: BanQueue,
    manager: BanManager,
    admin_config: AdminConfig,
    read_after_banner_timeout: Duration,
    close_delay: Duration,
}

const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

struct AcceptBackoff {
    current: Duration,
}

impl AcceptBackoff {
    fn new() -> Self {
        Self {
            current: ACCEPT_BACKOFF_INITIAL,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(ACCEPT_BACKOFF_MAX);
        delay
    }

    fn reset(&mut self) {
        self.current = ACCEPT_BACKOFF_INITIAL;
    }
}

pub async fn run_honeypot(
    config: HoneypotConfig,
    admin_config: AdminConfig,
    manager: BanManager,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_honeypot_with_readiness(config, admin_config, manager, shutdown, None).await
}

pub async fn run_honeypot_with_readiness(
    config: HoneypotConfig,
    admin_config: AdminConfig,
    manager: BanManager,
    mut shutdown: watch::Receiver<bool>,
    readiness: Option<oneshot::Sender<()>>,
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
    let (ban_sender, ban_receiver) = mpsc::channel(config.ban_queue_capacity);
    let pending_bans = Arc::new(StdMutex::new(HashSet::new()));
    let ban_queue = BanQueue {
        sender: ban_sender,
        pending: Arc::clone(&pending_bans),
    };
    let ban_worker = tokio::spawn(run_ban_worker(manager.clone(), ban_receiver, pending_bans));
    let connection_limit = Arc::new(Semaphore::new(config.max_concurrent_connections));
    let mut connections = JoinSet::new();
    let mut accept_backoff = AcceptBackoff::new();
    let context = ConnectionContext {
        banner,
        tracker,
        allowlist,
        ban_queue,
        manager,
        admin_config,
        read_after_banner_timeout,
        close_delay,
    };
    if let Some(readiness) = readiness {
        let _ = readiness.send(());
    }

    'accept: loop {
        while let Some(joined) = connections.try_join_next() {
            log_connection_result(Some(joined));
        }
        let permit = loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_ok() {
                        info!("honeypot listener shutting down");
                    }
                    break 'accept;
                }
                joined = connections.join_next(), if !connections.is_empty() => {
                    log_connection_result(joined);
                }
                permit = Arc::clone(&connection_limit).acquire_owned() => {
                    break permit.context("honeypot connection semaphore was closed")?;
                }
            }
        };

        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                drop(permit);
                if changed.is_ok() {
                    info!("honeypot listener shutting down");
                }
                break;
            }
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, remote_addr)) => {
                accept_backoff.reset();
                let ip = remote_addr.ip();
                let context = context.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, ip, context).await
                });
            }
            Err(error) => {
                drop(permit);
                let delay = accept_backoff.next_delay();
                warn!(%error, ?delay, "honeypot accept failed; retrying");
                tokio::select! {
                    _ = sleep(delay) => {}
                    _ = shutdown.changed() => break,
                }
            }
        }
    }

    while let Some(joined) = connections.join_next().await {
        log_connection_result(Some(joined));
    }
    drop(context);
    ban_worker.await.context("ban worker task failed")?;
    Ok(())
}

fn log_connection_result(result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>) {
    match result {
        Some(Ok(Err(error))) => debug!(%error, "failed to handle honeypot connection"),
        Some(Err(error)) => warn!(%error, "honeypot connection task failed"),
        _ => {}
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    ip: IpAddr,
    context: ConnectionContext,
) -> anyhow::Result<()> {
    let allowlisted = context.allowlist.iter().any(|entry| entry.contains(ip));
    if allowlisted {
        debug!(%ip, "honeypot visit ignored because IP is allowlisted");
    } else if context.manager.is_banned(ip).await {
        debug!(%ip, "honeypot visit ignored because IP is already banned");
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
                match context.ban_queue.enqueue(request).await {
                    Ok(BanQueueOutcome::Queued) => debug!(%ip, "ban request queued"),
                    Ok(BanQueueOutcome::AlreadyPending) => {
                        debug!(%ip, "ban request merged with an existing pending request")
                    }
                    Err(error) => error!(%error, %ip, "failed to queue ban request"),
                }
            }
        }
    }

    if allowlisted
        && try_handle_inline_admin(&mut stream, &context.manager, &context.admin_config).await?
    {
        return Ok(());
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

async fn run_ban_worker(
    manager: BanManager,
    mut receiver: mpsc::Receiver<BanRequest>,
    pending: Arc<StdMutex<HashSet<IpAddr>>>,
) {
    while let Some(request) = receiver.recv().await {
        let ip = request.ip;
        match manager.ban_ip(ip, "honeypot_rate_limit").await {
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
        match pending.lock() {
            Ok(mut pending) => {
                pending.remove(&ip);
            }
            Err(_) => error!(%ip, "ban pending set lock was poisoned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(last: u8) -> BanRequest {
        BanRequest {
            ip: format!("192.0.2.{last}").parse().unwrap(),
            count: 5,
        }
    }

    #[tokio::test]
    async fn ban_queue_deduplicates_pending_ip() {
        let (sender, mut receiver) = mpsc::channel(2);
        let queue = BanQueue {
            sender,
            pending: Arc::new(StdMutex::new(HashSet::new())),
        };

        assert_eq!(
            queue.enqueue(request(1)).await.unwrap(),
            BanQueueOutcome::Queued
        );
        assert_eq!(
            queue.enqueue(request(1)).await.unwrap(),
            BanQueueOutcome::AlreadyPending
        );
        assert_eq!(receiver.recv().await.unwrap().ip, request(1).ip);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn ban_queue_waits_for_capacity_instead_of_dropping() {
        let (sender, mut receiver) = mpsc::channel(1);
        let queue = BanQueue {
            sender,
            pending: Arc::new(StdMutex::new(HashSet::new())),
        };
        queue.enqueue(request(1)).await.unwrap();
        let waiting_queue = queue.clone();
        let waiting = tokio::spawn(async move { waiting_queue.enqueue(request(2)).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        receiver.recv().await.unwrap();
        assert_eq!(waiting.await.unwrap().unwrap(), BanQueueOutcome::Queued);
        assert_eq!(receiver.recv().await.unwrap().ip, request(2).ip);
    }

    #[test]
    fn accept_backoff_is_bounded_and_resettable() {
        let mut backoff = AcceptBackoff::new();
        let delays: Vec<_> = (0..7).map(|_| backoff.next_delay()).collect();
        assert_eq!(
            delays,
            vec![
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ]
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(50));
    }
}
