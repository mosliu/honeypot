use crate::{
    firewall::Firewall,
    store::{BanRecord, load_banned_ips, save_banned_ips},
};
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{info, warn};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BanOutcome {
    Banned,
    AlreadyBanned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnbanOutcome {
    Unbanned,
    NotBanned,
}

#[derive(Clone)]
pub struct BanManager {
    firewall: Arc<dyn Firewall>,
    state_path: PathBuf,
    records: Arc<RwLock<HashMap<IpAddr, BanRecord>>>,
    operation_lock: Arc<Mutex<()>>,
    sync_sender: Option<mpsc::Sender<Vec<BanRecord>>>,
}

impl BanManager {
    pub fn load(
        firewall: Arc<dyn Firewall>,
        state_path: impl Into<PathBuf>,
        sync_sender: Option<mpsc::Sender<Vec<BanRecord>>>,
    ) -> anyhow::Result<Self> {
        let state_path = state_path.into();
        let records = load_banned_ips(&state_path)?;
        Ok(Self {
            firewall,
            state_path,
            records: Arc::new(RwLock::new(records)),
            operation_lock: Arc::new(Mutex::new(())),
            sync_sender,
        })
    }

    pub async fn setup_and_restore(&self) -> anyhow::Result<()> {
        let firewall = Arc::clone(&self.firewall);
        tokio::task::spawn_blocking(move || firewall.setup()).await??;

        let snapshot = self.records_snapshot().await;
        for record in snapshot {
            let firewall = Arc::clone(&self.firewall);
            let ip = record.ip;
            tokio::task::spawn_blocking(move || firewall.ban(ip)).await??;
            info!(%ip, reason = record.reason, "restored firewall ban from local state");
        }
        self.notify_sync().await;
        Ok(())
    }

    pub async fn ban_ip(
        &self,
        ip: IpAddr,
        reason: impl Into<String>,
    ) -> anyhow::Result<BanOutcome> {
        let reason = reason.into();
        let _guard = self.operation_lock.lock().await;
        if self.records.read().await.contains_key(&ip) {
            return Ok(BanOutcome::AlreadyBanned);
        }

        let firewall = Arc::clone(&self.firewall);
        tokio::task::spawn_blocking(move || firewall.ban(ip)).await??;

        {
            let mut records = self.records.write().await;
            records.insert(ip, BanRecord::new(ip, reason.clone()));
            save_banned_ips(&self.state_path, &records)?;
        }

        info!(%ip, reason, "banned IP address");
        self.notify_sync().await;
        Ok(BanOutcome::Banned)
    }

    pub async fn unban_ip(&self, ip: IpAddr) -> anyhow::Result<UnbanOutcome> {
        let _guard = self.operation_lock.lock().await;
        if !self.records.read().await.contains_key(&ip) {
            return Ok(UnbanOutcome::NotBanned);
        }

        let firewall = Arc::clone(&self.firewall);
        tokio::task::spawn_blocking(move || firewall.unban(ip)).await??;

        {
            let mut records = self.records.write().await;
            records.remove(&ip);
            save_banned_ips(&self.state_path, &records)?;
        }

        info!(%ip, "unbanned IP address");
        self.notify_sync().await;
        Ok(UnbanOutcome::Unbanned)
    }

    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        self.records.read().await.contains_key(&ip)
    }

    pub async fn records_snapshot(&self) -> Vec<BanRecord> {
        let mut records: Vec<_> = self.records.read().await.values().cloned().collect();
        records.sort_by_key(|record| record.ip);
        records
    }

    async fn notify_sync(&self) {
        let Some(sender) = &self.sync_sender else {
            return;
        };

        let snapshot = self.records_snapshot().await;
        if let Err(error) = sender.send(snapshot).await {
            warn!(%error, "failed to queue WebDAV sync");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::Firewall;
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Default)]
    struct CountingFirewall {
        bans: AtomicUsize,
        unbans: AtomicUsize,
    }

    impl Firewall for CountingFirewall {
        fn setup(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn ban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            self.bans.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn unban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            self.unbans.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn ban_is_idempotent_in_state() {
        let dir = tempfile::tempdir().unwrap();
        let firewall = Arc::new(CountingFirewall::default());
        let manager =
            BanManager::load(firewall.clone(), dir.path().join("banned_ips.json"), None).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        assert_eq!(
            manager.ban_ip(ip, "test").await.unwrap(),
            BanOutcome::Banned
        );
        assert_eq!(
            manager.ban_ip(ip, "test").await.unwrap(),
            BanOutcome::AlreadyBanned
        );

        assert_eq!(firewall.bans.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unban_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let firewall = Arc::new(CountingFirewall::default());
        let manager =
            BanManager::load(firewall.clone(), dir.path().join("banned_ips.json"), None).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

        manager.ban_ip(ip, "test").await.unwrap();
        assert_eq!(manager.unban_ip(ip).await.unwrap(), UnbanOutcome::Unbanned);
        assert!(!manager.is_banned(ip).await);
        assert_eq!(firewall.unbans.load(Ordering::SeqCst), 1);
    }
}
