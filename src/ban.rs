use crate::{
    firewall::Firewall,
    store::{
        BanRecord, BanStateChange, append_state_change, clear_pending_change, compact_banned_ips,
        load_banned_ips, load_pending_change, save_pending_change,
    },
};
use anyhow::Context;
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock, watch};
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
    sync_sender: Option<watch::Sender<Arc<[BanRecord]>>>,
}

impl BanManager {
    pub fn load(
        firewall: Arc<dyn Firewall>,
        state_path: impl Into<PathBuf>,
        sync_sender: Option<watch::Sender<Arc<[BanRecord]>>>,
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
        tokio::task::spawn_blocking(move || firewall.setup())
            .await
            .context("firewall setup task failed")??;

        let snapshot = self.records_snapshot().await;
        for record in snapshot {
            let firewall = Arc::clone(&self.firewall);
            let ip = record.ip;
            tokio::task::spawn_blocking(move || firewall.ban(ip))
                .await
                .with_context(|| format!("firewall restore task failed for {ip}"))??;
            info!(%ip, reason = record.reason, "restored firewall ban from local state");
        }

        let guard = self.operation_lock.lock().await;
        self.recover_pending_locked().await?;
        drop(guard);
        self.notify_sync().await;
        Ok(())
    }

    pub async fn ban_ip(
        &self,
        ip: IpAddr,
        reason: impl Into<String>,
    ) -> anyhow::Result<BanOutcome> {
        let reason = reason.into();
        let guard = self.operation_lock.lock().await;
        let recovered = self.recover_pending_locked().await?;

        let result: anyhow::Result<BanOutcome> = async {
            if self.records.read().await.contains_key(&ip) {
                return Ok(BanOutcome::AlreadyBanned);
            }

            let record = BanRecord::new(ip, reason.clone());
            let change = BanStateChange::Ban { record };
            save_pending_change(&self.state_path, &change)?;
            self.finish_change_locked(&change).await?;
            info!(%ip, reason, "banned IP address");
            Ok(BanOutcome::Banned)
        }
        .await;
        let changed = recovered || matches!(&result, Ok(BanOutcome::Banned));

        drop(guard);
        if changed {
            self.notify_sync().await;
        }
        result
    }

    pub async fn unban_ip(&self, ip: IpAddr) -> anyhow::Result<UnbanOutcome> {
        let guard = self.operation_lock.lock().await;
        let recovered = self.recover_pending_locked().await?;

        let result: anyhow::Result<UnbanOutcome> = async {
            if !self.records.read().await.contains_key(&ip) {
                return Ok(UnbanOutcome::NotBanned);
            }

            let change = BanStateChange::Unban { ip };
            save_pending_change(&self.state_path, &change)?;
            self.finish_change_locked(&change).await?;
            info!(%ip, "unbanned IP address");
            Ok(UnbanOutcome::Unbanned)
        }
        .await;
        let changed = recovered || matches!(&result, Ok(UnbanOutcome::Unbanned));

        drop(guard);
        if changed {
            self.notify_sync().await;
        }
        result
    }

    pub async fn compact_state(&self) -> anyhow::Result<()> {
        let guard = self.operation_lock.lock().await;
        let recovered = self.recover_pending_locked().await?;
        let records = self.records.read().await.clone();
        let result = compact_banned_ips(&self.state_path, &records);

        drop(guard);
        if recovered {
            self.notify_sync().await;
        }
        result
    }

    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        self.records.read().await.contains_key(&ip)
    }

    pub async fn records_snapshot(&self) -> Vec<BanRecord> {
        let mut records: Vec<_> = self.records.read().await.values().cloned().collect();
        records.sort_by_key(|record| record.ip);
        records
    }

    async fn recover_pending_locked(&self) -> anyhow::Result<bool> {
        let Some(change) = load_pending_change(&self.state_path)? else {
            return Ok(false);
        };

        let ip = change.ip();
        warn!(%ip, change = ?change, "recovering pending firewall state change");
        self.finish_change_locked(&change).await?;
        info!(%ip, change = ?change, "recovered pending firewall state change");
        Ok(true)
    }

    async fn finish_change_locked(&self, change: &BanStateChange) -> anyhow::Result<()> {
        self.apply_firewall_change(change).await?;
        append_state_change(&self.state_path, change)?;

        {
            let mut records = self.records.write().await;
            change.apply_to(&mut records);
        }

        if let Err(error) = clear_pending_change(&self.state_path) {
            warn!(%error, ip = %change.ip(), "failed to clear committed pending state change");
        }
        Ok(())
    }

    async fn apply_firewall_change(&self, change: &BanStateChange) -> anyhow::Result<()> {
        let firewall = Arc::clone(&self.firewall);
        let ip = change.ip();
        let change = change.clone();
        tokio::task::spawn_blocking(move || match change {
            BanStateChange::Ban { record } => firewall.ban(record.ip),
            BanStateChange::Unban { ip } => firewall.unban(ip),
        })
        .await
        .with_context(|| format!("firewall state change task failed for {ip}"))??;
        Ok(())
    }

    async fn notify_sync(&self) {
        let Some(sender) = &self.sync_sender else {
            return;
        };

        let snapshot: Arc<[BanRecord]> = self.records_snapshot().await.into();
        sender.send_replace(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        firewall::Firewall,
        store::{journal_path, load_pending_change, save_banned_ips, save_pending_change},
    };
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
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

    struct JournalSabotageFirewall {
        state_path: PathBuf,
        sabotage_next_ban: AtomicBool,
        bans: AtomicUsize,
    }

    impl Firewall for JournalSabotageFirewall {
        fn setup(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn ban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            self.bans.fetch_add(1, Ordering::SeqCst);
            if self.sabotage_next_ban.swap(false, Ordering::SeqCst) {
                fs::create_dir(journal_path(&self.state_path))?;
            }
            Ok(())
        }

        fn unban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet))
    }

    #[tokio::test]
    async fn ban_is_idempotent_in_state() {
        let dir = tempfile::tempdir().unwrap();
        let firewall = Arc::new(CountingFirewall::default());
        let manager =
            BanManager::load(firewall.clone(), dir.path().join("banned_ips.json"), None).unwrap();

        assert_eq!(
            manager.ban_ip(ip(1), "test").await.unwrap(),
            BanOutcome::Banned
        );
        assert_eq!(
            manager.ban_ip(ip(1), "test").await.unwrap(),
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

        manager.ban_ip(ip(2), "test").await.unwrap();
        assert_eq!(
            manager.unban_ip(ip(2)).await.unwrap(),
            UnbanOutcome::Unbanned
        );
        assert!(!manager.is_banned(ip(2)).await);
        assert_eq!(firewall.unbans.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pending_ban_is_recovered_during_startup() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("banned_ips.json");
        let record = BanRecord::new(ip(3), "pending");
        save_pending_change(
            &state_path,
            &BanStateChange::Ban {
                record: record.clone(),
            },
        )
        .unwrap();
        let firewall = Arc::new(CountingFirewall::default());
        let manager = BanManager::load(firewall.clone(), &state_path, None).unwrap();

        manager.setup_and_restore().await.unwrap();

        assert!(manager.is_banned(record.ip).await);
        assert_eq!(firewall.bans.load(Ordering::SeqCst), 1);
        assert!(load_pending_change(&state_path).unwrap().is_none());
        assert!(
            load_banned_ips(&state_path)
                .unwrap()
                .contains_key(&record.ip)
        );
    }

    #[tokio::test]
    async fn pending_unban_is_recovered_during_startup() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("banned_ips.json");
        let mut records = HashMap::new();
        records.insert(ip(4), BanRecord::new(ip(4), "snapshot"));
        save_banned_ips(&state_path, &records).unwrap();
        save_pending_change(&state_path, &BanStateChange::Unban { ip: ip(4) }).unwrap();
        let firewall = Arc::new(CountingFirewall::default());
        let manager = BanManager::load(firewall.clone(), &state_path, None).unwrap();

        manager.setup_and_restore().await.unwrap();

        assert!(!manager.is_banned(ip(4)).await);
        assert_eq!(firewall.bans.load(Ordering::SeqCst), 1);
        assert_eq!(firewall.unbans.load(Ordering::SeqCst), 1);
        assert!(load_pending_change(&state_path).unwrap().is_none());
    }

    #[tokio::test]
    async fn journal_failure_keeps_memory_unchanged_and_next_operation_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("banned_ips.json");
        let firewall = Arc::new(JournalSabotageFirewall {
            state_path: state_path.clone(),
            sabotage_next_ban: AtomicBool::new(true),
            bans: AtomicUsize::new(0),
        });
        let manager = BanManager::load(firewall.clone(), &state_path, None).unwrap();

        assert!(manager.ban_ip(ip(5), "test").await.is_err());
        assert!(!manager.is_banned(ip(5)).await);
        assert!(load_pending_change(&state_path).unwrap().is_some());

        fs::remove_dir(journal_path(&state_path)).unwrap();
        assert_eq!(
            manager.ban_ip(ip(5), "test").await.unwrap(),
            BanOutcome::AlreadyBanned
        );
        assert!(manager.is_banned(ip(5)).await);
        assert_eq!(firewall.bans.load(Ordering::SeqCst), 2);
        assert!(load_pending_change(&state_path).unwrap().is_none());
    }

    #[tokio::test]
    async fn pending_persistence_failure_does_not_touch_firewall_or_memory() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let state_path = state_dir.join("banned_ips.json");
        let firewall = Arc::new(CountingFirewall::default());
        let manager = BanManager::load(firewall.clone(), &state_path, None).unwrap();
        fs::write(&state_dir, b"not a directory").unwrap();

        assert!(manager.ban_ip(ip(9), "test").await.is_err());

        assert!(!manager.is_banned(ip(9)).await);
        assert_eq!(firewall.bans.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn compact_state_preserves_records_and_clears_journal() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("banned_ips.json");
        let manager =
            BanManager::load(Arc::new(CountingFirewall::default()), &state_path, None).unwrap();
        manager.ban_ip(ip(6), "test").await.unwrap();
        assert!(journal_path(&state_path).exists());

        manager.compact_state().await.unwrap();

        assert!(!journal_path(&state_path).exists());
        assert!(load_banned_ips(&state_path).unwrap().contains_key(&ip(6)));
    }

    #[tokio::test]
    async fn watch_sync_keeps_latest_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let initial: Arc<[BanRecord]> = Vec::new().into();
        let (sender, receiver) = watch::channel(initial);
        let manager = BanManager::load(
            Arc::new(CountingFirewall::default()),
            dir.path().join("banned_ips.json"),
            Some(sender),
        )
        .unwrap();

        manager.ban_ip(ip(7), "first").await.unwrap();
        manager.ban_ip(ip(8), "second").await.unwrap();

        let latest = receiver.borrow().clone();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].ip, ip(7));
        assert_eq!(latest[1].ip, ip(8));
    }
}
