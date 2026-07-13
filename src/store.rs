use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BanRecord {
    pub ip: IpAddr,
    pub banned_at: DateTime<Utc>,
    pub reason: String,
}

impl BanRecord {
    pub fn new(ip: IpAddr, reason: impl Into<String>) -> Self {
        Self {
            ip,
            banned_at: Utc::now(),
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BannedIpsFile {
    pub updated_at: DateTime<Utc>,
    pub ips: Vec<BanRecord>,
}

impl BannedIpsFile {
    pub fn from_records(records: &HashMap<IpAddr, BanRecord>) -> Self {
        let mut ips: Vec<_> = records.values().cloned().collect();
        ips.sort_by_key(|record| record.ip);
        Self {
            updated_at: Utc::now(),
            ips,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum BanStateChange {
    Ban { record: BanRecord },
    Unban { ip: IpAddr },
}

impl BanStateChange {
    pub(crate) fn ip(&self) -> IpAddr {
        match self {
            Self::Ban { record } => record.ip,
            Self::Unban { ip } => *ip,
        }
    }

    pub(crate) fn apply_to(&self, records: &mut HashMap<IpAddr, BanRecord>) {
        match self {
            Self::Ban { record } => {
                records.insert(record.ip, record.clone());
            }
            Self::Unban { ip } => {
                records.remove(ip);
            }
        }
    }
}

pub fn load_banned_ips(path: impl AsRef<Path>) -> anyhow::Result<HashMap<IpAddr, BanRecord>> {
    let path = path.as_ref();
    let mut records = load_snapshot(path)?;
    replay_journal(path, &mut records)?;
    Ok(records)
}

pub fn save_banned_ips(
    path: impl AsRef<Path>,
    records: &HashMap<IpAddr, BanRecord>,
) -> anyhow::Result<()> {
    compact_banned_ips(path, records)
}

pub fn compact_banned_ips(
    path: impl AsRef<Path>,
    records: &HashMap<IpAddr, BanRecord>,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let file = BannedIpsFile::from_records(records);
    let json = serde_json::to_vec_pretty(&file).context("failed to serialize banned IP state")?;
    atomic_write(path, &json)?;
    remove_if_exists(&journal_path(path)).with_context(|| {
        format!(
            "failed to clear banned IP journal {}",
            journal_path(path).display()
        )
    })?;
    Ok(())
}

pub(crate) fn append_state_change(
    path: impl AsRef<Path>,
    change: &BanStateChange,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;

    let journal_path = journal_path(path);
    let mut line = serde_json::to_vec(change).context("failed to serialize banned IP change")?;
    line.push(b'\n');

    let journal_existed = journal_path.exists();
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut journal = options.open(&journal_path).with_context(|| {
        format!(
            "failed to open banned IP journal {}",
            journal_path.display()
        )
    })?;
    restrict_file_permissions(&journal_path)?;
    journal.write_all(&line).with_context(|| {
        format!(
            "failed to append banned IP journal {}",
            journal_path.display()
        )
    })?;
    journal.sync_data().with_context(|| {
        format!(
            "failed to sync banned IP journal {}",
            journal_path.display()
        )
    })?;
    if !journal_existed {
        sync_parent(&journal_path)?;
    }
    Ok(())
}

pub(crate) fn load_pending_change(
    path: impl AsRef<Path>,
) -> anyhow::Result<Option<BanStateChange>> {
    let pending_path = pending_path(path.as_ref());
    if !pending_path.exists() {
        return Ok(None);
    }

    let raw = fs::read(&pending_path).with_context(|| {
        format!(
            "failed to read pending banned IP change {}",
            pending_path.display()
        )
    })?;
    let change = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "failed to parse pending banned IP change {}",
            pending_path.display()
        )
    })?;
    Ok(Some(change))
}

pub(crate) fn save_pending_change(
    path: impl AsRef<Path>,
    change: &BanStateChange,
) -> anyhow::Result<()> {
    let path = pending_path(path.as_ref());
    let json =
        serde_json::to_vec(change).context("failed to serialize pending banned IP change")?;
    atomic_write(&path, &json).with_context(|| {
        format!(
            "failed to persist pending banned IP change {}",
            path.display()
        )
    })
}

pub(crate) fn clear_pending_change(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = pending_path(path.as_ref());
    remove_if_exists(&path).with_context(|| {
        format!(
            "failed to clear pending banned IP change {}",
            path.display()
        )
    })
}

fn load_snapshot(path: &Path) -> anyhow::Result<HashMap<IpAddr, BanRecord>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read banned IP state {}", path.display()))?;
    let file: BannedIpsFile = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse banned IP state {}", path.display()))?;

    Ok(file
        .ips
        .into_iter()
        .map(|record| (record.ip, record))
        .collect())
}

fn replay_journal(path: &Path, records: &mut HashMap<IpAddr, BanRecord>) -> anyhow::Result<()> {
    let journal_path = journal_path(path);
    if !journal_path.exists() {
        return Ok(());
    }

    let raw = fs::read(&journal_path).with_context(|| {
        format!(
            "failed to read banned IP journal {}",
            journal_path.display()
        )
    })?;
    let complete_len = raw
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if complete_len != raw.len() {
        let journal = OpenOptions::new()
            .write(true)
            .open(&journal_path)
            .with_context(|| {
                format!(
                    "failed to open torn banned IP journal {} for repair",
                    journal_path.display()
                )
            })?;
        journal.set_len(complete_len as u64).with_context(|| {
            format!(
                "failed to repair torn banned IP journal {}",
                journal_path.display()
            )
        })?;
        journal.sync_all().with_context(|| {
            format!(
                "failed to sync repaired banned IP journal {}",
                journal_path.display()
            )
        })?;
    }

    for (index, line) in raw[..complete_len].split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let change: BanStateChange = serde_json::from_slice(line).with_context(|| {
            format!(
                "failed to parse banned IP journal {} line {}",
                journal_path.display(),
                index + 1
            )
        })?;
        change.apply_to(records);
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    ensure_parent(path)?;
    let temp_path = temp_path(path);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .with_context(|| format!("failed to write temporary state {}", temp_path.display()))?;
    restrict_file_permissions(&temp_path)?;
    file.write_all(contents)
        .with_context(|| format!("failed to write temporary state {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temporary state {}", temp_path.display()))?;
    drop(file);

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace state file {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    sync_parent(path)?;
    Ok(())
}

fn ensure_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state directory {}", parent.display()))?;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "failed to restrict state file permissions {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::File::open(parent)
            .with_context(|| format!("failed to open state directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync state directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("banned_ips.json"));
    name.push(suffix);
    path.with_file_name(name)
}

pub(crate) fn journal_path(path: &Path) -> PathBuf {
    sidecar_path(path, ".journal")
}

pub(crate) fn pending_path(path: &Path) -> PathBuf {
    sidecar_path(path, ".pending")
}

fn temp_path(path: &Path) -> PathBuf {
    sidecar_path(path, ".tmp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet))
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("banned_ips.json");
        let mut records = HashMap::new();
        records.insert(ip(9), BanRecord::new(ip(9), "test"));

        save_banned_ips(&path, &records).unwrap();
        let loaded = load_banned_ips(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&ip(9)).unwrap().reason, "test");
    }

    #[test]
    fn missing_state_file_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_banned_ips(dir.path().join("missing.json")).unwrap();

        assert!(loaded.is_empty());
    }

    #[test]
    fn journal_replays_bans_and_unbans_over_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_ips.json");
        let mut records = HashMap::new();
        records.insert(ip(1), BanRecord::new(ip(1), "snapshot"));
        save_banned_ips(&path, &records).unwrap();

        append_state_change(&path, &BanStateChange::Unban { ip: ip(1) }).unwrap();
        append_state_change(
            &path,
            &BanStateChange::Ban {
                record: BanRecord::new(ip(2), "journal"),
            },
        )
        .unwrap();

        let loaded = load_banned_ips(&path).unwrap();
        assert!(!loaded.contains_key(&ip(1)));
        assert_eq!(loaded.get(&ip(2)).unwrap().reason, "journal");
    }

    #[test]
    fn compact_writes_replayed_state_and_clears_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_ips.json");
        append_state_change(
            &path,
            &BanStateChange::Ban {
                record: BanRecord::new(ip(3), "journal"),
            },
        )
        .unwrap();
        let records = load_banned_ips(&path).unwrap();

        compact_banned_ips(&path, &records).unwrap();

        assert!(!journal_path(&path).exists());
        assert_eq!(load_banned_ips(&path).unwrap(), records);
    }

    #[test]
    fn load_repairs_a_torn_final_journal_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_ips.json");
        append_state_change(
            &path,
            &BanStateChange::Ban {
                record: BanRecord::new(ip(5), "complete"),
            },
        )
        .unwrap();
        let journal_path = journal_path(&path);
        let complete_len = fs::metadata(&journal_path).unwrap().len();
        let mut journal = OpenOptions::new().append(true).open(&journal_path).unwrap();
        journal.write_all(b"{\"action\":\"ban\"").unwrap();
        drop(journal);

        let loaded = load_banned_ips(&path).unwrap();

        assert!(loaded.contains_key(&ip(5)));
        assert_eq!(fs::metadata(journal_path).unwrap().len(), complete_len);
    }

    #[test]
    fn pending_change_round_trips_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_ips.json");
        let change = BanStateChange::Ban {
            record: BanRecord::new(ip(4), "pending"),
        };

        save_pending_change(&path, &change).unwrap();
        assert_eq!(load_pending_change(&path).unwrap(), Some(change));
        clear_pending_change(&path).unwrap();
        assert_eq!(load_pending_change(&path).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn state_files_are_owner_read_write_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("banned_ips.json");
        let record = BanRecord::new(ip(5), "permissions");
        let records = HashMap::from([(record.ip, record.clone())]);
        save_banned_ips(&path, &records).unwrap();
        append_state_change(
            &path,
            &BanStateChange::Ban {
                record: record.clone(),
            },
        )
        .unwrap();
        save_pending_change(&path, &BanStateChange::Ban { record }).unwrap();

        for state_path in [&path, &journal_path(&path), &pending_path(&path)] {
            let mode = fs::metadata(state_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "unexpected mode for {}", state_path.display());
        }
    }
}
