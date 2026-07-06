use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
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

pub fn load_banned_ips(path: impl AsRef<Path>) -> anyhow::Result<HashMap<IpAddr, BanRecord>> {
    let path = path.as_ref();
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

pub fn save_banned_ips(
    path: impl AsRef<Path>,
    records: &HashMap<IpAddr, BanRecord>,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state directory {}", parent.display()))?;
    }

    let file = BannedIpsFile::from_records(records);
    let json =
        serde_json::to_string_pretty(&file).context("failed to serialize banned IP state")?;
    let temp_path = temp_state_path(path);
    fs::write(&temp_path, json)
        .with_context(|| format!("failed to write temporary state {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to replace state file {} with {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn temp_state_path(path: &Path) -> PathBuf {
    let mut temp_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("banned_ips.json")
        .to_string();
    temp_name.push_str(".tmp");
    path.with_file_name(temp_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("banned_ips.json");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let mut records = HashMap::new();
        records.insert(ip, BanRecord::new(ip, "test"));

        save_banned_ips(&path, &records).unwrap();
        let loaded = load_banned_ips(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&ip).unwrap().reason, "test");
    }

    #[test]
    fn missing_state_file_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_banned_ips(dir.path().join("missing.json")).unwrap();

        assert!(loaded.is_empty());
    }
}
