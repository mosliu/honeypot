use crate::{config::WebdavConfig, store::BanRecord};
use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebdavPayload {
    pub updated_at: DateTime<Utc>,
    pub banned_count: usize,
    pub ips: Vec<BanRecord>,
}

impl WebdavPayload {
    pub fn new(mut records: Vec<BanRecord>) -> Self {
        records.sort_by_key(|record| record.ip);
        Self {
            updated_at: Utc::now(),
            banned_count: records.len(),
            ips: records,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebdavUploadResult {
    pub exit_code: Option<i32>,
}

#[derive(Clone)]
pub struct WebdavClient {
    config: WebdavConfig,
}

impl WebdavClient {
    pub fn new(config: WebdavConfig) -> anyhow::Result<Self> {
        Ok(Self { config })
    }

    pub async fn upload_banned_ips(
        &self,
        records: Vec<BanRecord>,
    ) -> anyhow::Result<WebdavUploadResult> {
        let payload = WebdavPayload::new(records);
        let body =
            serde_json::to_vec_pretty(&payload).context("failed to serialize WebDAV payload")?;
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || run_curl_put(&config, &body)).await?
    }
}

fn run_curl_put(config: &WebdavConfig, body: &[u8]) -> anyhow::Result<WebdavUploadResult> {
    let temp_dir = std::env::temp_dir();
    let suffix = unique_suffix();
    let body_path = temp_dir.join(format!("honeypot-webdav-{suffix}.json"));
    let curl_config_path = temp_dir.join(format!("honeypot-webdav-{suffix}.curl"));
    let cleanup = CleanupFiles::new(vec![body_path.clone(), curl_config_path.clone()]);

    fs::write(&body_path, body)
        .with_context(|| format!("failed to write WebDAV body file {}", body_path.display()))?;
    fs::write(&curl_config_path, curl_config(config, &body_path)?).with_context(|| {
        format!(
            "failed to write WebDAV curl config {}",
            curl_config_path.display()
        )
    })?;

    let output = Command::new(&config.curl_binary)
        .arg("--config")
        .arg(&curl_config_path)
        .output()
        .with_context(|| format!("failed to execute {}", config.curl_binary))?;
    drop(cleanup);

    if output.status.success() {
        return Ok(WebdavUploadResult {
            exit_code: output.status.code(),
        });
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    bail!(
        "curl WebDAV PUT failed; exit_code={:?}; stdout={}; stderr={}",
        output.status.code(),
        stdout,
        stderr
    )
}

fn curl_config(config: &WebdavConfig, body_path: &Path) -> anyhow::Result<String> {
    let body = body_path
        .to_str()
        .context("temporary WebDAV body path is not valid UTF-8")?;
    let mut lines = vec![
        "fail".to_string(),
        "silent".to_string(),
        "show-error".to_string(),
        "request = \"PUT\"".to_string(),
        format!("url = {}", curl_quote(&config.url)),
        "header = \"content-type: application/json\"".to_string(),
        format!("connect-timeout = {}", config.timeout_seconds),
        format!("max-time = {}", config.timeout_seconds),
        format!("data-binary = {}", curl_quote(&format!("@{body}"))),
    ];

    if let Some(username) = config.username.as_deref() {
        let password = config.password.as_deref().unwrap_or_default();
        lines.push(format!(
            "user = {}",
            curl_quote(&format!("{username}:{password}"))
        ));
    }

    Ok(lines.join("\n"))
}

fn curl_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

struct CleanupFiles {
    paths: Vec<PathBuf>,
}

impl CleanupFiles {
    fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }
}

impl Drop for CleanupFiles {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn spawn_sync_worker(
    config: WebdavConfig,
    mut receiver: mpsc::Receiver<Vec<BanRecord>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return None;
    }

    Some(tokio::spawn(async move {
        let debounce = Duration::from_secs(config.debounce_seconds);
        let client = match WebdavClient::new(config) {
            Ok(client) => client,
            Err(error) => {
                error!(%error, "WebDAV sync worker disabled");
                return;
            }
        };

        while let Some(snapshot) = receiver.recv().await {
            let mut latest = snapshot;
            sleep(debounce).await;
            while let Ok(next) = receiver.try_recv() {
                latest = next;
            }

            let count = latest.len();
            match client.upload_banned_ips(latest).await {
                Ok(result) => info!(
                    exit_code = ?result.exit_code,
                    count,
                    "uploaded banned IP list to WebDAV"
                ),
                Err(error) => warn!(%error, count, "failed to upload banned IP list to WebDAV"),
            }
            debug!("WebDAV sync cycle finished");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn payload_sorts_ips_and_counts_records() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let payload = WebdavPayload::new(vec![
            BanRecord::new(ip_b, "test"),
            BanRecord::new(ip_a, "test"),
        ]);

        assert_eq!(payload.banned_count, 2);
        assert_eq!(payload.ips[0].ip, ip_a);
        assert_eq!(payload.ips[1].ip, ip_b);
    }

    #[test]
    fn curl_config_quotes_url_and_auth() {
        let config = WebdavConfig {
            enabled: true,
            url: "https://example.com/path with space/banned.json".to_string(),
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            ..WebdavConfig::default()
        };

        let rendered = curl_config(&config, Path::new("/tmp/body.json")).unwrap();

        assert!(rendered.contains("request = \"PUT\""));
        assert!(rendered.contains("url = \"https://example.com/path with space/banned.json\""));
        assert!(rendered.contains("user = \"user:pass\""));
        assert!(rendered.contains("data-binary = \"@/tmp/body.json\""));
    }
}
