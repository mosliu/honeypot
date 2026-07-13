use crate::{config::WebdavConfig, store::BanRecord};
use anyhow::{Context, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    future::{Future, pending},
    io::Write,
    path::Path,
    process::Stdio,
    sync::Arc,
};
use tempfile::{Builder, NamedTempFile, TempPath};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::watch,
    time::{Duration, Instant, sleep_until, timeout},
};
use tracing::{debug, error, info, warn};

const MAX_CURL_STDERR_BYTES: u64 = 64 * 1024;
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(1);

pub type WebdavSnapshot = Arc<[BanRecord]>;
pub type WebdavSyncSender = watch::Sender<WebdavSnapshot>;
pub type WebdavSyncReceiver = watch::Receiver<WebdavSnapshot>;

pub fn sync_channel() -> (WebdavSyncSender, WebdavSyncReceiver) {
    watch::channel(Arc::<[BanRecord]>::from([]))
}

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
        ensure!(
            config.timeout_seconds > 0,
            "webdav.timeout_seconds must be greater than 0"
        );
        Ok(Self { config })
    }

    pub async fn upload_banned_ips(
        &self,
        records: WebdavSnapshot,
    ) -> anyhow::Result<WebdavUploadResult> {
        let prepare_config = self.config.clone();
        let prepared =
            tokio::task::spawn_blocking(move || prepare_upload(&prepare_config, records.as_ref()))
                .await
                .context("WebDAV upload preparation task failed")??;

        run_curl_put(&self.config, &prepared).await
    }
}

struct PreparedUpload {
    body_path: TempPath,
    curl_config_path: TempPath,
}

fn prepare_upload(config: &WebdavConfig, records: &[BanRecord]) -> anyhow::Result<PreparedUpload> {
    let payload = WebdavPayload::new(records.to_vec());
    let body = serde_json::to_vec_pretty(&payload).context("failed to serialize WebDAV payload")?;

    let mut body_file = secure_temp_file("honeypot-webdav-body-")?;
    body_file
        .write_all(&body)
        .context("failed to write WebDAV body file")?;
    body_file
        .flush()
        .context("failed to flush WebDAV body file")?;

    let mut config_file = secure_temp_file("honeypot-webdav-config-")?;
    let rendered = curl_config(config, body_file.path())?;
    config_file
        .write_all(rendered.as_bytes())
        .context("failed to write WebDAV curl config")?;
    config_file
        .flush()
        .context("failed to flush WebDAV curl config")?;

    Ok(PreparedUpload {
        body_path: body_file.into_temp_path(),
        curl_config_path: config_file.into_temp_path(),
    })
}

fn secure_temp_file(prefix: &str) -> anyhow::Result<NamedTempFile> {
    Builder::new()
        .prefix(prefix)
        .tempfile()
        .with_context(|| format!("failed to create secure temporary file with prefix {prefix}"))
}

async fn run_curl_put(
    config: &WebdavConfig,
    prepared: &PreparedUpload,
) -> anyhow::Result<WebdavUploadResult> {
    debug!(
        body_path = %prepared.body_path.display(),
        "starting WebDAV curl upload"
    );
    let mut child = Command::new(&config.curl_binary)
        .arg("--config")
        .arg(prepared.curl_config_path.as_os_str())
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {}", config.curl_binary))?;

    let stderr = child
        .stderr
        .take()
        .context("failed to capture curl stderr")?;
    let stderr_task = tokio::spawn(async move {
        let mut limited = stderr.take(MAX_CURL_STDERR_BYTES);
        let mut output = Vec::new();
        limited.read_to_end(&mut output).await.map(|_| output)
    });

    let hard_timeout = Duration::from_secs(config.timeout_seconds);
    let status = match timeout(hard_timeout, child.wait()).await {
        Ok(result) => result.context("failed to wait for curl WebDAV PUT")?,
        Err(_) => {
            let _ = child.start_kill();
            let _ = timeout(PROCESS_REAP_TIMEOUT, child.wait()).await;
            let _ = timeout(PROCESS_REAP_TIMEOUT, stderr_task).await;
            bail!(
                "curl WebDAV PUT exceeded hard timeout of {} seconds and was terminated",
                config.timeout_seconds
            );
        }
    };

    let stderr = match stderr_task.await {
        Ok(Ok(output)) => String::from_utf8_lossy(&output).trim().to_string(),
        Ok(Err(error)) => format!("failed to read curl stderr: {error}"),
        Err(error) => format!("failed to join curl stderr reader: {error}"),
    };

    if status.success() {
        return Ok(WebdavUploadResult {
            exit_code: status.code(),
        });
    }

    bail!(
        "curl WebDAV PUT failed; exit_code={:?}; stderr={}",
        status.code(),
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
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n");
    format!("\"{escaped}\"")
}

#[derive(Clone, Copy)]
struct SyncTiming {
    debounce: Duration,
    retry_initial: Duration,
    retry_max: Duration,
}

impl SyncTiming {
    fn from_config(config: &WebdavConfig) -> Self {
        Self {
            debounce: Duration::from_secs(config.debounce_seconds),
            retry_initial: Duration::from_secs(config.retry_initial_seconds),
            retry_max: Duration::from_secs(config.retry_max_seconds),
        }
    }
}

pub fn spawn_sync_worker(
    config: WebdavConfig,
    receiver: WebdavSyncReceiver,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_sync_worker_with_shutdown(config, receiver, None)
}

pub fn spawn_sync_worker_with_shutdown(
    config: WebdavConfig,
    receiver: WebdavSyncReceiver,
    shutdown: Option<watch::Receiver<bool>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return None;
    }

    Some(tokio::spawn(async move {
        let timing = SyncTiming::from_config(&config);
        let client = match WebdavClient::new(config) {
            Ok(client) => client,
            Err(error) => {
                error!(%error, "WebDAV sync worker disabled");
                return;
            }
        };

        run_sync_loop(receiver, shutdown, timing, move |snapshot| {
            let client = client.clone();
            async move { client.upload_banned_ips(snapshot).await }
        })
        .await;
    }))
}

async fn run_sync_loop<U, F>(
    mut receiver: WebdavSyncReceiver,
    mut shutdown: Option<watch::Receiver<bool>>,
    timing: SyncTiming,
    mut upload: U,
) where
    U: FnMut(WebdavSnapshot) -> F,
    F: Future<Output = anyhow::Result<WebdavUploadResult>>,
{
    'worker: loop {
        let changed = tokio::select! {
            changed = receiver.changed() => changed,
            _ = wait_for_shutdown(&mut shutdown) => break,
        };
        if changed.is_err() {
            break;
        }
        let mut latest = receiver.borrow_and_update().clone();

        'snapshot: loop {
            if !timing.debounce.is_zero() {
                let deadline = Instant::now() + timing.debounce;
                loop {
                    tokio::select! {
                        changed = receiver.changed() => {
                            if changed.is_err() {
                                break 'worker;
                            }
                            latest = receiver.borrow_and_update().clone();
                        }
                        _ = sleep_until(deadline) => break,
                        _ = wait_for_shutdown(&mut shutdown) => break 'worker,
                    }
                }
            }

            let mut retry_delay = timing.retry_initial;
            loop {
                let count = latest.len();
                let result = tokio::select! {
                    result = upload(latest.clone()) => Some(result),
                    changed = receiver.changed() => {
                        if changed.is_err() {
                            break 'worker;
                        }
                        latest = receiver.borrow_and_update().clone();
                        None
                    }
                    _ = wait_for_shutdown(&mut shutdown) => break 'worker,
                };

                let Some(result) = result else {
                    continue 'snapshot;
                };

                match result {
                    Ok(result) => {
                        info!(
                            exit_code = ?result.exit_code,
                            count,
                            "uploaded banned IP list to WebDAV"
                        );
                        debug!("WebDAV sync cycle finished");
                        continue 'worker;
                    }
                    Err(error) => warn!(
                        %error,
                        count,
                        retry_seconds = retry_delay.as_secs_f64(),
                        "failed to upload banned IP list to WebDAV; retry scheduled"
                    ),
                }

                let retry_at = Instant::now() + retry_delay;
                loop {
                    tokio::select! {
                        changed = receiver.changed() => {
                            if changed.is_err() {
                                break 'worker;
                            }
                            latest = receiver.borrow_and_update().clone();
                        }
                        _ = sleep_until(retry_at) => break,
                        _ = wait_for_shutdown(&mut shutdown) => break 'worker,
                    }
                }
                retry_delay = retry_delay.saturating_mul(2).min(timing.retry_max);
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut Option<watch::Receiver<bool>>) {
    let Some(shutdown) = shutdown else {
        pending::<()>().await;
        return;
    };

    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::sync::Notify;

    fn record(last_octet: u8) -> BanRecord {
        BanRecord::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), "test")
    }

    fn snapshot(last_octet: u8) -> WebdavSnapshot {
        Arc::from(vec![record(last_octet)])
    }

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
    fn curl_config_quotes_url_auth_and_line_breaks() {
        let config = WebdavConfig {
            enabled: true,
            url: "https://example.com/path with space/banned.json".to_string(),
            username: Some("user".to_string()),
            password: Some("pass\nword".to_string()),
            ..WebdavConfig::default()
        };

        let rendered = curl_config(&config, Path::new("/tmp/body.json")).unwrap();

        assert!(rendered.contains("request = \"PUT\""));
        assert!(rendered.contains("url = \"https://example.com/path with space/banned.json\""));
        assert!(rendered.contains("user = \"user:pass\\nword\""));
        assert!(rendered.contains("data-binary = \"@/tmp/body.json\""));
        assert!(!rendered.contains("pass\nword"));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_upload_files_are_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let config = WebdavConfig {
            enabled: true,
            url: "https://example.com/banned.json".to_string(),
            ..WebdavConfig::default()
        };
        let prepared = prepare_upload(&config, &[record(1)]).unwrap();
        let body_path = prepared.body_path.to_path_buf();
        let config_path = prepared.curl_config_path.to_path_buf();

        assert_eq!(
            std::fs::metadata(&body_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&config_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        drop(prepared);
        assert!(!body_path.exists());
        assert!(!config_path.exists());
    }

    #[tokio::test]
    async fn sync_worker_coalesces_to_latest_snapshot() {
        let (sender, receiver) = sync_channel();
        let uploads = Arc::new(Mutex::new(Vec::new()));
        let uploaded = Arc::new(Notify::new());
        let timing = SyncTiming {
            debounce: Duration::from_millis(30),
            retry_initial: Duration::from_millis(10),
            retry_max: Duration::from_millis(20),
        };
        let uploads_for_worker = Arc::clone(&uploads);
        let uploaded_for_worker = Arc::clone(&uploaded);
        let worker = tokio::spawn(run_sync_loop(receiver, None, timing, move |snapshot| {
            let uploads = Arc::clone(&uploads_for_worker);
            let uploaded = Arc::clone(&uploaded_for_worker);
            async move {
                uploads.lock().unwrap().push(snapshot[0].ip);
                uploaded.notify_one();
                Ok(WebdavUploadResult { exit_code: Some(0) })
            }
        }));

        sender.send_replace(snapshot(1));
        tokio::time::sleep(Duration::from_millis(5)).await;
        sender.send_replace(snapshot(2));
        timeout(Duration::from_secs(1), uploaded.notified())
            .await
            .unwrap();

        assert_eq!(
            uploads.lock().unwrap().as_slice(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))]
        );
        drop(sender);
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn sync_worker_retries_failures_with_latest_snapshot() {
        let (sender, receiver) = sync_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let successful_ip = Arc::new(Mutex::new(None));
        let uploaded = Arc::new(Notify::new());
        let timing = SyncTiming {
            debounce: Duration::ZERO,
            retry_initial: Duration::from_millis(30),
            retry_max: Duration::from_millis(60),
        };
        let attempts_for_worker = Arc::clone(&attempts);
        let successful_ip_for_worker = Arc::clone(&successful_ip);
        let uploaded_for_worker = Arc::clone(&uploaded);
        let worker = tokio::spawn(run_sync_loop(receiver, None, timing, move |snapshot| {
            let attempts = Arc::clone(&attempts_for_worker);
            let successful_ip = Arc::clone(&successful_ip_for_worker);
            let uploaded = Arc::clone(&uploaded_for_worker);
            async move {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    bail!("temporary failure");
                }
                *successful_ip.lock().unwrap() = Some(snapshot[0].ip);
                uploaded.notify_one();
                Ok(WebdavUploadResult { exit_code: Some(0) })
            }
        }));

        sender.send_replace(snapshot(1));
        tokio::time::sleep(Duration::from_millis(5)).await;
        sender.send_replace(snapshot(2));
        timeout(Duration::from_secs(1), uploaded.notified())
            .await
            .unwrap();

        assert!(attempts.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            *successful_ip.lock().unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)))
        );
        drop(sender);
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn optional_shutdown_stops_sync_worker() {
        let (_sender, receiver) = sync_channel();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let worker = tokio::spawn(run_sync_loop(
            receiver,
            Some(shutdown_receiver),
            SyncTiming {
                debounce: Duration::ZERO,
                retry_initial: Duration::from_millis(10),
                retry_max: Duration::from_millis(20),
            },
            |_snapshot| async { Ok(WebdavUploadResult { exit_code: Some(0) }) },
        ));

        shutdown_sender.send(true).unwrap();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn curl_process_is_killed_after_hard_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let fake_curl = dir.path().join("fake-curl");
        std::fs::write(&fake_curl, "#!/bin/sh\nexec sleep 60\n").unwrap();
        let mut permissions = std::fs::metadata(&fake_curl).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&fake_curl, permissions).unwrap();

        let config = WebdavConfig {
            enabled: true,
            url: "https://example.com/banned.json".to_string(),
            curl_binary: fake_curl.to_string_lossy().to_string(),
            timeout_seconds: 1,
            ..WebdavConfig::default()
        };
        let client = WebdavClient::new(config).unwrap();
        let error = client
            .upload_banned_ips(snapshot(1))
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("hard timeout"));
    }
}
