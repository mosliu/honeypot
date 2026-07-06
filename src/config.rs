use crate::allowlist::AllowlistEntry;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AppConfig {
    pub honeypot: HoneypotConfig,
    pub admin: AdminConfig,
    pub firewall: FirewallConfig,
    pub state: StateConfig,
    pub webdav: WebdavConfig,
    pub logging: LoggingConfig,
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.honeypot.max_visits > 0,
            "honeypot.max_visits must be greater than 0"
        );
        ensure!(
            self.honeypot.window_seconds > 0,
            "honeypot.window_seconds must be greater than 0"
        );
        ensure!(
            self.honeypot.max_tracked_ips > 0,
            "honeypot.max_tracked_ips must be greater than 0"
        );
        ensure!(
            !self.admin.password.trim().is_empty(),
            "admin.password must not be empty"
        );
        if self.admin.inline_on_honeypot_port {
            ensure!(
                self.admin.inline_path_prefix.starts_with('/'),
                "admin.inline_path_prefix must start with /"
            );
            ensure!(
                !self.admin.inline_path_prefix.contains(char::is_whitespace),
                "admin.inline_path_prefix must not contain whitespace"
            );
            ensure!(
                self.admin.inline_probe_timeout_ms > 0,
                "admin.inline_probe_timeout_ms must be greater than 0"
            );
        }
        ensure!(
            self.logging.retention_files > 0,
            "logging.retention_files must be greater than 0"
        );
        ensure!(
            self.firewall.ipset_hash_size > 0,
            "firewall.ipset_hash_size must be greater than 0"
        );
        ensure!(
            self.firewall.ipset_max_elements > 0,
            "firewall.ipset_max_elements must be greater than 0"
        );
        if self.webdav.enabled {
            ensure!(!self.webdav.url.trim().is_empty(), "webdav.url must be set");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct HoneypotConfig {
    pub listen_addr: String,
    pub max_visits: usize,
    pub window_seconds: u64,
    pub max_tracked_ips: usize,
    pub allowlist: Vec<AllowlistEntry>,
    pub banner: String,
    pub read_after_banner_timeout_ms: u64,
    pub close_delay_ms: u64,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:2222".to_string(),
            max_visits: 5,
            window_seconds: 60,
            max_tracked_ips: 100_000,
            allowlist: vec![
                "127.0.0.1".parse().expect("valid loopback IP"),
                "::1".parse().expect("valid loopback IP"),
            ],
            banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n".to_string(),
            read_after_banner_timeout_ms: 1500,
            close_delay_ms: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AdminConfig {
    pub listen_addr: String,
    pub password: String,
    pub inline_on_honeypot_port: bool,
    pub inline_path_prefix: String,
    pub inline_probe_timeout_ms: u64,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            password: "change-me".to_string(),
            inline_on_honeypot_port: false,
            inline_path_prefix: "/_honeypot_admin".to_string(),
            inline_probe_timeout_ms: 250,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    Ufw,
    Iptables,
    #[default]
    IptablesIpset,
    DryRun,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FirewallConfig {
    pub backend: FirewallBackend,
    pub ufw_binary: String,
    pub iptables_binary: String,
    pub ip6tables_binary: String,
    pub ipset_binary: String,
    pub chain: String,
    pub rule_position: u16,
    pub ipset_name_v4: String,
    pub ipset_name_v6: String,
    pub ipset_hash_size: u32,
    pub ipset_max_elements: u32,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::IptablesIpset,
            ufw_binary: "ufw".to_string(),
            iptables_binary: "iptables".to_string(),
            ip6tables_binary: "ip6tables".to_string(),
            ipset_binary: "ipset".to_string(),
            chain: "INPUT".to_string(),
            rule_position: 1,
            ipset_name_v4: "honeypot_banned_v4".to_string(),
            ipset_name_v6: "honeypot_banned_v6".to_string(),
            ipset_hash_size: 4096,
            ipset_max_elements: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct StateConfig {
    pub banned_ips_path: String,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            banned_ips_path: "state/banned_ips.json".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct WebdavConfig {
    pub enabled: bool,
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub curl_binary: String,
    pub timeout_seconds: u64,
    pub debounce_seconds: u64,
}

impl Default for WebdavConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            username: None,
            password: None,
            curl_binary: "curl".to_string(),
            timeout_seconds: 15,
            debounce_seconds: 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub directory: String,
    pub file_prefix: String,
    pub level: String,
    pub retention_files: usize,
    pub retention_days: u64,
    pub stdout: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: "logs".to_string(),
            file_prefix: "honeypot".to_string(),
            level: "info".to_string(),
            retention_files: 7,
            retention_days: 14,
            stdout: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_ip_and_cidr_allowlist_entries() {
        let config: AppConfig = toml::from_str(
            r#"
            [honeypot]
            allowlist = ["127.0.0.1", "172.23.16.0/24"]

            [admin]
            password = "secret"
            "#,
        )
        .unwrap();

        assert_eq!(config.honeypot.allowlist.len(), 2);
        assert!(config.honeypot.allowlist[1].contains("172.23.16.9".parse().unwrap()));
    }
}
