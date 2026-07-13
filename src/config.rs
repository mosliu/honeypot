use crate::allowlist::AllowlistEntry;
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path};
use tracing_subscriber::EnvFilter;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
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
        let honeypot_addr = parse_socket_addr("honeypot.listen_addr", &self.honeypot.listen_addr)?;
        let admin_addr = parse_socket_addr("admin.listen_addr", &self.admin.listen_addr)?;
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
            self.honeypot.max_concurrent_connections > 0,
            "honeypot.max_concurrent_connections must be greater than 0"
        );
        ensure!(
            self.honeypot.ban_queue_capacity > 0,
            "honeypot.ban_queue_capacity must be greater than 0"
        );
        ensure!(
            !self.admin.password.trim().is_empty(),
            "admin.password must be explicitly configured"
        );
        ensure!(
            self.admin.password.trim().chars().count() >= 16,
            "admin.password must contain at least 16 characters"
        );
        ensure!(
            !is_placeholder_password(&self.admin.password),
            "admin.password must not use a documented placeholder value"
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
            ensure!(
                self.admin.inline_request_timeout_ms > 0,
                "admin.inline_request_timeout_ms must be greater than 0"
            );
            ensure!(
                self.admin.inline_probe_timeout_ms <= self.admin.inline_request_timeout_ms,
                "admin.inline_probe_timeout_ms must not exceed admin.inline_request_timeout_ms"
            );
            ensure!(
                self.admin.inline_max_request_bytes > 0,
                "admin.inline_max_request_bytes must be greater than 0"
            );
            ensure!(
                !self
                    .admin
                    .inline_path_prefix
                    .trim_end_matches('/')
                    .is_empty(),
                "admin.inline_path_prefix must not be the root path"
            );
            ensure!(
                !self.admin.inline_path_prefix.contains('?')
                    && !self.admin.inline_path_prefix.contains('#'),
                "admin.inline_path_prefix must not contain a query or fragment delimiter"
            );
        }
        let effective_admin_addr = if self.admin.inline_on_honeypot_port {
            honeypot_addr
        } else {
            admin_addr
        };
        ensure!(
            effective_admin_addr.ip().is_loopback() || self.admin.allow_insecure_http,
            "remote plaintext admin access requires admin.allow_insecure_http = true"
        );
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
        ensure!(
            self.firewall.command_timeout_seconds > 0,
            "firewall.command_timeout_seconds must be greater than 0"
        );
        if self.firewall.backend == FirewallBackend::Nftables {
            ensure!(
                !self.firewall.nft_table.trim().is_empty(),
                "firewall.nft_table must not be empty"
            );
            ensure!(
                !self.firewall.nft_chain.trim().is_empty(),
                "firewall.nft_chain must not be empty"
            );
            ensure!(
                !self.firewall.nft_hook.trim().is_empty(),
                "firewall.nft_hook must not be empty"
            );
            ensure!(
                !self.firewall.nft_set_name_v4.trim().is_empty(),
                "firewall.nft_set_name_v4 must not be empty"
            );
            ensure!(
                !self.firewall.nft_set_name_v6.trim().is_empty(),
                "firewall.nft_set_name_v6 must not be empty"
            );
        }
        if self.webdav.enabled {
            ensure!(!self.webdav.url.trim().is_empty(), "webdav.url must be set");
            ensure!(
                self.webdav.timeout_seconds > 0,
                "webdav.timeout_seconds must be greater than 0"
            );
            ensure!(
                self.webdav.retry_initial_seconds > 0,
                "webdav.retry_initial_seconds must be greater than 0"
            );
            ensure!(
                self.webdav.retry_max_seconds >= self.webdav.retry_initial_seconds,
                "webdav.retry_max_seconds must be at least webdav.retry_initial_seconds"
            );
            ensure!(
                self.webdav.url.starts_with("https://")
                    || (self.webdav.allow_insecure_http && self.webdav.url.starts_with("http://")),
                "webdav.url must use https:// unless webdav.allow_insecure_http = true"
            );
            ensure!(
                self.webdav.username.is_some() == self.webdav.password.is_some(),
                "webdav.username and webdav.password must be configured together"
            );
            if let Some(password) = self.webdav.password.as_deref() {
                ensure!(
                    !password.is_empty() && password != "webdav-password",
                    "webdav.password must not be empty or use the example value"
                );
            }
            ensure!(
                !contains_crlf(&self.webdav.url)
                    && self
                        .webdav
                        .username
                        .as_deref()
                        .is_none_or(|value| !contains_crlf(value))
                    && self
                        .webdav
                        .password
                        .as_deref()
                        .is_none_or(|value| !contains_crlf(value)),
                "WebDAV values must not contain CR or LF characters"
            );
        }
        ensure!(
            !self.state.banned_ips_path.trim().is_empty(),
            "state.banned_ips_path must not be empty"
        );
        ensure!(
            !self.logging.directory.trim().is_empty(),
            "logging.directory must not be empty"
        );
        ensure!(
            !self.logging.file_prefix.trim().is_empty(),
            "logging.file_prefix must not be empty"
        );
        EnvFilter::try_new(&self.logging.level)
            .context("logging.level must be a valid tracing filter")?;
        Ok(())
    }
}

fn parse_socket_addr(field: &str, value: &str) -> anyhow::Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("{field} must be a numeric socket address"))
}

fn is_placeholder_password(password: &str) -> bool {
    matches!(
        password.trim().to_ascii_lowercase().as_str(),
        "change-me"
            | "replace-with-a-long-random-password"
            | "configured-password"
            | "your-password"
            | "password"
            | "admin"
    )
}

fn contains_crlf(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HoneypotConfig {
    pub listen_addr: String,
    pub max_visits: usize,
    pub window_seconds: u64,
    pub max_tracked_ips: usize,
    pub max_concurrent_connections: usize,
    pub ban_queue_capacity: usize,
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
            max_concurrent_connections: 1024,
            ban_queue_capacity: 4096,
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
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub listen_addr: String,
    pub password: String,
    pub inline_on_honeypot_port: bool,
    pub inline_path_prefix: String,
    pub inline_probe_timeout_ms: u64,
    pub inline_request_timeout_ms: u64,
    pub inline_max_request_bytes: usize,
    pub allow_insecure_http: bool,
    pub allow_legacy_get_password: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            password: String::new(),
            inline_on_honeypot_port: false,
            inline_path_prefix: "/_honeypot_admin".to_string(),
            inline_probe_timeout_ms: 250,
            inline_request_timeout_ms: 3_000,
            inline_max_request_bytes: 16 * 1024,
            allow_insecure_http: false,
            allow_legacy_get_password: false,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    #[default]
    Nftables,
    Ufw,
    Iptables,
    IptablesIpset,
    DryRun,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub backend: FirewallBackend,
    pub nft_binary: String,
    pub nft_table: String,
    pub nft_chain: String,
    pub nft_hook: String,
    pub nft_priority: String,
    pub nft_set_name_v4: String,
    pub nft_set_name_v6: String,
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
    pub command_timeout_seconds: u64,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Nftables,
            nft_binary: "nft".to_string(),
            nft_table: "honeypot".to_string(),
            nft_chain: "input".to_string(),
            nft_hook: "input".to_string(),
            nft_priority: "filter".to_string(),
            nft_set_name_v4: "banned_v4".to_string(),
            nft_set_name_v6: "banned_v6".to_string(),
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
            command_timeout_seconds: 15,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct WebdavConfig {
    pub enabled: bool,
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub curl_binary: String,
    pub timeout_seconds: u64,
    pub debounce_seconds: u64,
    pub retry_initial_seconds: u64,
    pub retry_max_seconds: u64,
    pub allow_insecure_http: bool,
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
            retry_initial_seconds: 5,
            retry_max_seconds: 300,
            allow_insecure_http: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
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

    fn valid_config() -> AppConfig {
        let mut config = AppConfig::default();
        config.admin.password = "correct horse battery staple".to_string();
        config
    }

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

    #[test]
    fn rejects_unknown_nested_configuration_fields() {
        let error = toml::from_str::<AppConfig>(
            r#"
            [admin]
            password = "correct horse battery staple"
            passwrod = "typo"
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field"));
        assert!(error.to_string().contains("passwrod"));
    }

    #[test]
    fn rejects_missing_short_and_placeholder_admin_passwords() {
        let mut config = AppConfig::default();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("explicitly")
        );

        config.admin.password = "too-short".to_string();
        assert!(config.validate().unwrap_err().to_string().contains("16"));

        config.admin.password = "replace-with-a-long-random-password".to_string();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("placeholder")
        );
    }

    #[test]
    fn remote_plaintext_admin_requires_explicit_opt_in() {
        let mut config = valid_config();
        config.admin.listen_addr = "0.0.0.0:8080".to_string();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("plaintext")
        );

        config.admin.allow_insecure_http = true;
        config.validate().unwrap();
    }

    #[test]
    fn validates_connection_and_inline_resource_limits() {
        let mut config = valid_config();
        config.honeypot.max_concurrent_connections = 0;
        assert!(config.validate().is_err());

        config.honeypot.max_concurrent_connections = 10;
        config.admin.inline_on_honeypot_port = true;
        config.admin.allow_insecure_http = true;
        config.admin.inline_probe_timeout_ms = 500;
        config.admin.inline_request_timeout_ms = 100;
        assert!(config.validate().is_err());

        config.admin.inline_request_timeout_ms = 500;
        config.admin.inline_path_prefix = "/".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn webdav_requires_bounded_secure_configuration() {
        let mut config = valid_config();
        config.webdav.enabled = true;
        config.webdav.url = "http://example.com/banned.json".to_string();
        config.webdav.timeout_seconds = 0;
        assert!(config.validate().is_err());

        config.webdav.timeout_seconds = 15;
        assert!(config.validate().is_err());

        config.webdav.allow_insecure_http = true;
        config.webdav.username = Some("user".to_string());
        assert!(config.validate().is_err());

        config.webdav.password = Some("non-placeholder-secret".to_string());
        config.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_logging_filter() {
        let mut config = valid_config();
        config.logging.level = "[not a filter".to_string();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("logging.level")
        );
    }

    #[test]
    fn distributed_templates_parse_but_require_a_real_password() {
        for (name, raw) in [
            (
                "config.example.toml",
                include_str!("../config.example.toml"),
            ),
            (
                "packaging/config.toml",
                include_str!("../packaging/config.toml"),
            ),
        ] {
            let config: AppConfig =
                toml::from_str(raw).unwrap_or_else(|error| panic!("{name} did not parse: {error}"));
            let error = match config.validate() {
                Ok(()) => panic!("{name} unexpectedly passed validation"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("placeholder"),
                "unexpected validation error for {name}: {error:#}"
            );
        }
    }

    #[test]
    fn load_accepts_a_valid_configuration_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = valid_config();
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();

        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded.admin.password, config.admin.password);
        assert_eq!(loaded.honeypot.listen_addr, config.honeypot.listen_addr);
    }
}
