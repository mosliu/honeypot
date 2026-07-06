use crate::config::{FirewallBackend, FirewallConfig};
use anyhow::{Context, bail};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
};
use tracing::{debug, info, warn};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub success: bool,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &CommandSpec) -> anyhow::Result<CommandResult>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CommandSpec) -> anyhow::Result<CommandResult> {
        debug!(
            program = command.program,
            args = ?command.args,
            "running firewall command"
        );
        let output = Command::new(&command.program)
            .args(&command.args)
            .output()
            .with_context(|| format!("failed to execute {}", command.program))?;
        Ok(CommandResult {
            success: output.status.success(),
            status_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

pub trait Firewall: Send + Sync {
    fn setup(&self) -> anyhow::Result<()>;
    fn ban(&self, ip: IpAddr) -> anyhow::Result<()>;
    fn unban(&self, ip: IpAddr) -> anyhow::Result<()>;
}

pub struct SystemFirewall<R> {
    config: FirewallConfig,
    runner: R,
}

impl<R> SystemFirewall<R> {
    pub fn new(config: FirewallConfig, runner: R) -> Self {
        Self { config, runner }
    }
}

impl<R: CommandRunner> Firewall for SystemFirewall<R> {
    fn setup(&self) -> anyhow::Result<()> {
        for command in self.setup_commands() {
            self.run_required(&command)?;
        }
        if self.config.backend == FirewallBackend::IptablesIpset {
            self.ensure_ipset_rule(false)?;
            self.ensure_ipset_rule(true)?;
        }
        Ok(())
    }

    fn ban(&self, ip: IpAddr) -> anyhow::Result<()> {
        match self.config.backend {
            FirewallBackend::Ufw => self.run_required(&ufw_ban_command(&self.config, ip)),
            FirewallBackend::Iptables => self.ensure_iptables_drop(ip),
            FirewallBackend::IptablesIpset => {
                self.run_required(&ipset_add_command(&self.config, ip))
            }
            FirewallBackend::DryRun => {
                info!(%ip, "dry-run firewall ban");
                Ok(())
            }
        }
    }

    fn unban(&self, ip: IpAddr) -> anyhow::Result<()> {
        match self.config.backend {
            FirewallBackend::Ufw => self.run_required(&ufw_unban_command(&self.config, ip)),
            FirewallBackend::Iptables => {
                self.run_required(&iptables_unban_command(&self.config, ip))
            }
            FirewallBackend::IptablesIpset => {
                self.run_required(&ipset_delete_command(&self.config, ip))
            }
            FirewallBackend::DryRun => {
                info!(%ip, "dry-run firewall unban");
                Ok(())
            }
        }
    }
}

impl<R: CommandRunner> SystemFirewall<R> {
    pub fn setup_commands(&self) -> Vec<CommandSpec> {
        match self.config.backend {
            FirewallBackend::IptablesIpset => ipset_setup_commands(&self.config),
            _ => Vec::new(),
        }
    }

    fn ensure_ipset_rule(&self, ipv6: bool) -> anyhow::Result<()> {
        let check = ipset_rule_check_command(&self.config, ipv6);
        let check_result = self.runner.run(&check)?;
        if check_result.success {
            return Ok(());
        }

        let insert = ipset_rule_insert_command(&self.config, ipv6);
        self.run_required(&insert)
    }

    fn ensure_iptables_drop(&self, ip: IpAddr) -> anyhow::Result<()> {
        let check = iptables_check_command(&self.config, ip);
        let check_result = self.runner.run(&check)?;
        if check_result.success {
            return Ok(());
        }

        self.run_required(&iptables_ban_command(&self.config, ip))
    }

    fn run_required(&self, command: &CommandSpec) -> anyhow::Result<()> {
        let result = self.runner.run(command)?;
        if result.success {
            return Ok(());
        }

        bail!(
            "command failed: {} {}; status={:?}; stderr={}",
            command.program,
            command.args.join(" "),
            result.status_code,
            result.stderr
        );
    }
}

pub fn planned_ban_commands(config: &FirewallConfig, ip: IpAddr) -> Vec<CommandSpec> {
    match config.backend {
        FirewallBackend::Ufw => vec![ufw_ban_command(config, ip)],
        FirewallBackend::Iptables => vec![
            iptables_check_command(config, ip),
            iptables_ban_command(config, ip),
        ],
        FirewallBackend::IptablesIpset => vec![ipset_add_command(config, ip)],
        FirewallBackend::DryRun => Vec::new(),
    }
}

pub fn planned_unban_commands(config: &FirewallConfig, ip: IpAddr) -> Vec<CommandSpec> {
    match config.backend {
        FirewallBackend::Ufw => vec![ufw_unban_command(config, ip)],
        FirewallBackend::Iptables => vec![iptables_unban_command(config, ip)],
        FirewallBackend::IptablesIpset => vec![ipset_delete_command(config, ip)],
        FirewallBackend::DryRun => Vec::new(),
    }
}

pub fn ipset_setup_commands(config: &FirewallConfig) -> Vec<CommandSpec> {
    vec![
        CommandSpec::new(
            &config.ipset_binary,
            [
                "create",
                &config.ipset_name_v4,
                "hash:ip",
                "family",
                "inet",
                "hashsize",
                &config.ipset_hash_size.to_string(),
                "maxelem",
                &config.ipset_max_elements.to_string(),
                "-exist",
            ],
        ),
        CommandSpec::new(
            &config.ipset_binary,
            [
                "create",
                &config.ipset_name_v6,
                "hash:ip",
                "family",
                "inet6",
                "hashsize",
                &config.ipset_hash_size.to_string(),
                "maxelem",
                &config.ipset_max_elements.to_string(),
                "-exist",
            ],
        ),
    ]
}

fn ufw_ban_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        &config.ufw_binary,
        ["prepend", "deny", "from", &ip.to_string()],
    )
}

fn ufw_unban_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        &config.ufw_binary,
        ["delete", "deny", "from", &ip.to_string()],
    )
}

fn iptables_program(config: &FirewallConfig, ip: IpAddr) -> &str {
    match ip {
        IpAddr::V4(_) => &config.iptables_binary,
        IpAddr::V6(_) => &config.ip6tables_binary,
    }
}

fn iptables_check_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        iptables_program(config, ip),
        ["-C", &config.chain, "-s", &ip.to_string(), "-j", "DROP"],
    )
}

fn iptables_ban_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        iptables_program(config, ip),
        [
            "-I",
            &config.chain,
            &config.rule_position.to_string(),
            "-s",
            &ip.to_string(),
            "-j",
            "DROP",
        ],
    )
}

fn iptables_unban_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        iptables_program(config, ip),
        ["-D", &config.chain, "-s", &ip.to_string(), "-j", "DROP"],
    )
}

fn ipset_name_for(config: &FirewallConfig, ip: IpAddr) -> &str {
    match ip {
        IpAddr::V4(_) => &config.ipset_name_v4,
        IpAddr::V6(_) => &config.ipset_name_v6,
    }
}

fn ipset_add_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        &config.ipset_binary,
        ["add", ipset_name_for(config, ip), &ip.to_string(), "-exist"],
    )
}

fn ipset_delete_command(config: &FirewallConfig, ip: IpAddr) -> CommandSpec {
    CommandSpec::new(
        &config.ipset_binary,
        ["del", ipset_name_for(config, ip), &ip.to_string(), "-exist"],
    )
}

fn ipset_rule_check_command(config: &FirewallConfig, ipv6: bool) -> CommandSpec {
    let binary = if ipv6 {
        &config.ip6tables_binary
    } else {
        &config.iptables_binary
    };
    let set_name = if ipv6 {
        &config.ipset_name_v6
    } else {
        &config.ipset_name_v4
    };

    CommandSpec::new(
        binary,
        [
            "-C",
            &config.chain,
            "-m",
            "set",
            "--match-set",
            set_name,
            "src",
            "-j",
            "DROP",
        ],
    )
}

fn ipset_rule_insert_command(config: &FirewallConfig, ipv6: bool) -> CommandSpec {
    let binary = if ipv6 {
        &config.ip6tables_binary
    } else {
        &config.iptables_binary
    };
    let set_name = if ipv6 {
        &config.ipset_name_v6
    } else {
        &config.ipset_name_v4
    };

    CommandSpec::new(
        binary,
        [
            "-I",
            &config.chain,
            &config.rule_position.to_string(),
            "-m",
            "set",
            "--match-set",
            set_name,
            "src",
            "-j",
            "DROP",
        ],
    )
}

pub fn backend_scaling_note(backend: &FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::IptablesIpset => {
            "one iptables rule plus O(1)-style ipset membership checks; recommended for many IPs"
        }
        FirewallBackend::Iptables => {
            "one iptables rule per banned IP; simple but rule traversal grows with list size"
        }
        FirewallBackend::Ufw => {
            "one ufw rule per banned IP; convenient but not ideal for large lists"
        }
        FirewallBackend::DryRun => "no firewall changes; for local testing only",
    }
}

pub fn log_firewall_backend(config: &FirewallConfig) {
    info!(
        backend = ?config.backend,
        scaling = backend_scaling_note(&config.backend),
        "firewall backend selected"
    );
    if matches!(
        config.backend,
        FirewallBackend::Ufw | FirewallBackend::Iptables
    ) {
        warn!(
            backend = ?config.backend,
            "large ban lists are more efficient with firewall.backend = \"iptables_ipset\""
        );
    }
}

pub fn local_loopback_ips() -> [IpAddr; 2] {
    [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipset_setup_creates_ipv4_and_ipv6_sets() {
        let config = FirewallConfig::default();
        let commands = ipset_setup_commands(&config);

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].program, "ipset");
        assert_eq!(
            commands[0].args[0..5],
            ["create", "honeypot_banned_v4", "hash:ip", "family", "inet"]
        );
        assert_eq!(
            commands[1].args[0..5],
            ["create", "honeypot_banned_v6", "hash:ip", "family", "inet6"]
        );
    }

    #[test]
    fn ipset_ban_uses_single_set_add_command() {
        let config = FirewallConfig::default();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        let commands = planned_ban_commands(&config, ip);

        assert_eq!(
            commands,
            vec![CommandSpec::new(
                "ipset",
                ["add", "honeypot_banned_v4", "203.0.113.10", "-exist"]
            )]
        );
    }

    #[test]
    fn plain_iptables_plans_check_then_insert() {
        let config = FirewallConfig {
            backend: FirewallBackend::Iptables,
            ..FirewallConfig::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        let commands = planned_ban_commands(&config, ip);

        assert_eq!(commands[0].args[0], "-C");
        assert_eq!(commands[1].args[0], "-I");
        assert_eq!(commands[1].args[2], "1");
    }
}
