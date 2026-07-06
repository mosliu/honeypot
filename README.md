# honeypot

Configurable Rust honeypot for Debian/Ubuntu. It listens on a TCP port, counts repeated visits by source IP, and permanently bans abusive IPs through `ufw`, `iptables`, or the recommended high-volume `iptables + ipset` backend.

## Quick Start

```powershell
cargo build --release
Copy-Item config.example.toml config.toml
```

Edit `config.toml` before production use:

- Set `admin.password` to a long random value.
- Set `honeypot.allowlist` with exact IPs or CIDR ranges that must never be banned.
- Choose `firewall.backend`.
- Configure `webdav` if remote banned-IP sync is needed.
- Configure `logging.directory`, `logging.level`, `logging.retention_files`, and `logging.retention_days`.

For local development without changing firewall rules:

```toml
[firewall]
backend = "dry_run"
```

Run:

```powershell
cargo run -- --config config.toml
```

## Admin API

Unban with POST:

```bash
curl -X POST http://127.0.0.1:8080/unban \
  -H 'content-type: application/json' \
  -d '{"ip":"203.0.113.10","password":"configured-password"}'
```

Unban with GET:

```bash
curl 'http://127.0.0.1:8080/unban?ip=203.0.113.10&password=configured-password'
```

List banned IPs:

```bash
curl 'http://127.0.0.1:8080/banned?password=configured-password'
```

## Firewall Backend Guidance

- `iptables_ipset`: recommended default for many IPs. It uses a constant number of iptables rules and stores IPs in kernel hash sets.
- `iptables`: simple, but adds one rule per banned IP.
- `ufw`: convenient, but also adds one rule per banned IP.
- `dry_run`: logs firewall actions without applying them.

The service must run with privileges that allow firewall changes when not using `dry_run`.
Install `curl` on the target system when `webdav.enabled = true`.
