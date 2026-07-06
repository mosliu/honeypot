# Rust Honeypot PRD

## Summary

Build a lightweight Rust honeypot for Debian/Ubuntu servers. The service listens on a configured TCP address, counts visits by source IP in a configurable sliding time window, permanently bans abusive IPs through a configurable firewall backend, exposes a password-protected admin API for unbanning, optionally uploads the complete banned IP list to WebDAV, and records security events in configurable rolling logs.

## Goals

- Provide a simple deployable binary for Debian/Ubuntu.
- Detect repeated access to a configured honeypot port.
- Ban abusive IPs permanently until explicitly unbanned.
- Support `ufw`, plain `iptables`, and an efficient high-volume `iptables + ipset` mode.
- Persist banned IP state locally and restore it on service startup.
- Provide a minimal password-protected HTTP admin interface.
- Optionally serve the admin interface on the honeypot listener under a configured hidden path.
- Sync banned IP state to a configured WebDAV endpoint.
- Provide configurable file logging with level and retention controls.
- Provide a systemd service installer for Debian/Ubuntu deployments.

## Non-Goals

- This project does not emulate a full SSH, HTTP, FTP, or database protocol.
- This project does not provide a web dashboard.
- This project does not install OS package dependencies automatically.
- This project does not replace system-level firewall persistence tooling.
- This project does not guarantee that sophisticated scanners cannot identify it as a honeypot.

## Personas

- Server operator: wants to reduce repeated hostile scans against exposed services.
- Security operator: wants a simple banned-IP feed that can be synchronized to external storage.
- Developer/operator: wants predictable Rust code, logs, tests, and configuration-driven behavior.

## Functional Requirements

### Honeypot Listener

- The listener binds to `honeypot.listen_addr`.
- On every TCP connection, the service records the remote IP.
- The service returns a configurable banner and closes the connection.
- The service ignores IPs listed in `honeypot.allowlist`.
- `honeypot.allowlist` accepts exact IPs and CIDR ranges, for example `127.0.0.1`, `::1`, and `172.23.16.0/24`.
- The service uses a sliding window based on:
  - `honeypot.max_visits`
  - `honeypot.window_seconds`
- Reaching the configured count inside the window queues a permanent ban.

### Firewall Ban Backends

- `ufw` mode:
  - Ban: `ufw prepend deny from <ip>`
  - Unban: `ufw delete deny from <ip>`
  - Best for simple deployments and small ban lists.
- `iptables` mode:
  - Checks for an existing rule with `iptables -C` or `ip6tables -C`.
  - Inserts a source DROP rule with `iptables -I` or `ip6tables -I`.
  - Deletes with `iptables -D` or `ip6tables -D`.
  - Simple, but one rule is added per IP.
- `iptables_ipset` mode:
  - Creates IPv4 and IPv6 `hash:ip` sets with `ipset`.
  - Ensures one iptables/ip6tables DROP rule points to each set.
  - Adds/removes banned IPs with `ipset add` and `ipset del`.
  - Recommended default for large ban lists because firewall rule count stays constant while IP membership is kept in kernel hash sets.
- `dry_run` mode:
  - Does not execute firewall changes.
  - Intended for development and config validation.

### Admin API

- The API binds to `admin.listen_addr`.
- Requests must include `admin.password`.
- Endpoints:
  - `GET /health`
  - `POST /unban`
  - `GET /unban`
  - `GET /banned`
- `POST /unban` body:

```json
{
  "ip": "203.0.113.10",
  "password": "configured-password"
}
```

- `GET /unban` query:

```text
/unban?ip=203.0.113.10&password=configured-password
```

- `GET /banned` returns the current persisted banned IP snapshot.
- If `admin.inline_on_honeypot_port = true`, these endpoints are served on the honeypot listener under `admin.inline_path_prefix`, for example `http://host:22/_honeypot_admin/unban`.

### State Persistence

- The service persists banned IPs to `state.banned_ips_path`.
- State file format is JSON with:
  - `updated_at`
  - `ips[]`
  - `ip`
  - `banned_at`
  - `reason`
- On startup, the service initializes the firewall backend and reapplies all persisted records.

### WebDAV Sync

- WebDAV sync is controlled by `webdav.enabled`.
- When enabled, changes to the banned set queue an upload.
- Uploads are debounced by `webdav.debounce_seconds`.
- The upload method is HTTP `PUT` to `webdav.url`.
- The transport uses the configured `webdav.curl_binary`, defaulting to `curl`.
- The payload is a complete JSON snapshot, not an incremental patch.
- Basic authentication is supported through `webdav.username` and `webdav.password`.
- Failed uploads are logged and do not roll back local firewall state.

### Logging

- Logging uses the Rust `tracing` ecosystem.
- Log directory is configured with `logging.directory`.
- Log level is configured with `logging.level`.
- File prefix is configured with `logging.file_prefix`.
- Retention controls:
  - `logging.retention_files`
  - `logging.retention_days`
- Logs include:
  - firewall backend selection
  - threshold hits
  - ban success/failure
  - unban success/failure
  - WebDAV sync success/failure
  - service startup/shutdown

### Service Installation

- `scripts/install-service.sh` installs:
  - `/usr/local/bin/honeypot`
  - `/etc/honeypot/config.toml`
  - `/etc/systemd/system/honeypot.service`
  - `/var/lib/honeypot`
  - `/var/log/honeypot`
- The installer enables `honeypot.service`.
- The installer starts the service only when `--start` is provided.

### Port 22 SSH-Like Behavior

- Operators can bind `honeypot.listen_addr` to `0.0.0.0:22`.
- The service can send a configurable OpenSSH-like banner.
- The service can wait for a client identification string after sending its banner.
- The service can delay connection close.
- This reduces trivial banner-only fingerprints but does not implement full SSH key exchange, authentication, or session behavior.

## Non-Functional Requirements

### Performance

- The listener should avoid running firewall commands directly in the accept path.
- Ban operations should be queued and processed outside the connection accept path.
- Visit tracking should keep only timestamps inside the configured sliding window.
- `honeypot.max_tracked_ips` limits in-memory tracking growth.
- The default backend should be `iptables_ipset` for large IP volumes.

### Reliability

- Firewall command failures must be logged and must not be written as successful bans.
- Local state writes should be atomic enough for normal operation by writing a temporary file and renaming it.
- Admin unban should update firewall first, then local state, then WebDAV.

### Security

- The admin API should bind to localhost by default.
- The admin password must not be empty.
- The real `config.toml` should not be committed because it may contain secrets.
- Error responses should not expose WebDAV credentials or firewall command output to API callers.

## Configuration Surface

The canonical example is `config.example.toml`.

Key sections:

- `[honeypot]`
- `[admin]`
- `[firewall]`
- `[state]`
- `[webdav]`
- `[logging]`

## Acceptance Criteria

- `cargo test` passes.
- `cargo fmt --check` passes.
- The binary starts with a valid config file.
- `dry_run` mode can be used without root privileges for local testing.
- `iptables_ipset` mode plans one set-add command per ban and a constant number of iptables rules.
- The docs folder contains the user requirements and this PRD.
