# Honeypot Requirements

## Original Requirements

1. Implement a honeypot in Rust.
2. Target Debian or Ubuntu systems.
3. Listen on a configured port. If an IP visits more than the configured count within the configured time window, permanently block that IP using configurable `ufw` or `iptables`.
4. Provide an interface that uses a configured password to unblock a specific IP.
5. Support configuring a WebDAV service and upload all banned IPs to it.
6. Consider the case where many IPs access the honeypot, and choose a ban strategy that saves system resources.
7. Use Git for code management.
8. Put the requirements and generated PRD under `docs/`.
9. Use a logging framework to record ban activity. Logging must allow configuring the log path, retained file count, retained days, and log level.
10. Provide a way to automatically install the program as a system service.
11. Allow the unban API to be served directly on the configured honeypot port.
12. The primary deployment target is port 22. Reduce obvious honeypot fingerprints where practical, while documenting that complete indistinguishability requires a full SSH protocol implementation.

## Implemented Interpretation

- The honeypot listens on `honeypot.listen_addr`, for example `0.0.0.0:2222`.
- The threshold is a sliding window: with `max_visits = 5` and `window_seconds = 60`, the fifth visit from the same IP inside 60 seconds triggers a ban.
- Bans are permanent until the admin API unbans the IP.
- The local banned IP state is persisted to `state.banned_ips_path` as JSON and restored on startup.
- The admin API listens on `admin.listen_addr`.
- The admin API supports:
  - `POST /unban` with `Authorization: Bearer <password>` and JSON body `{"ip":"203.0.113.10"}`.
  - `GET /banned` with Bearer authentication.
  - `GET /health`.
- `honeypot.allowlist` supports exact IP entries and CIDR entries, for example `127.0.0.1`, `::1`, and `172.23.16.0/24`.
- `admin.inline_on_honeypot_port = true` serves admin endpoints on the honeypot listener only for allowlisted source IPs. Public plaintext use requires an explicit insecure-HTTP opt-in.
- `scripts/install-service.sh` validates configuration before replacement and transactionally installs the release binary, config, documentation, and systemd unit.
- The systemd service reports ready only after firewall restoration and all required listeners complete startup.
- Port 22 can be used by setting `honeypot.listen_addr = "0.0.0.0:22"`. The current implementation can mimic an OpenSSH banner and timing, but does not implement a complete SSH key exchange.
- WebDAV sync is optional. When enabled, the program uploads a complete JSON snapshot of all banned IPs using HTTP `PUT`.
- WebDAV notifications retain only the latest snapshot, retry failures with bounded exponential backoff, and never block local firewall operations.
- Logging uses the `tracing` ecosystem, writes daily rolling log files, and enforces retention periodically while running.
- Runtime state uses an atomic snapshot, incremental journal, and pending intent so interrupted firewall changes can be recovered; state files are owner-only on Unix.
- Connection concurrency, per-IP visit history, and the pending ban queue are explicitly bounded.
- For modern Debian/Ubuntu systems, `firewall.backend = "nftables"` is the recommended mode. It uses native nftables sets without requiring `ipset`.
- `firewall.backend = "iptables_ipset"` remains available as a compatibility-focused high-volume mode. It keeps one iptables rule and stores IP membership in ipset hash sets.

## Operational Assumptions

- The service is expected to run with enough privileges to modify firewall rules.
- Debian/Ubuntu packages may need to be installed before use:
  - `ufw` for `firewall.backend = "ufw"`.
  - `iptables` for `firewall.backend = "iptables"`.
  - `nftables` for `firewall.backend = "nftables"`.
  - `iptables` and `ipset` for `firewall.backend = "iptables_ipset"`.
  - `curl` when `webdav.enabled = true`.
- `iptables` rules and `ipset` contents can be restored by this program when it starts, based on the local state file. If bans must survive a machine reboot before the service starts, configure this program as a system service or use the distribution's firewall persistence tooling.
- The real `config.toml` is ignored by Git because it can contain passwords.
