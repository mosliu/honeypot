# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-07-13

### Security

- Made Bearer authentication the default for protected standalone and inline admin endpoints; legacy query-string passwords now require `admin.allow_legacy_get_password = true`.
- Restricted inline admin handling to allowlisted source IPs and rejected duplicate or ambiguous HTTP authentication and framing headers.
- Required an explicit admin password of at least 16 characters, rejected documented placeholders and unknown configuration fields, and required explicit opt-in for remote plaintext admin or HTTP WebDAV access.
- Moved WebDAV credentials out of process arguments into owner-only temporary curl configuration files, with bounded stderr capture and hard process timeouts.
- Set Unix snapshot, journal, and pending state files to mode `0600`.

### Reliability

- Replaced full-state rewrites on each ban with an atomic snapshot, durable JSONL journal, and recoverable pending intent around firewall changes.
- Added torn-journal repair, startup recovery, graceful state compaction, Unix directory metadata synchronization, and failure-path tests.
- Added bounded firewall command timeouts, idempotent restore/unban behavior, accept-error backoff, connection task draining, SIGTERM handling, and aggregated shutdown errors.
- Changed WebDAV synchronization to latest-only snapshots with debounce and bounded exponential retry, without blocking local firewall operations.
- Enforced log retention periodically during long-running service operation.

### Performance

- Added `honeypot.max_concurrent_connections` and a bounded, IP-deduplicated ban queue that waits for capacity instead of dropping security events.
- Replaced global visit-table sweeps with a bounded LRU and capped each IP at `max_visits` timestamps.
- Reaped completed connection tasks while listeners remain active.

### Admin And Configuration

- Added bounded incremental inline HTTP parsing with separate probe/request deadlines and request-size limits.
- Added `--check-config` for deployment preflight validation.
- Added validation for numeric listen addresses, resource limits, firewall/WebDAV timeouts, secure URL policy, path constraints, credential pairing, and logging filters.
- Kept optional POST body passwords for 0.2 compatibility while documenting Bearer authentication as the supported default.

### Deployment

- Changed the systemd unit to `Type=notify`; readiness is reported only after firewall restoration and all required listeners are ready, and shutdown reports `STOPPING=1`.
- Added systemd resource limits, a restrictive umask, private temporary files, and bounded startup/shutdown timeouts.
- Added a production config template and transactional installer rollback that restores files plus prior active/enabled service state after any installation failure.
- Updated CI to use locked all-target/all-feature checks and included installer and packaging files in release archives.

### Upgrade Notes

- Existing installations must replace placeholder or shorter-than-16-character admin passwords before startup.
- Legacy `GET /unban` and query-string authentication are disabled unless `admin.allow_legacy_get_password = true` is set temporarily for migration.
- Non-loopback plaintext admin listeners and `http://` WebDAV URLs now require their respective `allow_insecure_http` opt-in.
- Misspelled or obsolete configuration keys now fail validation instead of being silently ignored.

## [0.2.0] - 2026-07-07

### Added

- Native `nftables` firewall backend for modern Debian and Ubuntu systems.
- Inline admin mode on the honeypot port under a configurable hidden path.
- Systemd service unit and installer script for Debian/Ubuntu deployment.
- GitHub Actions workflow for CI and tag-based release publishing.
- IP and CIDR allowlist support.
- Rolling file logging with configurable directory, level, retention file count, and retention days.
- WebDAV banned-IP snapshot upload support.
- Local banned-IP state persistence and restore on startup.

### Changed

- Default firewall backend recommendation now favors `nftables` on Ubuntu 24 / Debian 13 class systems.
- Updated example configuration and documentation for `nftables`, service installation, inline admin usage, and cross-compilation.
- Improved SSH-like honeypot behavior with configurable banner timing and client identification wait.

## [0.1.0] - 2026-07-06

### Added

- Initial Rust honeypot implementation.
- TCP listener with configurable rate-based IP banning.
- Firewall backends for `ufw`, `iptables`, `iptables_ipset`, and `dry_run`.
- Password-protected admin API for unbanning and viewing banned IPs.
- Release packaging, docs, and deployment guidance.
