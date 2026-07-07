# Changelog

All notable changes to this project will be documented in this file.

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
