# honeypot

Rust 编写的 Debian/Ubuntu 蜜罐服务。程序监听一个配置端口，按来源 IP 统计访问次数；当某个 IP 在配置时间窗口内达到阈值后，通过 `nftables`、`ufw`、`iptables` 或 `iptables + ipset` 后端永久封禁该 IP，直到通过管理 API 解封。

## 功能

- Rust 单二进制服务。
- 支持 Debian/Ubuntu。
- 可配置监听地址、访问阈值和统计窗口。
- 白名单支持纯 IP 和 CIDR，例如 `127.0.0.1`、`::1`、`172.23.16.0/24`。
- 防火墙后端：
  - `nftables`：现代 Debian/Ubuntu 的推荐默认值。
  - `iptables_ipset`：高性能兼容方案，适合大量 IP。
  - `iptables`：每个 IP 一条 DROP 规则。
  - `ufw`：每个 IP 一条 UFW deny 规则。
  - `dry_run`：只记录日志，不修改防火墙。
- 本地持久化已封禁 IP，启动时自动恢复。
- 管理 API 支持密码解封 IP 和查看封禁列表。
- 可选 WebDAV 同步，将完整封禁列表 PUT 到远端。
- 使用 `tracing` 日志框架，支持日志目录、级别、保留文件数、保留天数配置。
- GitHub Actions 支持自动 CI 和 tag 发布 Release。

## 目录

- `config.example.toml`：配置模板。
- `docs/requirements.md`：需求整理。
- `docs/prd.md`：PRD。
- `src/`：Rust 源码。
- `.github/workflows/ci-release.yml`：GitHub 自动编译和发布流程。

## 本地快速开始

```powershell
cargo build --release
Copy-Item config.example.toml config.toml
cargo run -- --config config.toml
```

生产运行前必须修改 `config.toml`：

- 将 `admin.password` 改成长随机密码。
- 将 `honeypot.allowlist` 设置为永不封禁的 IP 或 CIDR。
- 根据规模选择 `firewall.backend`，Ubuntu 24 / Debian 13 这类系统建议优先使用 `nftables`。
- 如果需要 WebDAV，同步配置 `webdav.enabled`、`webdav.url`、`webdav.username`、`webdav.password`。
- 根据运维策略配置 `logging.directory`、`logging.level`、`logging.retention_files`、`logging.retention_days`。

本地开发时建议先使用：

```toml
[firewall]
backend = "dry_run"
```

## 编译

开发编译：

```bash
cargo build
```

Release 编译：

```bash
cargo build --release
```

输出位置：

```text
target/release/honeypot
```

Windows 主机上输出文件是：

```text
target/release/honeypot.exe
```

质量检查：

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

## Debian/Ubuntu 编译和运行

安装基础依赖：

```bash
sudo apt update
sudo apt install -y build-essential curl nftables iptables ipset ufw
```

编译：

```bash
cargo build --release
```

运行：

```bash
sudo ./target/release/honeypot --config config.toml
```

说明：

- 非 `dry_run` 模式需要 root 或等效权限修改防火墙。
- `nftables` 后端需要系统安装 `nft` 命令，Ubuntu 24 / Debian 13 推荐使用这个后端。
- `iptables_ipset` 需要 `iptables`、`ip6tables` 和 `ipset`。
- `ufw` 后端需要系统安装并启用 UFW。
- `webdav.enabled = true` 时需要目标系统有 `curl`。

## 自动安装 systemd service

先编译：

```bash
cargo build --release
```

准备生产配置：

```bash
cp config.example.toml config.toml
vim config.toml
```

安装 systemd 服务：

```bash
sudo scripts/install-service.sh --config config.toml
```

安装并立即启动：

```bash
sudo scripts/install-service.sh --config config.toml --start
```

安装脚本会执行：

- 安装二进制到 `/usr/local/bin/honeypot`。
- 安装配置到 `/etc/honeypot/config.toml`。
- 安装 systemd unit 到 `/etc/systemd/system/honeypot.service`。
- 创建 `/var/lib/honeypot` 和 `/var/log/honeypot`。
- 执行 `systemctl daemon-reload`。
- 执行 `systemctl enable honeypot.service`。

常用运维命令：

```bash
sudo systemctl start honeypot.service
sudo systemctl stop honeypot.service
sudo systemctl restart honeypot.service
sudo systemctl status honeypot.service
journalctl -u honeypot.service -f
```

## 在蜜罐端口上提供解封接口

默认情况下，管理 API 独立监听 `admin.listen_addr`，例如 `127.0.0.1:8080`。如果希望解封接口直接挂在蜜罐端口上，可以启用 inline 模式：

```toml
[admin]
listen_addr = "127.0.0.1:8080"
password = "replace-with-a-long-random-password"
inline_on_honeypot_port = true
inline_path_prefix = "/_honeypot_admin"
inline_probe_timeout_ms = 250
```

启用后，不再启动独立 admin 端口。管理接口会挂在蜜罐监听端口的隐藏路径下：

```bash
curl 'http://server-ip:22/_honeypot_admin/unban?ip=203.0.113.10&password=configured-password'
curl 'http://server-ip:22/_honeypot_admin/banned?password=configured-password'
curl 'http://server-ip:22/_honeypot_admin/health'
```

注意：

- 如果某个来源 IP 已被防火墙封禁，它无法从同一个来源 IP 访问 inline 解封接口，因为防火墙会先挡住连接。
- 管理方 IP 应该加入 `honeypot.allowlist`。
- inline 模式会在蜜罐端口上短暂探测 HTTP 管理请求；普通 SSH 探测和非隐藏路径请求仍按蜜罐连接处理。
- 从安全角度，默认的独立本地管理端口更稳妥；inline 模式适合端口受限或临时运维场景。

## 22 端口部署和拟真限制

如果主要想保护 SSH，可以直接监听 22：

```toml
[honeypot]
listen_addr = "0.0.0.0:22"
banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
read_after_banner_timeout_ms = 1500
close_delay_ms = 0
```

但同一个 IP 的同一个 22 端口不能同时给真实 OpenSSH 和本程序使用。常见部署方式：

- 将真实 SSH 移到另一个端口，并只允许 VPN、堡垒机或白名单 IP 访问。
- 给真实 SSH 使用另一个内网 IP，本程序占用公网 22。
- 在云安全组或前置防火墙上只把公网 22 指向本程序。

本项目提供轻量 SSH-like 行为：

- 可配置 OpenSSH 风格 banner。
- 发送 banner 后等待客户端 identification。
- 可配置关闭延迟。

这可以减少非常简单的端口扫描特征，但不能保证“识别不出来是蜜罐”。专业扫描器会继续做 SSH key exchange、算法协商和行为指纹识别；如果服务不实现完整 SSH 协议，仍可能被识别。要高度拟真，需要实现完整 SSH 握手和认证流程，或接入专用 SSH 蜜罐协议栈。

## 跨平台编译

这个项目的业务目标是 Debian/Ubuntu。Windows/macOS 可以编译用于开发验证，但真实封禁依赖 Linux 防火墙命令，生产部署应使用 Linux 目标产物。

### 使用 cross 编译 Linux 产物

`cross` 是最省事的跨平台编译方式，依赖 Docker。

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target aarch64-unknown-linux-gnu
```

输出示例：

```text
target/x86_64-unknown-linux-gnu/release/honeypot
target/x86_64-unknown-linux-musl/release/honeypot
target/aarch64-unknown-linux-gnu/release/honeypot
```

### Linux 编译 musl 静态产物

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

### Linux 编译 ARM64 GNU 产物

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt install -y gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

### Linux 编译 Windows 产物

这只适合开发验证，不适合生产封禁。

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install -y mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

### Windows GNU 工具链注意事项

如果 Windows 上使用 `x86_64-pc-windows-gnu`，并遇到 `dlltool.exe: program not found`，需要把 MinGW/Cygwin 的 bin 目录加入 PATH。例如：

```powershell
$env:PATH = 'C:\cygwin64\bin;C:\cygwin64\usr\x86_64-w64-mingw32\bin;' + $env:PATH
cargo test
```

## GitHub 自动编译和发布 Release

仓库包含 `.github/workflows/ci-release.yml`：

- push 到任意分支：自动运行格式检查、clippy、测试、release build。
- pull request：自动运行同样的 CI。
- 推送 `v*` tag：自动构建 Linux release 包，生成 sha256，并创建 GitHub Release。

推荐用 tag 触发发布，而不是每个提交都发布 Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Release 会包含：

- `honeypot-x86_64-unknown-linux-gnu.tar.gz`
- `honeypot-x86_64-unknown-linux-musl.tar.gz`
- `honeypot-aarch64-unknown-linux-gnu.tar.gz`
- 对应的 `.sha256` 文件

如果仓库设置里禁用了 Actions 写权限，需要在 GitHub 仓库设置中允许 workflow 使用 `GITHUB_TOKEN` 写入 release。通常路径是：

```text
Settings -> Actions -> General -> Workflow permissions -> Read and write permissions
```

如果确实希望每次 push 到 `main` 都发布 Release，可以改 workflow 的 `release-build` 和 `release-publish` 的 `if` 条件，并显式设置 release tag/name。不过不建议这样做，因为普通提交会快速产生大量 Release。

## 管理 API

解封 IP：

```bash
curl -X POST http://127.0.0.1:8080/unban \
  -H 'content-type: application/json' \
  -d '{"ip":"203.0.113.10","password":"configured-password"}'
```

也可以用 GET：

```bash
curl 'http://127.0.0.1:8080/unban?ip=203.0.113.10&password=configured-password'
```

查看当前封禁列表：

```bash
curl 'http://127.0.0.1:8080/banned?password=configured-password'
```

健康检查：

```bash
curl 'http://127.0.0.1:8080/health'
```

## 防火墙后端选择

`nftables` 是现代 Debian/Ubuntu 的默认推荐：

- 使用内核原生 `nftables` 表、链和地址集合。
- 不需要额外依赖 `ipset`。
- 对 Ubuntu 24 这类 `iptables-nft` 环境更直接。

`iptables_ipset` 是兼容性很好的高性能备选：

- iptables/ip6tables 只维护常量数量的规则。
- IP 放在内核 ipset 哈希集合里。
- 大量封禁 IP 时，比一 IP 一规则更省规则遍历成本和管理成本。

`iptables`：

- 简单直接。
- 每个 IP 一条规则。
- IP 多时规则链会变长。

`ufw`：

- 运维友好。
- 每个 IP 一条 UFW 规则。
- 更适合小规模封禁。

`dry_run`：

- 本地开发和 CI 友好。
- 不会修改系统防火墙。

## 配置示例

```toml
[honeypot]
listen_addr = "0.0.0.0:2222"
max_visits = 5
window_seconds = 60
max_tracked_ips = 100000
allowlist = ["127.0.0.1", "::1", "172.23.16.0/24"]
banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"

[admin]
listen_addr = "127.0.0.1:8080"
password = "replace-with-a-long-random-password"

[firewall]
backend = "nftables"
```

完整模板见 `config.example.toml`。
