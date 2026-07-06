use crate::{
    admin::password_matches,
    ban::{BanManager, UnbanOutcome},
    config::AdminConfig,
    store::BanRecord,
};
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::{error, warn};

const MAX_INLINE_HTTP_BYTES: usize = 16 * 1024;
const INLINE_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct InlineHttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct InlineUnbanRequest {
    ip: IpAddr,
    password: String,
}

#[derive(Debug, Deserialize)]
struct InlinePasswordQuery {
    password: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    ok: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct BannedResponse {
    ok: bool,
    banned_count: usize,
    ips: Vec<BanRecord>,
}

struct InlineHttpResponse {
    status_code: u16,
    reason: &'static str,
    body: Vec<u8>,
}

pub async fn try_handle_inline_admin(
    stream: &mut TcpStream,
    manager: &BanManager,
    config: &AdminConfig,
) -> anyhow::Result<bool> {
    if !config.inline_on_honeypot_port {
        return Ok(false);
    }

    let mut peek_buffer = [0_u8; 1024];
    let peeked = match timeout(
        Duration::from_millis(config.inline_probe_timeout_ms),
        stream.peek(&mut peek_buffer),
    )
    .await
    {
        Ok(Ok(0)) => return Ok(false),
        Ok(Ok(peeked)) => peeked,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Ok(false),
    };

    let Some((_, target)) = parse_request_line(&peek_buffer[..peeked]) else {
        return Ok(false);
    };
    if admin_subpath(&target, &config.inline_path_prefix).is_none() {
        return Ok(false);
    }

    let request = read_http_request(stream).await?;
    let response = handle_inline_request(request, manager, config).await;
    write_response(stream, response).await?;
    Ok(true)
}

async fn handle_inline_request(
    request: InlineHttpRequest,
    manager: &BanManager,
    config: &AdminConfig,
) -> InlineHttpResponse {
    let Some(path) = admin_subpath(&request.target, &config.inline_path_prefix) else {
        return json_response(
            404,
            "Not Found",
            &MessageResponse {
                ok: false,
                message: "not found".to_string(),
            },
        );
    };

    match (request.method.as_str(), path.as_str()) {
        ("GET", "/health") => json_response(
            200,
            "OK",
            &MessageResponse {
                ok: true,
                message: "ok".to_string(),
            },
        ),
        ("GET", "/banned") => {
            let query = query_string(&request.target);
            let parsed = serde_urlencoded::from_str::<InlinePasswordQuery>(query);
            let Ok(parsed) = parsed else {
                return json_response(
                    400,
                    "Bad Request",
                    &MessageResponse {
                        ok: false,
                        message: "invalid query".to_string(),
                    },
                );
            };
            if !password_matches(&parsed.password, &config.password) {
                warn!("inline admin banned-list request rejected because password was invalid");
                return json_response(
                    401,
                    "Unauthorized",
                    &MessageResponse {
                        ok: false,
                        message: "invalid password".to_string(),
                    },
                );
            }

            let ips = manager.records_snapshot().await;
            json_response(
                200,
                "OK",
                &BannedResponse {
                    ok: true,
                    banned_count: ips.len(),
                    ips,
                },
            )
        }
        ("GET", "/unban") => {
            let query = query_string(&request.target);
            match serde_urlencoded::from_str::<InlineUnbanRequest>(query) {
                Ok(unban) => unban_inline(manager, config, unban).await,
                Err(_) => json_response(
                    400,
                    "Bad Request",
                    &MessageResponse {
                        ok: false,
                        message: "invalid query".to_string(),
                    },
                ),
            }
        }
        ("POST", "/unban") => match serde_json::from_slice::<InlineUnbanRequest>(&request.body) {
            Ok(unban) => unban_inline(manager, config, unban).await,
            Err(_) => json_response(
                400,
                "Bad Request",
                &MessageResponse {
                    ok: false,
                    message: "invalid json".to_string(),
                },
            ),
        },
        _ => json_response(
            404,
            "Not Found",
            &MessageResponse {
                ok: false,
                message: "not found".to_string(),
            },
        ),
    }
}

async fn unban_inline(
    manager: &BanManager,
    config: &AdminConfig,
    request: InlineUnbanRequest,
) -> InlineHttpResponse {
    if !password_matches(&request.password, &config.password) {
        warn!(
            ip = %request.ip,
            "inline admin unban request rejected because password was invalid"
        );
        return json_response(
            401,
            "Unauthorized",
            &MessageResponse {
                ok: false,
                message: "invalid password".to_string(),
            },
        );
    }

    match manager.unban_ip(request.ip).await {
        Ok(UnbanOutcome::Unbanned) => json_response(
            200,
            "OK",
            &MessageResponse {
                ok: true,
                message: format!("{} unbanned", request.ip),
            },
        ),
        Ok(UnbanOutcome::NotBanned) => json_response(
            404,
            "Not Found",
            &MessageResponse {
                ok: false,
                message: format!("{} is not banned", request.ip),
            },
        ),
        Err(error) => {
            error!(ip = %request.ip, %error, "inline admin unban failed");
            json_response(
                500,
                "Internal Server Error",
                &MessageResponse {
                    ok: false,
                    message: "failed to unban ip".to_string(),
                },
            )
        }
    }
}

async fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<InlineHttpRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let read = timeout(INLINE_HTTP_READ_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("inline admin request read timed out")??;
        if read == 0 {
            bail!("inline admin connection closed before full HTTP request was read");
        }

        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_INLINE_HTTP_BYTES {
            bail!(
                "inline admin request exceeded {} bytes",
                MAX_INLINE_HTTP_BYTES
            );
        }

        if let Some(request) = parse_complete_request(&buffer)? {
            return Ok(request);
        }
    }
}

fn parse_complete_request(buffer: &[u8]) -> anyhow::Result<Option<InlineHttpRequest>> {
    let Some(header_end) = find_header_end(buffer) else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&buffer[..header_end])
        .context("inline admin HTTP headers were not valid UTF-8")?;
    let Some(first_line) = headers.lines().next() else {
        bail!("inline admin HTTP request line missing");
    };
    let mut parts = first_line.split_whitespace();
    let method = parts.next().context("inline admin HTTP method missing")?;
    let target = parts.next().context("inline admin HTTP target missing")?;
    let content_length = content_length(headers)?;
    let full_length = header_end + content_length;
    if buffer.len() < full_length {
        return Ok(None);
    }

    Ok(Some(InlineHttpRequest {
        method: method.to_ascii_uppercase(),
        target: target.to_string(),
        body: buffer[header_end..full_length].to_vec(),
    }))
}

fn parse_request_line(buffer: &[u8]) -> Option<(String, String)> {
    let line_end = buffer.iter().position(|byte| *byte == b'\n')?;
    let line = std::str::from_utf8(&buffer[..line_end]).ok()?.trim();
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next()?.to_string();
    if !matches!(method.as_str(), "GET" | "POST" | "HEAD" | "PUT" | "DELETE") {
        return None;
    }
    Some((method, target))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            buffer
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

fn content_length(headers: &str) -> anyhow::Result<usize> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .context("invalid content-length header");
        }
    }
    Ok(0)
}

fn admin_subpath(target: &str, prefix: &str) -> Option<String> {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let prefix = normalize_prefix(prefix);
    if path == prefix {
        return Some("/".to_string());
    }
    let rest = path.strip_prefix(&prefix)?;
    if !rest.starts_with('/') {
        return None;
    }
    Some(rest.to_string())
}

fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn query_string(target: &str) -> &str {
    target.split_once('?').map_or("", |(_, query)| query)
}

fn json_response<T: Serialize>(
    status_code: u16,
    reason: &'static str,
    value: &T,
) -> InlineHttpResponse {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    InlineHttpResponse {
        status_code,
        reason,
        body,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    response: InlineHttpResponse,
) -> anyhow::Result<()> {
    let headers = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.status_code,
        response.reason,
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_subpath_matches_only_configured_prefix() {
        assert_eq!(
            admin_subpath("/_honeypot_admin/unban?ip=1.1.1.1", "/_honeypot_admin").unwrap(),
            "/unban"
        );
        assert!(admin_subpath("/_honeypot_adminx/unban", "/_honeypot_admin").is_none());
        assert!(admin_subpath("/unban", "/_honeypot_admin").is_none());
    }

    #[test]
    fn complete_request_parser_waits_for_body() {
        let partial = b"POST /_honeypot_admin/unban HTTP/1.1\r\ncontent-length: 4\r\n\r\n{}";
        assert!(parse_complete_request(partial).unwrap().is_none());

        let full = b"POST /_honeypot_admin/unban HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}";
        let parsed = parse_complete_request(full).unwrap().unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/_honeypot_admin/unban");
        assert_eq!(parsed.body, b"{}");
    }
}
