use crate::{
    admin::password_matches,
    ban::{BanManager, UnbanOutcome},
    config::AdminConfig,
    store::BanRecord,
};
use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tracing::{error, warn};

const MAX_INLINE_HEADERS: usize = 32;
const HTTP_METHOD_PREFIXES: [&[u8]; 5] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE "];

#[derive(Debug)]
struct InlineHttpRequest {
    method: String,
    target: String,
    body: Vec<u8>,
    authorization: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineUnbanRequest {
    ip: IpAddr,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyUnbanQuery {
    ip: IpAddr,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LegacyPasswordQuery {
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

    let Some(request) = read_inline_candidate(stream, config).await? else {
        return Ok(false);
    };
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
        return message_response(404, "Not Found", false, "not found");
    };

    match (request.method.as_str(), path.as_str()) {
        ("GET", "/health") => message_response(200, "OK", true, "ok"),
        ("GET", "/banned") => {
            let legacy_password = config
                .allow_legacy_get_password
                .then(|| {
                    serde_urlencoded::from_str::<LegacyPasswordQuery>(query_string(&request.target))
                        .ok()
                        .map(|query| query.password)
                })
                .flatten();
            let password =
                bearer_password(request.authorization.as_deref()).or(legacy_password.as_deref());
            if !password.is_some_and(|password| password_matches(password, &config.password)) {
                warn!("inline admin banned-list request rejected because authentication failed");
                return message_response(401, "Unauthorized", false, "invalid credentials");
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
        ("GET", "/unban") if config.allow_legacy_get_password => {
            match serde_urlencoded::from_str::<LegacyUnbanQuery>(query_string(&request.target)) {
                Ok(query) => {
                    unban_inline(manager, config, query.ip, Some(query.password), None).await
                }
                Err(_) => message_response(400, "Bad Request", false, "invalid query"),
            }
        }
        ("GET", "/unban") => message_response(405, "Method Not Allowed", false, "use POST /unban"),
        ("POST", "/unban") => match serde_json::from_slice::<InlineUnbanRequest>(&request.body) {
            Ok(unban) => {
                unban_inline(
                    manager,
                    config,
                    unban.ip,
                    unban.password,
                    request.authorization.as_deref(),
                )
                .await
            }
            Err(_) => message_response(400, "Bad Request", false, "invalid json"),
        },
        _ => message_response(404, "Not Found", false, "not found"),
    }
}

async fn unban_inline(
    manager: &BanManager,
    config: &AdminConfig,
    ip: IpAddr,
    body_password: Option<String>,
    authorization: Option<&str>,
) -> InlineHttpResponse {
    let password = bearer_password(authorization).or(body_password.as_deref());
    if !password.is_some_and(|password| password_matches(password, &config.password)) {
        warn!(%ip, "inline admin unban request rejected because authentication failed");
        return message_response(401, "Unauthorized", false, "invalid credentials");
    }

    match manager.unban_ip(ip).await {
        Ok(UnbanOutcome::Unbanned) => message_response(200, "OK", true, &format!("{ip} unbanned")),
        Ok(UnbanOutcome::NotBanned) => {
            message_response(404, "Not Found", false, &format!("{ip} is not banned"))
        }
        Err(error) => {
            error!(%ip, %error, "inline admin unban failed");
            message_response(500, "Internal Server Error", false, "failed to unban ip")
        }
    }
}

async fn read_inline_candidate(
    stream: &mut TcpStream,
    config: &AdminConfig,
) -> anyhow::Result<Option<InlineHttpRequest>> {
    let started_at = Instant::now();
    let probe_deadline = started_at + Duration::from_millis(config.inline_probe_timeout_ms);
    let request_deadline = started_at + Duration::from_millis(config.inline_request_timeout_ms);
    let mut buffer = Vec::with_capacity(config.inline_max_request_bytes.min(4096));

    loop {
        if let Some(line_end) = buffer.iter().position(|byte| *byte == b'\n') {
            let Some((_, target)) = parse_request_line(&buffer[..=line_end]) else {
                return Ok(None);
            };
            if admin_subpath(&target, &config.inline_path_prefix).is_none() {
                return Ok(None);
            }
            break;
        }
        if !could_be_http_request(&buffer) {
            return Ok(None);
        }
        if !read_more(
            stream,
            &mut buffer,
            probe_deadline,
            config.inline_max_request_bytes,
        )
        .await?
        {
            return Ok(None);
        }
    }

    loop {
        if let Some(request) = parse_complete_request(&buffer, config.inline_max_request_bytes)? {
            return Ok(Some(request));
        }
        if !read_more(
            stream,
            &mut buffer,
            request_deadline,
            config.inline_max_request_bytes,
        )
        .await?
        {
            bail!("inline admin connection closed before the request completed");
        }
    }
}

async fn read_more(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    deadline: Instant,
    max_request_bytes: usize,
) -> anyhow::Result<bool> {
    ensure!(
        buffer.len() < max_request_bytes,
        "inline admin request exceeded configured size limit"
    );
    let remaining = max_request_bytes - buffer.len();
    let mut chunk = [0_u8; 1024];
    let chunk_len = remaining.min(chunk.len());
    let read = timeout_at(deadline, stream.read(&mut chunk[..chunk_len]))
        .await
        .context("inline admin request deadline exceeded")??;
    if read == 0 {
        return Ok(false);
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(true)
}

fn could_be_http_request(buffer: &[u8]) -> bool {
    HTTP_METHOD_PREFIXES
        .iter()
        .any(|prefix| prefix.starts_with(buffer) || buffer.starts_with(prefix))
}

fn parse_complete_request(
    buffer: &[u8],
    max_request_bytes: usize,
) -> anyhow::Result<Option<InlineHttpRequest>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_INLINE_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let header_length = match request
        .parse(buffer)
        .context("invalid inline admin HTTP request")?
    {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(length) => length,
    };
    let method = request.method.context("inline admin HTTP method missing")?;
    let target = request.path.context("inline admin HTTP target missing")?;
    let mut content_length = None;
    let mut authorization = None;

    for header in request.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            ensure!(content_length.is_none(), "duplicate content-length header");
            let value = str::from_utf8(header.value)
                .context("content-length header was not valid ASCII")?;
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid content-length header")?,
            );
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("transfer-encoding is not supported by inline admin");
        } else if header.name.eq_ignore_ascii_case("authorization") {
            ensure!(authorization.is_none(), "duplicate authorization header");
            authorization = Some(
                str::from_utf8(header.value)
                    .context("authorization header was not valid UTF-8")?
                    .trim()
                    .to_string(),
            );
        }
    }

    let full_length = header_length
        .checked_add(content_length.unwrap_or_default())
        .context("inline admin request length overflow")?;
    ensure!(
        full_length <= max_request_bytes,
        "inline admin request exceeded configured size limit"
    );
    if buffer.len() < full_length {
        return Ok(None);
    }

    Ok(Some(InlineHttpRequest {
        method: method.to_ascii_uppercase(),
        target: target.to_string(),
        body: buffer[header_length..full_length].to_vec(),
        authorization,
    }))
}

fn parse_request_line(buffer: &[u8]) -> Option<(String, String)> {
    let line_end = buffer.iter().position(|byte| *byte == b'\n')?;
    let line = str::from_utf8(&buffer[..line_end]).ok()?.trim();
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next()?.to_string();
    if !matches!(method.as_str(), "GET" | "POST" | "HEAD" | "PUT" | "DELETE") {
        return None;
    }
    Some((method, target))
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
    prefix.trim_end_matches('/').to_string()
}

fn query_string(target: &str) -> &str {
    target.split_once('?').map_or("", |(_, query)| query)
}

fn bearer_password(authorization: Option<&str>) -> Option<&str> {
    let (scheme, password) = authorization?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !password.is_empty()).then_some(password)
}

fn message_response(
    status_code: u16,
    reason: &'static str,
    ok: bool,
    message: &str,
) -> InlineHttpResponse {
    json_response(
        status_code,
        reason,
        &MessageResponse {
            ok,
            message: message.to_string(),
        },
    )
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
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
    use tokio::net::TcpListener;

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
        assert!(
            parse_complete_request(partial, 16 * 1024)
                .unwrap()
                .is_none()
        );

        let full = b"POST /_honeypot_admin/unban HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}";
        let parsed = parse_complete_request(full, 16 * 1024).unwrap().unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/_honeypot_admin/unban");
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn rejects_oversized_and_ambiguous_requests_without_panicking() {
        let overflow = format!(
            "POST /_honeypot_admin/unban HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
            usize::MAX
        );
        assert!(parse_complete_request(overflow.as_bytes(), 16 * 1024).is_err());

        let duplicate = b"POST /_honeypot_admin/unban HTTP/1.1\r\ncontent-length: 0\r\ncontent-length: 0\r\n\r\n";
        assert!(parse_complete_request(duplicate, 16 * 1024).is_err());

        let chunked = b"POST /_honeypot_admin/unban HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n";
        assert!(parse_complete_request(chunked, 16 * 1024).is_err());
    }

    #[test]
    fn extracts_bearer_password_case_insensitively() {
        assert_eq!(bearer_password(Some("Bearer secret")), Some("secret"));
        assert_eq!(bearer_password(Some("bearer secret")), Some("secret"));
        assert_eq!(bearer_password(Some("Basic secret")), None);
    }

    #[tokio::test]
    async fn candidate_reader_accepts_fragmented_request_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            for part in [
                b"G".as_slice(),
                b"ET /_honeypot_admin/health HTTP/1.1\r\n".as_slice(),
                b"host: localhost\r\n\r\n".as_slice(),
            ] {
                stream.write_all(part).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let config = AdminConfig {
            inline_on_honeypot_port: true,
            inline_probe_timeout_ms: 100,
            inline_request_timeout_ms: 200,
            ..AdminConfig::default()
        };

        let request = read_inline_candidate(&mut stream, &config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.target, "/_honeypot_admin/health");
        client.await.unwrap();
    }
}
