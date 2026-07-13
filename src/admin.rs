use crate::{
    ban::{BanManager, UnbanOutcome},
    config::AdminConfig,
    store::BanRecord,
};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
};
use tracing::{error, info, warn};

#[derive(Clone)]
struct AdminState {
    manager: BanManager,
    password: Arc<String>,
    allow_legacy_get_password: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbanRequest {
    ip: IpAddr,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPasswordQuery {
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyUnbanRequest {
    ip: IpAddr,
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

pub async fn run_admin_api(
    config: AdminConfig,
    manager: BanManager,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    run_admin_api_with_readiness(config, manager, shutdown, None).await
}

pub async fn run_admin_api_with_readiness(
    config: AdminConfig,
    manager: BanManager,
    mut shutdown: watch::Receiver<bool>,
    readiness: Option<oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let listener = TcpListener::bind(&listen_addr).await?;
    let app = router(config, manager);
    info!(%listen_addr, "admin API started");
    if let Some(readiness) = readiness {
        let _ = readiness.send(());
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            info!("admin API shutting down");
        })
        .await?;
    Ok(())
}

pub fn router(config: AdminConfig, manager: BanManager) -> Router {
    let allow_legacy_get_password = config.allow_legacy_get_password;
    let state = AdminState {
        manager,
        password: Arc::new(config.password),
        allow_legacy_get_password,
    };

    let mut router = Router::new()
        .route("/health", get(health))
        .route("/unban", post(post_unban))
        .route("/banned", get(get_banned));

    if allow_legacy_get_password {
        router = router.route("/unban", get(get_unban));
    }

    router
        .with_state(state)
        .layer(middleware::from_fn(add_no_store_header))
}

async fn add_no_store_header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn health() -> Response {
    message_response(StatusCode::OK, true, "ok".to_string())
}

async fn post_unban(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(request): Json<UnbanRequest>,
) -> Response {
    let password = bearer_password(&headers)
        .map(str::to_owned)
        .or(request.password);
    unban(state, request.ip, password.as_deref()).await
}

async fn get_unban(
    State(state): State<AdminState>,
    Query(request): Query<LegacyUnbanRequest>,
) -> Response {
    unban(state, request.ip, Some(&request.password)).await
}

async fn get_banned(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(query): Query<LegacyPasswordQuery>,
) -> Response {
    let provided_password = bearer_password(&headers).or_else(|| {
        state
            .allow_legacy_get_password
            .then_some(query.password.as_deref())
            .flatten()
    });
    if !provided_password.is_some_and(|password| password_matches(password, &state.password)) {
        warn!("admin banned-list request rejected because password was invalid");
        return banned_response(
            StatusCode::UNAUTHORIZED,
            BannedResponse {
                ok: false,
                banned_count: 0,
                ips: Vec::new(),
            },
        );
    }

    let ips = state.manager.records_snapshot().await;
    banned_response(
        StatusCode::OK,
        BannedResponse {
            ok: true,
            banned_count: ips.len(),
            ips,
        },
    )
}

async fn unban(state: AdminState, ip: IpAddr, password: Option<&str>) -> Response {
    if !password.is_some_and(|password| password_matches(password, &state.password)) {
        warn!(%ip, "admin unban request rejected because password was invalid");
        return message_response(
            StatusCode::UNAUTHORIZED,
            false,
            "invalid password".to_string(),
        );
    }

    match state.manager.unban_ip(ip).await {
        Ok(UnbanOutcome::Unbanned) => {
            message_response(StatusCode::OK, true, format!("{ip} unbanned"))
        }
        Ok(UnbanOutcome::NotBanned) => {
            message_response(StatusCode::NOT_FOUND, false, format!("{ip} is not banned"))
        }
        Err(error) => {
            error!(%ip, %error, "admin unban failed");
            message_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                "failed to unban ip".to_string(),
            )
        }
    }
}

fn bearer_password(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, credentials) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return None;
    }
    Some(credentials)
}

fn message_response(status: StatusCode, ok: bool, message: String) -> Response {
    no_store_response(status, Json(MessageResponse { ok, message }))
}

fn banned_response(status: StatusCode, body: BannedResponse) -> Response {
    no_store_response(status, Json(body))
}

fn no_store_response<T: Serialize>(status: StatusCode, body: Json<T>) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        body,
    )
        .into_response()
}

pub(crate) fn password_matches(provided: &str, expected: &str) -> bool {
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    let max_len = provided.len().max(expected.len());
    let mut diff = provided.len() ^ expected.len();

    for index in 0..max_len {
        let left = provided.get(index).copied().unwrap_or_default();
        let right = expected.get(index).copied().unwrap_or_default();
        diff |= (left ^ right) as usize;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::Firewall;
    use axum::body::Body;
    use std::{net::Ipv4Addr, path::PathBuf};
    use tower::ServiceExt;

    struct NoopFirewall;

    impl Firewall for NoopFirewall {
        fn setup(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn ban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            Ok(())
        }

        fn unban(&self, _ip: IpAddr) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn test_state(allow_legacy_get_password: bool) -> (AdminState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let manager = BanManager::load(
            Arc::new(NoopFirewall),
            PathBuf::from(dir.path()).join("banned_ips.json"),
            None,
        )
        .unwrap();
        (
            AdminState {
                manager,
                password: Arc::new("correct horse battery staple".to_string()),
                allow_legacy_get_password,
            },
            dir,
        )
    }

    #[test]
    fn password_match_requires_exact_content() {
        assert!(password_matches("secret", "secret"));
        assert!(!password_matches("secret", "Secret"));
        assert!(!password_matches("secret", "secret!"));
        assert!(!password_matches("", "secret"));
    }

    #[test]
    fn bearer_password_is_case_insensitive_and_rejects_other_schemes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bEaReR secret"),
        );
        assert_eq!(bearer_password(&headers), Some("secret"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic secret"),
        );
        assert_eq!(bearer_password(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(bearer_password(&headers), None);
    }

    #[tokio::test]
    async fn banned_list_uses_bearer_and_disables_legacy_query_by_default() {
        let (state, _dir) = test_state(false);
        let query = LegacyPasswordQuery {
            password: Some("correct horse battery staple".to_string()),
        };

        let rejected = get_banned(State(state.clone()), HeaderMap::new(), Query(query)).await;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            rejected.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer correct horse battery staple"),
        );
        let accepted =
            get_banned(State(state), headers, Query(LegacyPasswordQuery::default())).await;
        assert_eq!(accepted.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn banned_list_allows_query_password_only_when_legacy_mode_is_enabled() {
        let (state, _dir) = test_state(true);
        let response = get_banned(
            State(state),
            HeaderMap::new(),
            Query(LegacyPasswordQuery {
                password: Some("correct horse battery staple".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_unban_accepts_optional_body_password_and_sets_no_store() {
        let (state, _dir) = test_state(false);
        let response = post_unban(
            State(state),
            HeaderMap::new(),
            Json(UnbanRequest {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                password: Some("correct horse battery staple".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[tokio::test]
    async fn framework_rejections_also_set_no_store() {
        let (state, _dir) = test_state(false);
        let config = AdminConfig {
            password: "correct horse battery staple".to_string(),
            ..AdminConfig::default()
        };
        let app = router(config, state.manager);
        let request = Request::builder()
            .method("POST")
            .uri("/unban")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }
}
