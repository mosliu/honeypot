use crate::{
    ban::{BanManager, UnbanOutcome},
    config::AdminConfig,
    store::BanRecord,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tokio::{net::TcpListener, sync::watch};
use tracing::{error, info, warn};

#[derive(Clone)]
struct AdminState {
    manager: BanManager,
    password: Arc<String>,
}

#[derive(Debug, Deserialize)]
struct UnbanRequest {
    ip: IpAddr,
    password: String,
}

#[derive(Debug, Deserialize)]
struct PasswordQuery {
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
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listen_addr = config.listen_addr.clone();
    let listener = TcpListener::bind(&listen_addr).await?;
    let app = router(config, manager);
    info!(%listen_addr, "admin API started");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            info!("admin API shutting down");
        })
        .await?;
    Ok(())
}

pub fn router(config: AdminConfig, manager: BanManager) -> Router {
    let state = AdminState {
        manager,
        password: Arc::new(config.password),
    };

    Router::new()
        .route("/health", get(health))
        .route("/unban", post(post_unban).get(get_unban))
        .route("/banned", get(get_banned))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(MessageResponse {
        ok: true,
        message: "ok".to_string(),
    })
}

async fn post_unban(
    State(state): State<AdminState>,
    Json(request): Json<UnbanRequest>,
) -> impl IntoResponse {
    unban(state, request.ip, request.password).await
}

async fn get_unban(
    State(state): State<AdminState>,
    Query(request): Query<UnbanRequest>,
) -> impl IntoResponse {
    unban(state, request.ip, request.password).await
}

async fn get_banned(
    State(state): State<AdminState>,
    Query(query): Query<PasswordQuery>,
) -> impl IntoResponse {
    if !password_matches(&query.password, &state.password) {
        warn!("admin banned-list request rejected because password was invalid");
        return (
            StatusCode::UNAUTHORIZED,
            Json(BannedResponse {
                ok: false,
                banned_count: 0,
                ips: Vec::new(),
            }),
        );
    }

    let ips = state.manager.records_snapshot().await;
    (
        StatusCode::OK,
        Json(BannedResponse {
            ok: true,
            banned_count: ips.len(),
            ips,
        }),
    )
}

async fn unban(state: AdminState, ip: IpAddr, password: String) -> impl IntoResponse {
    if !password_matches(&password, &state.password) {
        warn!(%ip, "admin unban request rejected because password was invalid");
        return (
            StatusCode::UNAUTHORIZED,
            Json(MessageResponse {
                ok: false,
                message: "invalid password".to_string(),
            }),
        );
    }

    match state.manager.unban_ip(ip).await {
        Ok(UnbanOutcome::Unbanned) => (
            StatusCode::OK,
            Json(MessageResponse {
                ok: true,
                message: format!("{ip} unbanned"),
            }),
        ),
        Ok(UnbanOutcome::NotBanned) => (
            StatusCode::NOT_FOUND,
            Json(MessageResponse {
                ok: false,
                message: format!("{ip} is not banned"),
            }),
        ),
        Err(error) => {
            error!(%ip, %error, "admin unban failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MessageResponse {
                    ok: false,
                    message: "failed to unban ip".to_string(),
                }),
            )
        }
    }
}

fn password_matches(provided: &str, expected: &str) -> bool {
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
    use super::password_matches;

    #[test]
    fn password_match_requires_exact_content() {
        assert!(password_matches("secret", "secret"));
        assert!(!password_matches("secret", "Secret"));
        assert!(!password_matches("secret", "secret!"));
        assert!(!password_matches("", "secret"));
    }
}
