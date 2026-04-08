//! Health check endpoint.

use axum::{extract::State, Json};
use std::sync::Arc;

use crate::api::state::ApiState;
use crate::api::types::{HealthResponse, MachineCountsResponse};

/// Server start time for uptime calculation.
static SERVER_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Record the server start time. Call once at startup.
pub fn mark_server_start() {
    let _ = SERVER_START.set(std::time::Instant::now());
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Server is healthy", body = HealthResponse)
    )
)]
pub async fn health(state: Option<State<Arc<ApiState>>>) -> Json<HealthResponse> {
    let (machines, uptime) = match state {
        Some(State(s)) => {
            let counts = s.machine_counts();
            (
                Some(MachineCountsResponse {
                    total: counts.0,
                    running: counts.1,
                }),
                SERVER_START.get().map(|t| t.elapsed().as_secs()),
            )
        }
        None => (None, None),
    };

    Json(HealthResponse {
        status: "ok",
        version: crate::VERSION,
        machines,
        uptime_seconds: uptime,
    })
}
