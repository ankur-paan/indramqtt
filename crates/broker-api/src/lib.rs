use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .route("/api/v1/metrics", get(|| async { "metrics_placeholder" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_router_health() {
        let _app = router();
        assert!(true);
    }
}
