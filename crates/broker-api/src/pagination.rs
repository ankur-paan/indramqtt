//! Shared server-side pagination with EMQX semantics.
//!
//! Every list endpoint paginates with `page` / `limit` query parameters and
//! reports `meta { page, limit, count, hasnext }`. This module is the single
//! place that behaviour lives so handlers cannot drift (wrong defaults,
//! renamed params, or paginating before filtering).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

/// EMQX default page: the first page.
pub const DEFAULT_PAGE: u32 = 1;
/// EMQX default limit: 100 rows per page.
pub const DEFAULT_LIMIT: u32 = 100;
/// Upper bound for `limit`; larger values are clamped, never rejected.
pub const MAX_LIMIT: u32 = 1000;

/// Parsed `page` / `limit` query parameters.
///
/// Axum extractor: reads `page` and `limit` from the query string, falling
/// back to [`DEFAULT_PAGE`] / [`DEFAULT_LIMIT`] when absent or malformed
/// (never rejects with 400). `limit` is clamped to `1..=1000` and `page`
/// to `>= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageParams {
    /// 1-based page number, always `>= 1`.
    pub page: u32,
    /// Rows per page, always `1..=1000`.
    pub limit: u32,
}

impl Default for PageParams {
    fn default() -> Self {
        Self {
            page: DEFAULT_PAGE,
            limit: DEFAULT_LIMIT,
        }
    }
}

impl PageParams {
    /// Parse from a raw query string (without the leading `?`).
    fn from_query(query: Option<&str>) -> Self {
        let mut page = DEFAULT_PAGE;
        let mut limit = DEFAULT_LIMIT;
        if let Some(query) = query {
            for pair in query.split('&') {
                let Some((key, value)) = pair.split_once('=') else {
                    continue;
                };
                match key {
                    "page" => {
                        if let Ok(parsed) = value.parse::<u32>() {
                            page = parsed;
                        }
                    }
                    "limit" => {
                        if let Ok(parsed) = value.parse::<u32>() {
                            limit = parsed;
                        }
                    }
                    _ => {}
                }
            }
        }
        Self {
            page: page.max(1),
            limit: limit.clamp(1, MAX_LIMIT),
        }
    }
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for PageParams
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_query(parts.uri.query()))
    }
}

/// Contract for `meta`: `count` is the total number of rows AFTER filtering
/// and `hasnext` reports whether more rows exist beyond this page, i.e.
/// `(page * limit) < count` computed in `u64` arithmetic so large pages
/// cannot overflow. The returned value is exactly
/// `{ page, limit, count, hasnext }`.
pub fn meta_page(page: u32, limit: u32, count: usize) -> serde_json::Value {
    let covered = u64::from(page) * u64::from(limit);
    serde_json::json!({
        "page": page,
        "limit": limit,
        "count": count,
        "hasnext": covered < count as u64,
    })
}

/// Alias kept for the name used in the task brief; identical to
/// [`meta_page`].
pub fn meta(page: u32, limit: u32, count: usize) -> serde_json::Value {
    meta_page(page, limit, count)
}

/// Slice the requested page out of the fully filtered row set.
///
/// Callers must filter first, then call this: slicing after filtering is
/// what makes paginate-before-filter bugs impossible by construction.
/// `page` is 1-based (values `< 1` are treated as 1); out-of-range pages
/// yield an empty slice. Uses `u64` arithmetic so large pages cannot
/// overflow.
pub fn paginate<T: Clone>(items: &[T], page: u32, limit: u32) -> &[T] {
    let page = page.max(1);
    if limit == 0 || items.is_empty() {
        return &[];
    }
    let start = ((u64::from(page) - 1) * u64::from(limit)).min(items.len() as u64) as usize;
    let end = (start as u64 + u64::from(limit)).min(items.len() as u64) as usize;
    &items[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    async fn extract(uri: &str) -> PageParams {
        let req = Request::builder().uri(uri).body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        PageParams::from_request_parts(&mut parts, &())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn defaults_when_no_query_string() {
        let params = extract("/api/v5/clients").await;
        assert_eq!(params.page, 1);
        assert_eq!(params.limit, 100);
    }

    #[tokio::test]
    async fn parses_page_and_limit() {
        let params = extract("/api/v5/clients?page=2&limit=10").await;
        assert_eq!(params.page, 2);
        assert_eq!(params.limit, 10);
    }

    #[tokio::test]
    async fn limit_is_clamped_to_bounds() {
        let low = extract("/api/v5/clients?limit=0").await;
        assert_eq!(low.limit, 1);
        let high = extract("/api/v5/clients?limit=99999").await;
        assert_eq!(high.limit, 1000);
    }

    #[tokio::test]
    async fn malformed_page_falls_back_to_default() {
        let params = extract("/api/v5/clients?page=abc&limit=10").await;
        assert_eq!(params.page, 1);
        assert_eq!(params.limit, 10);
    }

    #[tokio::test]
    async fn malformed_limit_falls_back_to_default() {
        let params = extract("/api/v5/clients?page=3&limit=xyz").await;
        assert_eq!(params.page, 3);
        assert_eq!(params.limit, 100);
    }

    #[test]
    fn paginate_slices_second_page_after_filtering() {
        let items: Vec<u32> = (0..25).collect();
        let page = paginate(&items, 2, 10);
        let expected: Vec<u32> = (10..20).collect();
        assert_eq!(page, expected.as_slice());
    }

    #[test]
    fn meta_page_reports_hasnext_at_boundary() {
        let more = meta_page(2, 10, 25);
        assert_eq!(
            more,
            serde_json::json!({"page": 2, "limit": 10, "count": 25, "hasnext": true})
        );
        let exact = meta_page(3, 10, 30);
        assert_eq!(
            exact,
            serde_json::json!({"page": 3, "limit": 10, "count": 30, "hasnext": false})
        );
        let alias = meta(2, 10, 25);
        assert_eq!(alias, more);
    }
}
