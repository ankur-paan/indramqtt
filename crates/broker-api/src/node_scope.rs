//! Single-node scope check for `/nodes/{node}/...` routes.
//!
//! Node-scoped routes must 404 `NOT_FOUND` for unknown nodes. This broker
//! is single-node first: the helper compares the requested `{node}` segment
//! against the one local node name with an exact, case-sensitive match.
//!
//! Single-node contract: callers pass the kernel's `--node-id` (default
//! `indra-node-1` per `broker-node/src/main.rs:49-51`) as `local` once W0-19
//! exposes it; until then callers pass the literal they already use (for
//! example the `"indramqtt@127.0.0.1"` literal rendered by
//! `v5::nodes::list_nodes`). No caller migration happens in this task.

use crate::errors::EmqxError;

/// Resolve a requested node name against the local node name.
///
/// Returns `Ok(())` only on an exact, case-sensitive match. Anything else
/// (unknown names, empty strings, differently-cased names, prefix matches)
/// returns 404 `NOT_FOUND` naming the unknown node.
pub fn resolve_node(local: &str, requested: &str) -> Result<(), EmqxError> {
    if requested == local && !requested.is_empty() {
        Ok(())
    } else {
        Err(EmqxError::NotFound(format!("node not found: {requested}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_local_name_resolves() {
        assert!(resolve_node("indra-node-1", "indra-node-1").is_ok());
    }

    #[test]
    fn unknown_name_yields_not_found() {
        let err = resolve_node("indra-node-1", "other-node").unwrap_err();
        assert_eq!(err.code(), "NOT_FOUND");
        assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
        assert!(
            err.message().contains("other-node"),
            "message names the unknown node: {}",
            err.message()
        );
    }

    #[test]
    fn empty_and_differently_cased_names_yield_not_found() {
        for requested in [
            "",
            "INDRA-NODE-1",
            "Indra-Node-1",
            "indra-node-1-extra",
            "indra-node-",
        ] {
            let err = resolve_node("indra-node-1", requested).unwrap_err();
            assert_eq!(err.code(), "NOT_FOUND", "requested: {requested:?}");
            assert_eq!(
                err.status_code(),
                axum::http::StatusCode::NOT_FOUND,
                "requested: {requested:?}"
            );
        }
    }
}
