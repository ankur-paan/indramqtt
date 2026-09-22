//! v5 REST API compatibility router for IndraMQTT.

pub mod alarms;
pub mod auth;
pub mod auto_subscribe;
pub mod banned;
pub mod clients;
pub mod gateways;
pub mod monitor;
pub mod monitoring;
pub mod nodes;
pub mod retainer;
pub mod rules;
pub mod schemas;
pub mod slow_subscriptions;
pub mod status;
pub mod trace;
pub mod tracing;

use crate::ApiState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};

/// Public `/api/v5/*` endpoints: login only. These stay outside the
/// authentication middleware; everything else requires a bearer token.
pub fn public_router() -> Router<ApiState> {
    Router::new()
        .route("/login/challenge", post(auth::scram_challenge))
        .route("/login/verify", post(auth::scram_verify))
        .route("/login", post(auth::direct_login))
}

/// Authenticated `/api/v5/*` endpoints. Served behind the
/// [`crate::api_auth::require_api_auth`] middleware.
pub fn protected_router() -> Router<ApiState> {
    Router::new()
        // Auth & Identity
        .route("/logout", post(auth::logout))
        .route("/current_user", get(auth::current_user))
        .route("/user_scopes", get(auth::user_scopes))
        .route("/users", get(auth::list_users).post(auth::create_user))
        .route(
            "/users/:username",
            delete(auth::delete_user).put(auth::update_user),
        )
        .route(
            "/users/:username/change_pwd",
            put(auth::change_user_password).post(auth::change_user_password),
        )
        // Authentication (AuthN) built-in-database users
        .route(
            "/authentication/:id/users",
            get(auth::list_authn_users).post(auth::create_authn_user),
        )
        .route(
            "/authentication/:id/users/:user_id",
            put(auth::update_authn_user).delete(auth::delete_authn_user),
        )
        // Authorization (AuthZ / ACL) rules
        .route(
            "/authorization/sources/:type/rules",
            get(auth::list_authz_rules).post(auth::create_authz_rule),
        )
        .route(
            "/authorization/sources/:type/rules/:index",
            delete(auth::delete_authz_rule),
        )
        // Live Monitoring & Rates
        .route("/metrics", get(monitoring::get_metrics))
        .route(
            "/monitor",
            get(monitor::list_monitor).delete(monitor::clear_monitor),
        )
        .route("/monitor/nodes/:node", get(monitor::get_monitor_node))
        .route("/monitor_current", get(monitoring::monitor_current))
        .route(
            "/monitor_current/nodes/:node",
            get(monitoring::monitor_current_node),
        )
        .route("/stats", get(monitoring::get_stats))
        .route("/status", get(status::get_status))
        .route(
            "/mqtt/auto_subscribe",
            get(auto_subscribe::get_auto_subscribe).put(auto_subscribe::put_auto_subscribe),
        )
        .route(
            "/mqtt/retainer",
            get(retainer::get_retainer_config).put(retainer::put_retainer_config),
        )
        .route(
            "/mqtt/retainer/message/:topic",
            get(retainer::get_retainer_message).delete(retainer::delete_retainer_message),
        )
        .route(
            "/mqtt/retainer/messages",
            get(retainer::list_retainer_messages).delete(retainer::clear_retainer_messages),
        )
        .route(
            "/slow_subscriptions",
            get(slow_subscriptions::list_slow_subscriptions)
                .delete(slow_subscriptions::clear_slow_subscriptions),
        )
        .route(
            "/slow_subscriptions/settings",
            get(slow_subscriptions::get_slow_subs_settings)
                .put(slow_subscriptions::put_slow_subs_settings),
        )
        .route(
            "/tracing",
            get(tracing::get_tracing).put(tracing::put_tracing),
        )
        .route(
            "/trace",
            get(trace::list_traces)
                .post(trace::create_trace)
                .delete(trace::clear_traces),
        )
        .route("/trace/:name", delete(trace::delete_trace))
        .route("/trace/:name/stop", put(trace::stop_trace))
        .route("/trace/:name/download", get(trace::download_trace))
        .route("/trace/:name/log", get(trace::get_trace_log))
        .route("/trace/:name/log_detail", get(trace::get_trace_log_detail))
        // Cluster & Nodes
        .route("/nodes", get(nodes::list_nodes))
        .route("/nodes/:node", get(nodes::get_node))
        .route("/nodes/:node/metrics", get(monitoring::get_metrics_node))
        .route("/nodes/:node/stats", get(monitoring::get_stats_node))
        .route("/nodes/:node/clients/:clientid", get(clients::get_client))
        // Clients & Subscriptions
        .route("/clients", get(clients::list_clients))
        .route("/clients_v2", get(clients::list_clients))
        .route("/clients/kickout/bulk", post(clients::batch_kick_clients))
        .route(
            "/clients/:clientid",
            get(clients::get_client).delete(clients::kick_client),
        )
        .route(
            "/clients/:clientid/subscriptions",
            get(clients::get_client_subscriptions),
        )
        .route(
            "/clients/:clientid/subscribe",
            post(clients::client_subscribe),
        )
        .route(
            "/clients/:clientid/subscribe/bulk",
            post(clients::bulk_subscribe),
        )
        .route(
            "/clients/:clientid/unsubscribe",
            post(clients::client_unsubscribe),
        )
        .route(
            "/clients/:clientid/unsubscribe/bulk",
            post(clients::bulk_unsubscribe),
        )
        .route(
            "/clients/:clientid/mqueue_messages",
            get(clients::get_client_mqueue),
        )
        .route(
            "/clients/:clientid/inflight_messages",
            get(clients::get_client_inflight),
        )
        .route(
            "/banned",
            get(banned::list_banned)
                .post(banned::create_banned)
                .delete(banned::clear_banned),
        )
        .route("/banned/:as/:who", delete(banned::delete_banned_one))
        .route(
            "/alarms",
            get(alarms::list_alarms).delete(alarms::clear_alarms),
        )
        .route("/alarms/force_deactivate", post(alarms::force_deactivate))
        .route("/subscriptions", get(clients::list_subscriptions))
        .route("/topics", get(clients::list_topics))
        .route("/topics/:topic", get(clients::get_topic))
        .route("/sessions_count", get(clients::get_sessions_count))
        .route("/publish", post(clients::publish_message))
        .route("/publish/bulk", post(clients::publish_bulk))
        // Rules, Flow Designer & Connectors
        .route("/rules", get(rules::list_rules).post(rules::create_rule))
        .route(
            "/rules/:id",
            get(rules::get_rule)
                .put(rules::update_rule)
                .delete(rules::delete_rule),
        )
        .route("/rules/:id/metrics", get(rules::get_rule_metrics))
        .route("/rules/:id/metrics/reset", put(rules::reset_rule_metrics))
        .route(
            "/connectors",
            get(rules::list_connectors).post(rules::create_connector),
        )
        .route(
            "/connectors/:id",
            get(rules::get_connector)
                .put(rules::update_connector)
                .delete(rules::delete_connector),
        )
        .route("/connectors_probe", post(rules::probe_connector))
        // Actions & Sources
        .route("/action_types", get(rules::get_action_types))
        .route("/actions_probe", post(rules::probe_action))
        // Schema API for dynamic UI forms
        .route("/schemas", get(schemas::list_schemas))
        .route("/schemas/:name", get(schemas::get_schema))
}
