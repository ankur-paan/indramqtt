//! EMQX v5 REST API compatibility router for IndraMQTT.

pub mod auth;
pub mod clients;
pub mod gateways;
pub mod monitoring;
pub mod nodes;
pub mod retained;
pub mod rules;
pub mod schemas;
pub mod system;
pub mod unsupported;

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
        // Authentication (AuthN) Providers & Built-in DB Users
        .route(
            "/authentication",
            get(auth::list_authentication).post(auth::create_authentication),
        )
        .route(
            "/authentication/:id",
            get(auth::get_authentication)
                .put(auth::update_authentication)
                .delete(auth::delete_authentication),
        )
        .route(
            "/authentication/:id/users",
            get(auth::list_authn_users).post(auth::create_authn_user),
        )
        .route(
            "/authentication/:id/users/:user_id",
            put(auth::update_authn_user).delete(auth::delete_authn_user),
        )
        // Authorization (AuthZ / ACL)
        .route(
            "/authorization/sources",
            get(auth::list_authorization_sources),
        )
        .route(
            "/authorization/settings",
            get(auth::get_authorization_settings).put(auth::update_authorization_settings),
        )
        .route(
            "/authorization/cache",
            delete(auth::clear_authorization_cache),
        )
        .route(
            "/authorization/sources/:type/rules",
            get(auth::list_authz_rules).post(auth::create_authz_rule),
        )
        .route(
            "/authorization/sources/:type/rules/:index",
            delete(auth::delete_authz_rule),
        )
        // System & License
        .route("/license", get(system::get_license))
        .route("/license/setting", get(system::get_license_setting))
        .route(
            "/license/session_hwm_history",
            get(system::get_license_session_hwm_history),
        )
        .route("/telemetry/status", get(system::get_telemetry_status))
        .route("/sso", get(system::get_sso_status))
        .route("/configs", get(system::get_configs))
        .route("/api_key", get(system::list_api_keys))
        .route("/api_key_scopes", get(system::get_api_key_scopes))
        // Live Monitoring & Rates
        .route("/monitor_current", get(monitoring::monitor_current))
        .route(
            "/monitor",
            get(monitoring::monitor).delete(monitoring::clear_alarms),
        )
        .route("/stats", get(monitoring::get_stats))
        .route("/metrics", get(monitoring::get_metrics))
        .route(
            "/alarms",
            get(monitoring::get_alarms).delete(monitoring::clear_alarms),
        )
        .route(
            "/alarms/force_deactivate",
            post(monitoring::deactivate_alarm),
        )
        // Cluster & Nodes
        .route("/nodes", get(nodes::list_nodes))
        .route("/nodes/:node", get(nodes::get_node))
        .route("/nodes/:node/clients/:clientid", get(clients::get_client))
        .route("/cluster", get(nodes::get_cluster))
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
            "/clients/:clientid/unsubscribe",
            post(clients::client_unsubscribe),
        )
        .route(
            "/clients/:clientid/mqueue_messages",
            get(clients::get_client_mqueue),
        )
        .route(
            "/clients/:clientid/inflight_messages",
            get(clients::get_client_inflight),
        )
        .route("/subscriptions", get(clients::list_subscriptions))
        .route("/topics", get(clients::list_topics))
        .route("/publish", post(clients::publish_message))
        // Retained & Delayed
        .route(
            "/mqtt/retained",
            get(retained::list_retained).delete(retained::clear_retained),
        )
        .route(
            "/mqtt/retained/:topic",
            get(retained::list_retained).delete(retained::clear_retained),
        )
        .route(
            "/mqtt/delayed/messages",
            get(retained::list_delayed_messages),
        )
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
        .route("/rules/:id/test", post(rules::test_rule_sql))
        .route("/rules/test", post(rules::test_rule_sql))
        .route("/rule_test", post(rules::test_rule_sql))
        .route("/rule_events", get(rules::get_rule_events))
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
        .route("/connectors/:id/start", post(rules::start_connector))
        .route(
            "/connectors/:id/enable/:enable",
            put(rules::enable_connector),
        )
        .route("/connectors_probe", post(rules::probe_connector))
        // Actions & Sources
        .route(
            "/actions",
            get(rules::list_actions).post(rules::create_action),
        )
        .route("/actions_summary", get(rules::get_actions_summary))
        .route(
            "/actions/:id",
            get(rules::get_action)
                .put(rules::update_action)
                .delete(rules::delete_action),
        )
        .route("/actions/:id/start", post(rules::start_action))
        .route("/actions/:id/enable/:enable", put(rules::enable_action))
        .route("/actions/:id/metrics", get(rules::get_action_metrics))
        .route(
            "/actions/:id/metrics/reset",
            put(rules::reset_action_metrics),
        )
        .route("/action_types", get(rules::get_action_types))
        .route("/actions_probe", post(rules::probe_action))
        .route(
            "/sources",
            get(rules::list_sources).post(rules::create_source),
        )
        .route("/sources_summary", get(rules::get_sources_summary))
        .route(
            "/sources/:id",
            get(rules::get_source)
                .put(rules::update_source)
                .delete(rules::delete_source),
        )
        .route("/sources/:id/enable/:enable", put(rules::enable_source))
        .route("/sources/:id/metrics", get(rules::get_source_metrics))
        .route(
            "/sources/:id/metrics/reset",
            put(rules::reset_source_metrics),
        )
        .route("/sources_probe", post(rules::probe_source))
        // Schema API for dynamic UI forms
        .route("/schemas", get(schemas::list_schemas))
        .route("/schemas/:name", get(schemas::get_schema))
        // Schema Registry & Validation
        .route(
            "/schema_registry",
            get(rules::list_schemas).post(rules::create_schema),
        )
        .route(
            "/schema_registry/:name",
            get(rules::get_schema)
                .put(rules::update_schema)
                .delete(rules::delete_schema),
        )
        .route(
            "/schema_validations",
            get(rules::list_schema_validations)
                .post(rules::create_schema_validation)
                .put(rules::update_schema_validation),
        )
        .route(
            "/schema_validations/validation/:name",
            get(rules::get_schema_validation).delete(rules::delete_schema_validation),
        )
        .route(
            "/schema_validations/validation/:name/enable/:enable",
            post(rules::enable_schema_validation),
        )
        .route(
            "/schema_validations/validation/:name/metrics",
            get(rules::get_schema_validation_metrics),
        )
        .route(
            "/schema_validations/validation/:name/metrics/reset",
            post(rules::reset_schema_validation_metrics),
        )
        // Multi-Protocol Gateways
        .route("/gateways", get(gateways::list_gateways))
        .route("/gateway", get(gateways::list_gateways))
        .route(
            "/gateways/:name",
            get(gateways::get_gateway).put(gateways::update_gateway),
        )
        .route(
            "/gateway/:name",
            get(gateways::get_gateway).put(gateways::update_gateway),
        )
        .route(
            "/gateways/:name/enable/:enable",
            put(gateways::toggle_gateway_enable),
        )
        .route(
            "/gateways/:name/listeners",
            get(gateways::list_gateway_listeners).post(gateways::add_gateway_listener),
        )
        .route(
            "/gateways/:name/listeners/:listenerId",
            put(gateways::update_gateway_listener).delete(gateways::delete_gateway_listener),
        )
        .route(
            "/gateways/:name/clients",
            get(gateways::list_gateway_clients),
        )
        .route(
            "/gateways/:name/clients/:clientid",
            get(gateways::get_gateway_client),
        )
        .route(
            "/gateways/:name/clients/:clientid/subscriptions",
            get(gateways::get_gateway_client_subs),
        )
        // Network Listeners
        .route("/listeners", get(gateways::list_listeners))
        .route(
            "/listeners/:id",
            get(gateways::get_listener)
                .post(gateways::add_listener)
                .put(gateways::update_listener)
                .delete(gateways::delete_listener),
        )
        .route("/listeners/:id/:action", post(gateways::handle_listener))
        // Diagnostics: Slow Subscriptions, Log Trace & Topic Metrics
        .route(
            "/slow_subscriptions",
            get(gateways::list_slow_subscriptions).delete(gateways::clear_slow_subscriptions),
        )
        .route(
            "/slow_subscriptions/settings",
            get(gateways::get_slow_sub_settings).put(gateways::update_slow_sub_settings),
        )
        .route(
            "/trace",
            get(gateways::list_traces).post(gateways::create_trace),
        )
        .route("/trace/:name", delete(gateways::delete_trace))
        .route(
            "/trace/:name/log_detail",
            get(gateways::get_trace_log_detail),
        )
        .route("/trace/:name/log", get(gateways::get_trace_log))
        .route("/trace/:name/download", get(gateways::download_trace))
        .route("/trace/:name/stop", put(gateways::stop_trace))
        .route(
            "/mqtt/topic_metrics",
            get(gateways::list_topic_metrics).post(gateways::add_topic_metrics),
        )
        .route(
            "/mqtt/topic_metrics/:topic",
            get(gateways::get_topic_metric).delete(gateways::delete_topic_metrics),
        )
        .route(
            "/mqtt/topic_metrics/:topic/reset",
            put(gateways::reset_topic_metrics),
        )
        // Client Blocklist (Banned)
        .route(
            "/banned",
            get(gateways::list_banned)
                .post(gateways::create_banned)
                .delete(gateways::clear_banned),
        )
        .route("/banned/:as/:who", delete(gateways::delete_banned))
        // Unsupported / Not Yet Developed Notice Endpoints
        .route(
            "/ai/completion_profiles",
            get(unsupported::ai_not_developed).post(unsupported::ai_not_developed),
        )
        .route(
            "/ai/providers",
            get(unsupported::ai_not_developed).post(unsupported::ai_not_developed),
        )
        .route("/ai/models", post(unsupported::ai_not_developed))
        .route("/a2a/cards/list", get(unsupported::a2a_not_developed))
        .route(
            "/configs/a2a_registry",
            get(unsupported::a2a_config).put(unsupported::a2a_config),
        )
        .route(
            "/indra/extra_features",
            get(unsupported::indramqtt_extra_features),
        )
}
