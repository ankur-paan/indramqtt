use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

/// Lock-free node metrics. An instance lives in node `Shared` state and
/// is shared with the management API; per-instance (never global) so
/// multi-node in-process tests stay isolated.
#[derive(Debug, Default)]
pub struct Metrics {
    messages_received: AtomicU64,
    messages_forwarded: AtomicU64,
    rules_executed: AtomicU64,
    connections_active: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// One MQTT ingress message accepted over BrokerLink.
    pub fn inc_messages_received(&self) -> u64 {
        self.messages_received.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// One `PublishOut` frame emitted toward the edge.
    pub fn inc_messages_forwarded(&self) -> u64 {
        self.inc_messages_forwarded_by(1)
    }

    pub fn inc_messages_forwarded_by(&self, n: u64) -> u64 {
        self.messages_forwarded.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One rule whose filter matched at ingress (regardless of actions).
    pub fn inc_rules_executed(&self) -> u64 {
        self.inc_rules_executed_by(1)
    }

    pub fn inc_rules_executed_by(&self, n: u64) -> u64 {
        self.rules_executed.fetch_add(n, Ordering::Relaxed) + n
    }

    pub fn inc_connections(&self) -> i64 {
        self.connections_active.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn dec_connections(&self) -> i64 {
        self.connections_active.fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// Reconcile the gauge (e.g. after a state rebuild).
    pub fn set_active_connections(&self, count: u64) {
        self.connections_active
            .store(count as i64, Ordering::Relaxed);
    }

    pub fn messages_received(&self) -> u64 {
        self.messages_received.load(Ordering::Relaxed)
    }

    pub fn messages_forwarded(&self) -> u64 {
        self.messages_forwarded.load(Ordering::Relaxed)
    }

    pub fn rules_executed(&self) -> u64 {
        self.rules_executed.load(Ordering::Relaxed)
    }

    pub fn connections_active(&self) -> i64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render_prometheus_metrics(&self) -> String {
        format!(
            "# HELP indramqtt_messages_received_total Total MQTT ingress messages accepted over BrokerLink.\n\
             # TYPE indramqtt_messages_received_total counter\n\
             indramqtt_messages_received_total {}\n\
             # HELP indramqtt_messages_forwarded_total Total PublishOut frames emitted toward the edge.\n\
             # TYPE indramqtt_messages_forwarded_total counter\n\
             indramqtt_messages_forwarded_total {}\n\
             # HELP indramqtt_rules_executed_total Total ingress rules whose filter matched.\n\
             # TYPE indramqtt_rules_executed_total counter\n\
             indramqtt_rules_executed_total {}\n\
             # HELP indramqtt_connections_active Currently bound edge connections.\n\
             # TYPE indramqtt_connections_active gauge\n\
             indramqtt_connections_active {}\n",
            self.messages_received(),
            self.messages_forwarded(),
            self.rules_executed(),
            self.connections_active(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_counters_and_gauge() {
        let metrics = Metrics::new();
        assert_eq!(metrics.inc_messages_received(), 1);
        assert_eq!(metrics.inc_messages_received(), 2);
        assert_eq!(metrics.inc_messages_forwarded_by(5), 5);
        assert_eq!(metrics.inc_rules_executed_by(3), 3);
        assert_eq!(metrics.inc_connections(), 1);
        assert_eq!(metrics.inc_connections(), 2);
        assert_eq!(metrics.dec_connections(), 1);
        metrics.set_active_connections(42);
        assert_eq!(metrics.connections_active(), 42);

        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_messages_received_total 2\n"));
        assert!(text.contains("indramqtt_messages_forwarded_total 5\n"));
        assert!(text.contains("indramqtt_rules_executed_total 3\n"));
        assert!(text.contains("indramqtt_connections_active 42\n"));
        assert!(text.contains("# TYPE indramqtt_connections_active gauge\n"));
    }
}
