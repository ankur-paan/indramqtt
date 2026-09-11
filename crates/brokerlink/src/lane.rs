use std::sync::Arc;
use crate::error::Result;
use crate::frame::BrokerFrame;
use crate::transport::BrokerLinkTransport;

/// Multi-lane dispatcher for parallel BrokerLink IPC channels.
///
/// Ensures frames with the same `conn_id` are consistently routed to the same
/// execution lane, preserving strict FIFO ordering per MQTT connection without
/// causing head-of-line blocking across distinct connections.
#[derive(Clone)]
pub struct LaneDispatcher {
    lanes: Vec<Arc<dyn BrokerLinkTransport>>,
}

impl LaneDispatcher {
    pub fn new(lanes: Vec<Arc<dyn BrokerLinkTransport>>) -> Self {
        assert!(!lanes.is_empty(), "LaneDispatcher requires at least one lane");
        Self { lanes }
    }

    #[inline]
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    #[inline]
    pub fn lane_for_conn(&self, conn_id: u64) -> usize {
        (conn_id as usize) % self.lanes.len()
    }

    pub fn get_lane(&self, conn_id: u64) -> Arc<dyn BrokerLinkTransport> {
        let idx = self.lane_for_conn(conn_id);
        self.lanes[idx].clone()
    }

    pub async fn dispatch(&self, frame: BrokerFrame) -> Result<()> {
        let lane = self.get_lane(frame.header.conn_id);
        lane.send(frame).await
    }
}
