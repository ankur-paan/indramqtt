use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Invalid QoS level: {0}")]
    InvalidQoS(u8),

    #[error("Invalid topic: {0}")]
    InvalidTopic(String),

    #[error("Topic contains empty level")]
    EmptyTopicLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl TryFrom<u8> for QoS {
    type Error = ProtocolError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::AtMostOnce),
            1 => Ok(Self::AtLeastOnce),
            2 => Ok(Self::ExactlyOnce),
            other => Err(ProtocolError::InvalidQoS(other)),
        }
    }
}

impl From<QoS> for u8 {
    fn from(qos: QoS) -> Self {
        qos as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Topic(String);

impl Topic {
    pub fn new(topic: impl Into<String>) -> Result<Self, ProtocolError> {
        let t = topic.into();
        Self::validate(&t)?;
        Ok(Self(t))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(topic: &str) -> Result<(), ProtocolError> {
        if topic.is_empty() {
            return Err(ProtocolError::InvalidTopic(
                "topic cannot be empty".to_string(),
            ));
        }
        if topic.contains('+') || topic.contains('#') {
            return Err(ProtocolError::InvalidTopic(
                "concrete topic cannot contain wildcards".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TopicFilter(String);

impl TopicFilter {
    pub fn new(filter: impl Into<String>) -> Result<Self, ProtocolError> {
        let f = filter.into();
        Self::validate(&f)?;
        Ok(Self(f))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(filter: &str) -> Result<(), ProtocolError> {
        if filter.is_empty() {
            return Err(ProtocolError::InvalidTopic(
                "filter cannot be empty".to_string(),
            ));
        }
        // Multi-level wildcard '#' can only appear as the last character or preceded by '/'
        if let Some(pos) = filter.find('#') {
            if pos != filter.len() - 1 {
                return Err(ProtocolError::InvalidTopic(
                    "'#' wildcard must be the final level".to_string(),
                ));
            }
            if pos > 0 && &filter[pos - 1..pos] != "/" {
                return Err(ProtocolError::InvalidTopic(
                    "'#' wildcard must be prefixed with '/'".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn matches(&self, topic: &Topic) -> bool {
        let filter_levels: Vec<&str> = self.0.split('/').collect();
        let topic_levels: Vec<&str> = topic.as_str().split('/').collect();

        let mut t_idx = 0;
        for (f_idx, &f_part) in filter_levels.iter().enumerate() {
            if f_part == "#" {
                return true;
            }

            if t_idx >= topic_levels.len() {
                return false;
            }

            if f_part == "+" || f_part == topic_levels[t_idx] {
                t_idx += 1;
            } else {
                return false;
            }

            if f_idx == filter_levels.len() - 1 && t_idx < topic_levels.len() {
                return false;
            }
        }

        t_idx == topic_levels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_conversion() {
        assert_eq!(QoS::try_from(0).unwrap(), QoS::AtMostOnce);
        assert_eq!(QoS::try_from(1).unwrap(), QoS::AtLeastOnce);
        assert_eq!(QoS::try_from(2).unwrap(), QoS::ExactlyOnce);
        assert!(QoS::try_from(3).is_err());
    }

    #[test]
    fn test_topic_matching() {
        let t1 = Topic::new("sensors/temperature/living_room").unwrap();
        let f1 = TopicFilter::new("sensors/temperature/+").unwrap();
        let f2 = TopicFilter::new("sensors/#").unwrap();
        let f3 = TopicFilter::new("sensors/humidity/+").unwrap();
        let f4 = TopicFilter::new("#").unwrap();

        assert!(f1.matches(&t1));
        assert!(f2.matches(&t1));
        assert!(!f3.matches(&t1));
        assert!(f4.matches(&t1));
    }
}
