use async_trait::async_trait;
use broker_protocol::{Topic, TopicFilter};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication failed for client {0}")]
    AuthenticationFailed(String),

    #[error("Permission denied: cannot publish to {0}")]
    PublishDenied(String),

    #[error("Permission denied: cannot subscribe to {0}")]
    SubscribeDenied(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()>;
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()>;
    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()>;
}

#[derive(Default)]
pub struct AllowAllAuth;

#[async_trait]
impl Authenticator for AllowAllAuth {
    async fn authenticate(
        &self,
        _client_id: &str,
        _username: Option<&str>,
        _password: Option<&[u8]>,
    ) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Authorizer for AllowAllAuth {
    async fn authorize_publish(&self, _client_id: &str, _topic: &Topic) -> Result<()> {
        Ok(())
    }

    async fn authorize_subscribe(&self, _client_id: &str, _filter: &TopicFilter) -> Result<()> {
        Ok(())
    }
}
