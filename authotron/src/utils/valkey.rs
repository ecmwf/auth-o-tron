// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared explicit Valkey connector; policy and key namespaces belong to its callers.

use crate::config::ui::BrowserBackendConfig;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionError {
    Configuration,
    Unavailable,
}

/// Clones share one bounded connection manager; no Debug exposes connection credentials.
#[derive(Clone)]
pub(crate) struct ValkeyConnection {
    connection: redis::aio::ConnectionManager,
    timeout: Duration,
}

impl ValkeyConnection {
    pub(crate) async fn connect(settings: &BrowserBackendConfig) -> Result<Self, ConnectionError> {
        use ConnectionError::*;
        settings.validate().map_err(|_| Configuration)?;
        let BrowserBackendConfig::Valkey {
            url,
            password,
            connect_timeout_ms,
            operation_timeout_ms,
            ..
        } = settings
        else {
            return Err(Configuration);
        };
        let mut info: redis::ConnectionInfo = url.parse().map_err(|_| Configuration)?;
        info.redis.password = Some(password.clone());
        let client = redis::Client::open(info).map_err(|_| Configuration)?;
        let manager = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_millis(*connect_timeout_ms))
            .set_response_timeout(Duration::from_millis(*operation_timeout_ms))
            .set_number_of_retries(0);
        let connection = tokio::time::timeout(
            Duration::from_millis(*connect_timeout_ms),
            redis::aio::ConnectionManager::new_with_config(client, manager),
        )
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)?;
        let backend = Self {
            connection,
            timeout: Duration::from_millis(*operation_timeout_ms),
        };
        backend.query::<String>(&redis::cmd("PING")).await?;
        Ok(backend)
    }

    /// One command attempt with an operation deadline. Mutation failures may be ambiguous;
    /// callers must not blindly retry. No application command replay or memory fallback.
    pub(crate) async fn query<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, ConnectionError> {
        let mut connection = self.connection.clone();
        tokio::time::timeout(self.timeout, command.query_async(&mut connection))
            .await
            .map_err(|_| ConnectionError::Unavailable)?
            .map_err(|_| ConnectionError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> BrowserBackendConfig {
        BrowserBackendConfig::Valkey {
            url: "redis://127.0.0.1:1/0".into(),
            key_prefix: "authotron:test".into(),
            password: "fixture-only".into(),
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        }
    }

    #[tokio::test]
    async fn invalid_settings_fail_as_configuration_before_network_initialization() {
        assert_eq!(
            ValkeyConnection::connect(&BrowserBackendConfig::Memory {})
                .await
                .err(),
            Some(ConnectionError::Configuration)
        );
        for field in [
            "url",
            "key_prefix",
            "password",
            "connect_timeout_ms",
            "operation_timeout_ms",
        ] {
            let mut config = settings();
            let BrowserBackendConfig::Valkey {
                url,
                key_prefix,
                password,
                connect_timeout_ms,
                operation_timeout_ms,
            } = &mut config
            else {
                unreachable!()
            };
            match field {
                "url" => *url = "redis://user:secret@127.0.0.1:1/0".into(),
                "key_prefix" => *key_prefix = "invalid prefix".into(),
                "password" => *password = " ".into(),
                "connect_timeout_ms" => *connect_timeout_ms = 0,
                _ => *operation_timeout_ms = 10001,
            }
            assert_eq!(
                ValkeyConnection::connect(&config).await.err(),
                Some(ConnectionError::Configuration),
                "{field}"
            );
        }
        let mut config = settings();
        let BrowserBackendConfig::Valkey { url, .. } = &mut config else {
            unreachable!()
        };
        *url = "rediss://valkey.example.org:6379/0".into();
        assert!(config.validate().is_ok());
    }
}
