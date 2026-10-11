use super::{BrowserVerifyError, opaque_id};
use crate::config::ui::BrowserBackendConfig;
use std::time::Duration;

#[derive(Clone)]
pub(super) struct Valkey {
    connection: redis::aio::ConnectionManager,
    prefix: String,
    timeout: Duration,
}

impl Valkey {
    pub async fn connect(settings: &BrowserBackendConfig) -> Result<Self, BrowserVerifyError> {
        let BrowserBackendConfig::Valkey {
            url,
            key_prefix,
            password,
            connect_timeout_ms,
            operation_timeout_ms,
        } = settings
        else {
            return Err(BrowserVerifyError::Unavailable);
        };
        let mut info: redis::ConnectionInfo =
            url.parse().map_err(|_| BrowserVerifyError::Unavailable)?;
        info.redis.password = Some(password.clone());
        let client = redis::Client::open(info).map_err(|_| BrowserVerifyError::Unavailable)?;
        let manager = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_millis(*connect_timeout_ms))
            .set_response_timeout(Duration::from_millis(*operation_timeout_ms))
            .set_number_of_retries(0);
        let connection = tokio::time::timeout(
            Duration::from_millis(*connect_timeout_ms),
            redis::aio::ConnectionManager::new_with_config(client, manager),
        )
        .await
        .map_err(|_| BrowserVerifyError::Unavailable)?
        .map_err(|_| BrowserVerifyError::Unavailable)?;
        let backend = Self {
            connection,
            prefix: key_prefix.clone(),
            timeout: Duration::from_millis(*operation_timeout_ms),
        };
        let mut connection = backend.connection.clone();
        tokio::time::timeout(
            backend.timeout,
            redis::cmd("PING").query_async::<String>(&mut connection),
        )
        .await
        .map_err(|_| BrowserVerifyError::Unavailable)?
        .map_err(|_| BrowserVerifyError::Unavailable)?;
        Ok(backend)
    }

    pub async fn call(&self, args: &[String]) -> Result<Vec<String>, BrowserVerifyError> {
        let mut connection = self.connection.clone();
        let mut command = redis::cmd("EVAL");
        command
            .arg(include_str!("valkey.lua"))
            .arg(1)
            .arg(&self.prefix)
            .arg(args);
        tokio::time::timeout(self.timeout, command.query_async(&mut connection))
            .await
            .map_err(|_| BrowserVerifyError::Unavailable)?
            .map_err(|_| BrowserVerifyError::Unavailable)
    }

    pub async fn admit(
        &self,
        limit: usize,
        window: u64,
        cap: usize,
        deadline: u64,
    ) -> Result<Lease, BrowserVerifyError> {
        let id = opaque_id();
        let result = self
            .call(&[
                "admit".into(),
                id.clone(),
                limit.to_string(),
                (window * 1000).to_string(),
                cap.to_string(),
                ((deadline + 2) * 1000).to_string(),
            ])
            .await?;
        if result.first().map(String::as_str) != Some("ok") {
            return Err(BrowserVerifyError::Limited);
        }
        Ok(Lease {
            backend: self.clone(),
            id,
            expires: result[1].clone(),
            released: false,
        })
    }

    pub async fn quota(&self, limit: usize, window: u64) -> Result<(), BrowserVerifyError> {
        let result = self
            .call(&[
                "quota".into(),
                "".into(),
                limit.to_string(),
                (window * 1000).to_string(),
            ])
            .await?;
        match result.first().map(String::as_str) {
            Some("ok") => Ok(()),
            Some("limited") => Err(BrowserVerifyError::Limited),
            _ => Err(BrowserVerifyError::Unavailable),
        }
    }
}

pub(super) struct Lease {
    backend: Valkey,
    id: String,
    expires: String,
    released: bool,
}

impl Lease {
    pub async fn release(&mut self) -> Result<(), BrowserVerifyError> {
        self.backend
            .call(&["release".into(), self.id.clone(), self.expires.clone()])
            .await?;
        self.released = true;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.released {
            let backend = self.backend.clone();
            let args = ["release".into(), self.id.clone(), self.expires.clone()];
            // Only bounded cleanup is detached; verification itself stays in the request.
            tokio::spawn(async move {
                let _ = backend.call(&args).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BrowserLoginState, LoginFlow};
    use super::*;
    use crate::{config::ConfigV2, models::user::User};
    use std::{process::Command, sync::Arc};

    struct Fixture(String);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }

    fn docker(args: &[&str]) -> String {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI required for disposable Valkey tests");
        assert!(
            output.status.success(),
            "Docker fixture command failed; check daemon and valkey/valkey:8 image availability"
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    async fn command<T: redis::FromRedisValue>(backend: &Valkey, name: &str, args: &[&str]) -> T {
        redis::cmd(name)
            .arg(args)
            .query_async(&mut backend.connection.clone())
            .await
            .unwrap()
    }

    fn config(url: &str, prefix: &str) -> ConfigV2 {
        serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "fixture", "realm": "fixture", "users": [{"username": "alice", "password": "public-fixture", "roles": ["reader"]}]}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "public-test-only"},
            "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "basic": {"provider_name": "fixture"}, "browser_session": {
                "public_origin": "https://login.example.test", "transaction_ttl_seconds": 45, "max_forms": 2, "max_sessions": 1,
                "max_forms_per_window": 100, "max_logins_per_window": 100, "max_inflight_logins": 1,
                "max_shared_inflight_logins": 1,
                "backend": {"type": "valkey", "url": url, "key_prefix": prefix, "password": "public-disposable-fixture"}
            }}
        })).unwrap()
    }

    async fn state(url: &str, prefix: &str) -> Arc<BrowserLoginState> {
        let mut state = BrowserLoginState::new(&config(url, prefix)).unwrap();
        state.initialize(true).await.unwrap();
        Arc::new(state)
    }

    fn user() -> User {
        User::new("fixture".into(), "alice".into(), None, None, None, None)
    }

    #[tokio::test]
    async fn api_only_and_ui_without_direct_login_never_connect_to_valkey() {
        let mut disabled = config("redis://127.0.0.1:1/0", "api-only");
        disabled.ui.enabled = false;
        let _ = crate::startup::build_app(Arc::new(disabled)).await.unwrap();
        let mut chooser = config("redis://127.0.0.1:1/0", "chooser");
        chooser.ui.basic = None;
        let _ = crate::startup::build_app(Arc::new(chooser)).await.unwrap();
    }

    #[tokio::test]
    async fn memory_honors_optional_cap_within_its_single_instance() {
        let mut cfg = config("redis://127.0.0.1:1/0", "memory");
        let settings = cfg.ui.browser_session.as_mut().unwrap();
        settings.backend = BrowserBackendConfig::Memory {};
        settings.max_inflight_logins = 2;
        let state = Arc::new(BrowserLoginState::new(&cfg).unwrap());
        let task = {
            let state = state.clone();
            tokio::spawn(async move { state.admitted(std::future::pending()).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            state.admitted(async { Ok(user()) }).await,
            Err(BrowserVerifyError::Limited)
        ));
        task.abort();
        let _ = task.await;
        assert!(state.admitted(async { Ok(user()) }).await.is_ok());
    }
}
