use super::{BrowserVerifyError, opaque_id};
use crate::config::ui::BrowserBackendConfig;
use crate::utils::valkey::ValkeyConnection;
#[cfg(test)]
use std::time::Duration;

#[derive(Clone)]
pub(super) struct Valkey {
    connection: ValkeyConnection,
    prefix: String,
}

impl Valkey {
    pub async fn connect(settings: &BrowserBackendConfig) -> Result<Self, BrowserVerifyError> {
        let BrowserBackendConfig::Valkey { key_prefix, .. } = settings else {
            return Err(BrowserVerifyError::Unavailable);
        };
        let connection = ValkeyConnection::connect(settings)
            .await
            .map_err(|_| BrowserVerifyError::Unavailable)?;
        Ok(Self {
            connection,
            prefix: key_prefix.clone(),
        })
    }

    pub async fn call(&self, args: &[String]) -> Result<Vec<String>, BrowserVerifyError> {
        let mut command = redis::cmd("EVAL");
        command
            .arg(include_str!("valkey.lua"))
            .arg(1)
            .arg(&self.prefix)
            .arg(args);
        self.connection
            .query(&command)
            .await
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
        backend
            .connection
            .query(redis::cmd(name).arg(args))
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

    /// Run explicitly: cargo test -p authotron disposable_valkey -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_atomic_cross_replica_expiry_quota_leases_and_outage() {
        let fixture = Fixture(docker(&[
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::6379",
            "valkey/valkey:8",
            "valkey-server",
            "--requirepass",
            "public-disposable-fixture",
            "--save",
            "",
            "--appendonly",
            "no",
        ]));
        let address = docker(&["port", &fixture.0, "6379/tcp"]);
        let url = format!("redis://{address}/0");
        let prefix = "authotron:browser:v1:test";
        let settings = config(&url, prefix).ui.browser_session.unwrap().backend;
        let mut ready = false;
        for _ in 0..100 {
            if Valkey::connect(&settings).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "disposable Valkey did not become ready");
        let a = state(&url, prefix).await;
        let b = state(&url, prefix).await;
        let backend = a.valkey.as_ref().unwrap();

        let (sid, csrf) = a.form(LoginFlow::Basic).await.unwrap();
        assert!(
            !b.consume(&sid, &"a".repeat(64), LoginFlow::Basic)
                .await
                .unwrap()
        );
        assert!(!b.consume(&sid, &csrf, LoginFlow::ApiKey).await.unwrap());
        let (left, right) = tokio::join!(
            a.consume(&sid, &csrf, LoginFlow::Basic),
            b.consume(&sid, &csrf, LoginFlow::Basic)
        );
        assert_ne!(
            left.unwrap(),
            right.unwrap(),
            "exactly one atomic consumer wins"
        );
        let (f1, _) = a.form(LoginFlow::Basic).await.unwrap();
        let (f2, _) = b.form(LoginFlow::ApiKey).await.unwrap();
        assert!(matches!(
            a.form(LoginFlow::Basic).await,
            Err(BrowserVerifyError::Capacity)
        ));
        b.discard(&f1).await.unwrap();
        a.discard(&f2).await.unwrap();

        let (left, right) =
            tokio::join!(a.save_session(user(), None), b.save_session(user(), None));
        assert_ne!(left.is_ok(), right.is_ok(), "one atomic capacity winner");
        let winner = left.or(right).unwrap();
        let _: usize = command(
            backend,
            "DEL",
            &[
                &format!("{prefix}:session:{winner}"),
                &format!("{prefix}:sessions"),
            ],
        )
        .await;

        let sid = a.save_session(user(), None).await.unwrap();
        let expiry = b.lookup(&sid).await.unwrap().unwrap().expires_at;
        let ttl1: i64 = command(backend, "PTTL", &[&format!("{prefix}:session:{sid}")]).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(a.lookup(&sid).await.unwrap().unwrap().expires_at, expiry);
        let ttl2: i64 = command(backend, "PTTL", &[&format!("{prefix}:session:{sid}")]).await;
        assert!(ttl2 < ttl1, "reads never extend expiry");
        assert!(matches!(
            b.save_session(user(), None).await,
            Err(BrowserVerifyError::Capacity)
        ));
        let mut oversized = user();
        oversized.username = "x".repeat(257);
        assert!(b.save_session(oversized, Some(&sid)).await.is_err());
        assert!(a.lookup(&sid).await.unwrap().is_some());
        let rotated = b.save_session(user(), Some(&sid)).await.unwrap();
        assert_ne!(rotated, sid);
        assert!(a.lookup(&sid).await.unwrap().is_none());

        // Corrupt/hostile values are rejected, including STRLEN guarding the large value.
        let key = format!("{prefix}:session:{rotated}");
        for payload in [
            "2\n9999999999999\n{}".to_owned(),
            "1\n9999999999999\ninvalid-json".to_owned(),
            "1\n9999999999999\n{\"version\":2,\"username\":\"alice\",\"realm\":\"fixture\",\"roles\":[],\"attributes\":{}}".to_owned(),
            "1\n9999999999999\n{\"version\":1,\"username\":\"alice\",\"realm\":\"fixture\",\"roles\":[],\"attributes\":{},\"password\":\"hostile\"}".to_owned(),
            "x".repeat(100000),
        ] {
            let _: String = command(backend, "SET", &[&key, &payload]).await;
            assert!(matches!(
                b.lookup(&rotated).await,
                Err(BrowserVerifyError::Unavailable)
            ));
        }
        let _: String = command(backend, "SET", &[&key, "1\n1\n{}"]).await;
        assert!(b.lookup(&rotated).await.unwrap().is_none());

        // Short TTLs exercise the same script without sleeping through production minima.
        let short = opaque_id();
        let csrf = opaque_id();
        backend
            .call(&[
                "form".into(),
                short.clone(),
                csrf.clone(),
                "basic".into(),
                "40".into(),
                "2".into(),
                "100".into(),
                "60000".into(),
            ])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(!b.consume(&short, &csrf, LoginFlow::Basic).await.unwrap());
        let _: usize = command(backend, "DEL", &[&key, &format!("{prefix}:sessions")]).await;
        let short_session = opaque_id();
        backend
            .call(&[
                "session".into(),
                short_session.clone(),
                "".into(),
                serde_json::to_string(&super::super::StoredIdentity::from_user(user())).unwrap(),
                "40".into(),
                "1".into(),
            ])
            .await
            .unwrap();
        assert!(b.lookup(&short_session).await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(b.lookup(&short_session).await.unwrap().is_none());
        assert!(
            a.save_session(user(), None).await.is_ok(),
            "pruning reclaims capacity"
        );

        let quotas = "authotron:browser:v1:quotas";
        let mut cfg = config(&url, quotas);
        let settings = cfg.ui.browser_session.as_mut().unwrap();
        settings.max_forms_per_window = 1;
        settings.max_logins_per_window = 1;
        settings.rate_window_seconds = 1;
        let mut q1 = BrowserLoginState::new(&cfg).unwrap();
        q1.initialize(true).await.unwrap();
        let mut q2 = BrowserLoginState::new(&cfg).unwrap();
        q2.initialize(true).await.unwrap();
        let time: Vec<String> = command(backend, "TIME", &[]).await;
        let micros: u64 = time[1].parse().unwrap();
        tokio::time::sleep(Duration::from_micros(1_050_000 - micros)).await;
        q1.form(LoginFlow::Basic).await.unwrap();
        assert!(matches!(
            q2.form(LoginFlow::Basic).await,
            Err(BrowserVerifyError::Limited)
        ));
        assert!(matches!(
            q1.admitted(async { Err(BrowserVerifyError::Rejected) })
                .await,
            Err(BrowserVerifyError::Rejected)
        ));
        assert!(matches!(
            q2.admitted(async { Ok(user()) }).await,
            Err(BrowserVerifyError::Limited)
        ));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(q2.admitted(async { Ok(user()) }).await.is_ok());

        // Two independently saturated local budgets can operate together without
        // a shared lease cap. Quota bookkeeping remains shared across both states.
        let mut local_cfg = config(&url, "local-budgets");
        local_cfg
            .ui
            .browser_session
            .as_mut()
            .unwrap()
            .max_shared_inflight_logins = None;
        let mut l1 = BrowserLoginState::new(&local_cfg).unwrap();
        l1.initialize(true).await.unwrap();
        let mut l2 = BrowserLoginState::new(&local_cfg).unwrap();
        l2.initialize(true).await.unwrap();
        let l1 = Arc::new(l1);
        let l2 = Arc::new(l2);
        let metrics1 = crate::metrics::Metrics::new();
        let metrics2 = crate::metrics::Metrics::new();
        let mut tasks = Vec::new();
        for (state, metrics) in [
            (l1.clone(), metrics1.clone()),
            (l2.clone(), metrics2.clone()),
        ] {
            tasks.push(tokio::spawn(async move {
                state
                    .admitted_with_metrics(std::future::pending(), Some(&metrics))
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while l1.inflight.available_permits() != 0 || l2.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            loop {
                let count: Option<usize> =
                    command(backend, "HGET", &["local-budgets:verify-quota", "used"]).await;
                if count == Some(2) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            metrics1
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 1")
        );
        assert!(
            metrics2
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 1")
        );
        assert!(matches!(
            l1.admitted(async { Ok(user()) }).await,
            Err(BrowserVerifyError::Limited)
        ));
        assert!(matches!(
            l2.admitted(async { Ok(user()) }).await,
            Err(BrowserVerifyError::Limited)
        ));
        let count: usize = command(backend, "EXISTS", &["local-budgets:leases"]).await;
        assert_eq!(count, 0);
        let count: usize = command(backend, "HGET", &["local-budgets:verify-quota", "used"]).await;
        assert_eq!(count, 2);
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(
            metrics1
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
        assert!(
            metrics2
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );

        // Paused Valkey cannot create more pending admissions than the local budget.
        fn eval_calls(info: &str) -> usize {
            info.lines()
                .find_map(|line| line.strip_prefix("cmdstat_eval:calls="))
                .unwrap_or("0,")
                .split(',')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        }
        let info: String = command(backend, "INFO", &["commandstats"]).await;
        let before = eval_calls(&info);
        docker(&["pause", &fixture.0]);
        let task = {
            let state = l1.clone();
            let metrics = metrics1.clone();
            tokio::spawn(async move {
                state
                    .admitted_with_metrics(async { Ok(user()) }, Some(&metrics))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while l1.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..20 {
            let started = std::time::Instant::now();
            assert!(matches!(
                l1.admitted(async { Ok(user()) }).await,
                Err(BrowserVerifyError::Limited)
            ));
            assert!(started.elapsed() < Duration::from_millis(100));
        }
        assert!(
            metrics1
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 1")
        );
        docker(&["unpause", &fixture.0]);
        assert!(task.await.unwrap().is_ok());
        let info: String = command(backend, "INFO", &["commandstats"]).await;
        assert_eq!(
            eval_calls(&info),
            before + 1,
            "excess local requests send no admission commands"
        );
        assert!(
            metrics1
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );

        // A dead connection is re-established for later operations, never replaying a write.
        let _: usize = command(
            backend,
            "CLIENT",
            &["KILL", "TYPE", "normal", "SKIPME", "yes"],
        )
        .await;
        let mut reconnected = false;
        for _ in 0..100 {
            if b.form(LoginFlow::Basic).await.is_ok() {
                reconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(reconnected, "a form eventually succeeds after reconnecting");
        b.discard(&short).await.unwrap();

        let mut lease = backend.admit(100, 60, 1, 10).await.unwrap();
        assert!(matches!(
            b.valkey.as_ref().unwrap().admit(100, 60, 1, 10).await,
            Err(BrowserVerifyError::Limited)
        ));
        lease.release().await.unwrap();
        let mut next = backend.admit(100, 60, 1, 10).await.unwrap();
        // Releasing a stale/incorrect expiry must not remove another lease.
        backend
            .call(&["release".into(), next.id.clone(), "1".into()])
            .await
            .unwrap();
        assert!(matches!(
            backend.admit(100, 60, 1, 10).await,
            Err(BrowserVerifyError::Limited)
        ));
        next.release().await.unwrap();

        let task = {
            let a = a.clone();
            tokio::spawn(async move { a.admitted(std::future::pending()).await })
        };
        let leases_key = format!("{prefix}:leases");
        for _ in 0..100 {
            let count: usize = command(backend, "ZCARD", &[&leases_key]).await;
            if count == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let count: usize = command(backend, "ZCARD", &[&leases_key]).await;
        assert_eq!(count, 1, "cancelled request acquired a shared lease");
        let cap_metrics = crate::metrics::Metrics::new();
        assert!(matches!(
            b.admitted_with_metrics(async { Ok(user()) }, Some(&cap_metrics))
                .await,
            Err(BrowserVerifyError::Limited)
        ));
        assert!(
            cap_metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            let count: usize = command(backend, "ZCARD", &[&leases_key]).await;
            if count == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let count: usize = command(backend, "ZCARD", &[&leases_key]).await;
        assert_eq!(count, 0);
        let departing = state(&url, "scale-down").await;
        let weak = Arc::downgrade(&departing);
        let metrics = crate::metrics::Metrics::new();
        let task = {
            let departing = departing.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                departing
                    .admitted_with_metrics(std::future::pending(), Some(&metrics))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let count: usize = command(backend, "ZCARD", &["scale-down:leases"]).await;
                if count == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(departing);
        task.abort();
        let _ = task.await;
        assert!(
            weak.upgrade().is_none(),
            "shutdown cleanup does not retain browser state"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let count: usize = command(backend, "ZCARD", &["scale-down:leases"]).await;
                if count == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
        let mut crashed = backend.admit(100, 60, 1, 0).await.unwrap();
        crashed.released = true;
        drop(crashed);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        backend
            .admit(100, 60, 1, 10)
            .await
            .unwrap()
            .release()
            .await
            .unwrap();

        let mut timed_config = config(&url, "deadline");
        timed_config
            .ui
            .browser_session
            .as_mut()
            .unwrap()
            .verification_timeout_seconds = 1;
        let mut timed = BrowserLoginState::new(&timed_config).unwrap();
        timed.initialize(true).await.unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            timed.admitted(std::future::pending()).await,
            Err(BrowserVerifyError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        let count: usize = command(
            timed.valkey.as_ref().unwrap(),
            "ZCARD",
            &["deadline:leases"],
        )
        .await;
        assert_eq!(count, 0, "verification timeout awaits exact lease release");

        let mut disabled =
            BrowserLoginState::new(&config("redis://127.0.0.1:1/0", "disabled")).unwrap();
        disabled.initialize(false).await.unwrap();
        let mut wrong = config(&url, "wrong-password");
        if let BrowserBackendConfig::Valkey { password, .. } =
            &mut wrong.ui.browser_session.as_mut().unwrap().backend
        {
            *password = "wrong".into();
        }
        assert!(
            BrowserLoginState::new(&wrong)
                .unwrap()
                .initialize(true)
                .await
                .is_err()
        );

        docker(&["pause", &fixture.0]);
        let started = std::time::Instant::now();
        assert!(matches!(
            b.lookup(&rotated).await,
            Err(BrowserVerifyError::Unavailable)
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "operation timeout bounds a stalled server"
        );
        docker(&["unpause", &fixture.0]);

        // Public routes fail closed on a shared-backend outage, without new cookies.
        let mut route_cfg = config(&url, "routes");
        route_cfg
            .ui
            .browser_session
            .as_mut()
            .unwrap()
            .max_shared_inflight_logins = None;
        let (app, app_state) = crate::startup::build_app(Arc::new(route_cfg))
            .await
            .unwrap();
        let (other_app, other_state) = crate::startup::build_app(Arc::new(config(&url, "routes")))
            .await
            .unwrap();
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        // ACL denies an index write after verification; preflight prevents a
        // session record from being created without its capacity index.
        let (acl_sid, acl_csrf) = app_state.browser.form(LoginFlow::Basic).await.unwrap();
        let _: String = command(backend, "ACL", &["SETUSER", "default", "-zadd"]).await;
        let orphan_sid = opaque_id();
        assert!(
            backend
                .call(&[
                    "session".into(),
                    orphan_sid.clone(),
                    "".into(),
                    serde_json::to_string(&super::super::StoredIdentity::from_user(user()))
                        .unwrap(),
                    "300000".into(),
                    "1".into()
                ])
                .await
                .is_err()
        );
        let count: usize = command(
            backend,
            "EXISTS",
            &[&format!("{prefix}:session:{orphan_sid}")],
        )
        .await;
        assert_eq!(count, 0);
        let response = app
            .clone()
            .oneshot(
                Request::post("/login/basic")
                    .header("origin", "https://login.example.test")
                    .header("cookie", format!("__Host-authotron_form={acl_sid}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "username=alice&password=public-fixture&csrf={acl_csrf}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let _: String = command(backend, "ACL", &["SETUSER", "default", "+zadd"]).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get("set-cookie").is_none());
        let metrics = app_state.metrics.render().unwrap();
        assert!(metrics.contains("authotron_browser_login_attempts_total{flow=\"basic\",outcome=\"backend_unavailable\"} 1"));
        assert!(!metrics.contains("outcome=\"success\""));
        assert!(metrics.contains("authotron_browser_logins_inflight 0"));
        let form = app
            .clone()
            .oneshot(Request::get("/login/basic").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(form.status(), StatusCode::OK);
        assert!(
            form.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=45")
        );
        let cookie = form.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let html =
            String::from_utf8(to_bytes(form.into_body(), 32768).await.unwrap().to_vec()).unwrap();
        let csrf = html
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let response = other_app
            .oneshot(
                Request::post("/login/basic")
                    .header("origin", "https://login.example.test")
                    .header("cookie", cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "username=alice&password=public-fixture&csrf={csrf}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "cross-replica browser POST"
        );
        let metrics = other_state.metrics.render().unwrap();
        assert!(metrics.contains(
            "authotron_browser_login_attempts_total{flow=\"basic\",outcome=\"success\"} 1"
        ));
        assert!(metrics.contains("authotron_browser_logins_inflight 0"));
        let cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("__Host-authotron_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let session = cookie
            .strip_prefix("__Host-authotron_session=")
            .unwrap()
            .to_owned();
        assert_eq!(
            app_state
                .browser
                .lookup(&session)
                .await
                .unwrap()
                .unwrap()
                .user
                .username,
            "alice"
        );
        let corrupt = "1\n10000000000000000\n{\"version\":1,\"username\":\"alice\",\"realm\":\"fixture\",\"roles\":[],\"attributes\":{}}";
        let _: String = command(
            backend,
            "SET",
            &[&format!("routes:session:{session}"), corrupt],
        )
        .await;
        let response = app
            .clone()
            .oneshot(
                Request::get("/login/account")
                    .header("cookie", format!("__Host-authotron_session={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["cache-control"], "no-store");
        for uid in [" ", "alice\n"] {
            let mut identity = user();
            identity.username = uid.into();
            assert!(matches!(
                app_state.browser.save_session(identity.clone(), None).await,
                Err(BrowserVerifyError::Rejected)
            ));
            let value = format!(
                "1\n9999999999999\n{}",
                serde_json::to_string(&super::super::StoredIdentity::from_user(identity)).unwrap()
            );
            let _: String = command(
                backend,
                "SET",
                &[&format!("routes:session:{session}"), &value],
            )
            .await;
            assert!(matches!(
                app_state.browser.lookup(&session).await,
                Err(BrowserVerifyError::Unavailable)
            ));
        }
        // Stall only cleanup: admission and local Basic verification finish before the pause.
        struct PauseCleanup(Valkey, Arc<std::sync::atomic::AtomicBool>);
        #[async_trait::async_trait]
        impl crate::augmenters::Augmenter for PauseCleanup {
            fn get_name(&self) -> &str {
                "pause-cleanup"
            }
            fn get_type(&self) -> &str {
                "plain"
            }
            fn get_realm(&self) -> &str {
                "fixture"
            }
            async fn augment(&self, _: Arc<futures::lock::Mutex<User>>) -> Result<(), String> {
                self.0
                    .connection
                    .query::<String>(redis::cmd("CLIENT").arg("PAUSE").arg(2500).arg("ALL"))
                    .await
                    .map_err(|_| "fixture pause failed".to_owned())?;
                self.1.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            }
        }
        let mut cfg = config(&url, "oauth-cleanup-deadline");
        let settings = cfg.ui.browser_session.as_mut().unwrap();
        settings.verification_timeout_seconds = 1;
        settings.max_inflight_logins = 1;
        let BrowserBackendConfig::Valkey {
            operation_timeout_ms,
            ..
        } = &mut settings.backend
        else {
            unreachable!()
        };
        *operation_timeout_ms = 5000;
        let mut browser = BrowserLoginState::new(&cfg).unwrap();
        browser.initialize(true).await.unwrap();
        let mut auth = crate::auth::Auth::new(
            &cfg.providers,
            &[],
            Arc::new(crate::store::no_store::NoStore),
            cfg.auth,
        );
        let augmented = Arc::new(std::sync::atomic::AtomicBool::new(false));
        auth.augmenters.push(Box::new(PauseCleanup(
            browser.valkey.as_ref().unwrap().clone(),
            augmented.clone(),
        )));
        let metrics = crate::metrics::Metrics::new();
        let outcome = tokio::time::timeout(
            Duration::from_millis(1800),
            crate::oauth::authentication::verify_identity(
                crate::browser::BrowserCredentials::Basic {
                    username: "alice",
                    password: "public-fixture",
                },
                &browser,
                &auth,
                &metrics,
            ),
        )
        .await
        .expect("strict helper exceeded total deadline tolerance");
        assert!(augmented.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            outcome.err(),
            Some(crate::oauth::authentication::AuthenticationError::Timeout)
        );
        assert_eq!(browser.inflight.available_permits(), 1);
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
        // Detached bounded cleanup or expiry releases the shared lease, not the caller deadline.
        tokio::time::sleep(Duration::from_millis(3000)).await;
        auth.augmenters.clear();
        assert!(
            crate::oauth::authentication::verify_identity(
                crate::browser::BrowserCredentials::Basic {
                    username: "alice",
                    password: "public-fixture"
                },
                &browser,
                &auth,
                &metrics,
            )
            .await
            .is_ok()
        );

        docker(&["stop", &fixture.0]);
        assert!(matches!(
            b.lookup(&rotated).await,
            Err(BrowserVerifyError::Unavailable)
        ));
        for path in ["/login/basic", "/login/account", "/login"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(path)
                        .header("cookie", format!("__Host-authotron_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().get("set-cookie").is_none());
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
