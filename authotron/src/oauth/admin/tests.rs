// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Finding and revoking logins as an operator, with coupled families at the in-process
//! identity provider.

use super::*;
use crate::oauth::{
    audit::family_ref,
    refresh::RefreshToken,
    refresh_grant::refresh_dispatch,
    upstream::tests::{Coupled, Valkey, coupled},
};
use crate::oidc::mock::{MockIdp, SUBJECT};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

/// Adds the client `cli` beside `desktop`.
fn second_client(config: &mut Value) {
    let clients = config["oauth"]["clients"].as_array_mut().unwrap();
    let mut cli = clients[0].clone();
    cli["client_id"] = json!("cli");
    cli["display_name"] = json!("Command line");
    clients.push(cli);
}

/// Starts a family of `username` in `realm` for `client`, coupled to a live offline
/// token at the provider when the realm is the method's. Returns the upstream token.
async fn login(coupled: &Coupled, realm: &str, username: &str, client: &str) -> Option<String> {
    let now = coupled.runtime.now().await.unwrap();
    login_at(coupled, realm, username, client, now).await
}

/// The same, started at `now_ms`.
async fn login_at(
    coupled: &Coupled,
    realm: &str,
    username: &str,
    client: &str,
    now_ms: u64,
) -> Option<String> {
    let grant = RefreshGrant {
        realm: realm.into(),
        username: username.into(),
        client_id: client.into(),
        upstream_coupled: realm == "idp",
        ..coupled.grant()
    };
    let upstream = (realm == "idp").then(|| coupled.idp.state.offline_token(SUBJECT));
    let sealed = upstream.as_ref().map(|token| coupled.seal(&grant, token));
    issue(coupled, &grant, sealed.as_deref(), now_ms).await;
    upstream
}

/// Starts a family of `username` in `realm` through the OIDC method `method`, coupled to
/// a live offline token at `idp`, the method's provider.
async fn login_through(
    coupled: &Coupled,
    idp: &MockIdp,
    method: &str,
    realm: &str,
    username: &str,
) {
    let grant = RefreshGrant {
        realm: realm.into(),
        username: username.into(),
        method: method.into(),
        ..coupled.grant()
    };
    let sealed = coupled.seal(&grant, &idp.state.offline_token(SUBJECT));
    let now = coupled.runtime.now().await.unwrap();
    issue(coupled, &grant, Some(&sealed), now).await;
}

async fn issue(coupled: &Coupled, grant: &RefreshGrant, sealed: Option<&str>, now_ms: u64) {
    let backend = coupled.runtime.refresh.as_ref().unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    let token = RefreshToken::generate().unwrap();
    refresh_dispatch!(backend, issue(grant, token.hash(), now_ms, policy, sealed)).unwrap();
}

fn filter(realm: &str, username: Option<&str>, client: Option<&str>) -> LoginFilter {
    LoginFilter {
        realm: realm.into(),
        username: username.map(Into::into),
        client: client.map(Into::into),
    }
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[tracing_test::traced_test]
#[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
async fn disposable_valkey_logins_are_found_by_realm_user_and_client_and_revoked() {
    let valkey = Valkey::start("authotron:admin-test").await;
    let coupled = coupled(|config| {
        config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
        second_client(config);
    })
    .await;
    let alice_desktop = login(&coupled, "idp", "alice", "desktop").await.unwrap();
    let alice_cli = login(&coupled, "idp", "alice", "cli").await.unwrap();
    login(&coupled, "idp", "bob", "desktop").await;
    login(&coupled, "other", "alice", "desktop").await;
    let runtime = &coupled.runtime;
    let found = |realm, username, client| async move {
        let found = runtime
            .find_logins(&filter(realm, username, client))
            .await
            .unwrap();
        let mut who: Vec<_> = found
            .iter()
            .map(|f| {
                format!(
                    "{}/{}/{}",
                    f.grant.realm, f.grant.username, f.grant.client_id
                )
            })
            .collect();
        who.sort();
        (found, who)
    };
    assert_eq!(
        found("idp", None, None).await.1,
        ["idp/alice/cli", "idp/alice/desktop", "idp/bob/desktop"]
    );
    assert_eq!(found("idp", None, Some("cli")).await.1, ["idp/alice/cli"]);
    assert_eq!(
        found("idp", Some("alice"), None).await.1,
        ["idp/alice/cli", "idp/alice/desktop"]
    );
    assert_eq!(
        found("idp", Some("alice"), Some("desktop")).await.1,
        ["idp/alice/desktop"]
    );
    assert_eq!(found("other", None, None).await.1, ["other/alice/desktop"]);
    assert!(found("IDP", None, None).await.1.is_empty());
    assert!(found("idp", Some("Alice"), None).await.1.is_empty());
    let (newest_first, _) = found("idp", None, None).await;
    assert!(
        newest_first
            .windows(2)
            .all(|w| w[0].created_at_ms >= w[1].created_at_ms)
    );

    // Alice's two logins in realm idp end, and so do their offline sessions.
    let (alice, _) = found("idp", Some("alice"), None).await;
    let revoked = runtime
        .revoke_found(&alice, &coupled.browser, &coupled.metrics)
        .await
        .unwrap();
    let expected = Revoked {
        families: 2,
        upstream_sent: 2,
        ..Revoked::default()
    };
    assert_eq!(revoked, expected);
    let sent = coupled.idp.state.revoked.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    for token in [&alice_desktop, &alice_cli] {
        assert!(sent.contains(token));
        assert!(!coupled.idp.state.refresh_token_live(token));
    }
    assert_eq!(found("idp", None, None).await.1, ["idp/bob/desktop"]);
    assert_eq!(found("other", None, None).await.1.len(), 1);
    // Revoking them again finds nothing to end.
    let again = runtime
        .revoke_found(&alice, &coupled.browser, &coupled.metrics)
        .await
        .unwrap();
    assert_eq!(again, Revoked::default());
    assert!(logs_contain("reason=\"admin_revoke\""));
    assert!(logs_contain("oauth.upstream.revocation_sent"));
}

/// Runs `authotron admin <line>` with `config`; its result and report.
async fn command(
    config: &crate::config::ConfigV2,
    line: &str,
) -> (Result<crate::admin::Finished, String>, String) {
    let args: Vec<String> = line.split_whitespace().map(String::from).collect();
    let command = crate::admin::parse(&args).unwrap();
    let mut out = Vec::new();
    let result = crate::admin::run(config, &command, &mut out).await;
    (result, String::from_utf8(out).unwrap())
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[tracing_test::traced_test]
#[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
async fn disposable_valkey_the_admin_command_lists_dry_runs_and_revokes_a_realm() {
    let valkey = Valkey::start("authotron:admin-command-test").await;
    let coupled = coupled(|config| {
        config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
        second_client(config);
    })
    .await;
    // A millisecond apart, so that the order does not rest on a tie.
    let now = coupled.runtime.now().await.unwrap();
    let alice = login_at(&coupled, "idp", "alice", "desktop", now - 2).await;
    let bob = login_at(&coupled, "idp", "bob", "cli", now - 1).await;
    login_at(&coupled, "other", "carol", "desktop", now).await;
    let (alice, bob) = (alice.unwrap(), bob.unwrap());
    let config = &coupled.config;
    let (result, listed) = command(config, "logins list --realm idp").await;
    result.unwrap();
    let rows: Vec<Vec<_>> = listed
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 4, "{listed}");
    assert_eq!(
        rows[0],
        [
            "CLIENT",
            "METHOD",
            "REALM",
            "USERNAME",
            "CREATED",
            "LAST_USED",
            "IDLE_EXPIRY",
            "ABSOLUTE_EXPIRY",
            "REFERENCE"
        ]
    );
    // Newest first.
    assert_eq!(rows[1][..4], ["cli", "sso", "idp", "bob"]);
    assert_eq!(rows[2][..4], ["desktop", "sso", "idp", "alice"]);
    assert_eq!(rows[3], ["2", "logins"]);
    let all = filter("idp", None, None);
    for family in coupled.runtime.find_logins(&all).await.unwrap() {
        assert!(listed.contains(&family_ref(&family.family_id)));
        assert!(!listed.contains(&family.family_id));
    }
    let (_, limited) = command(config, "logins list --realm idp --limit 1").await;
    assert!(limited.ends_with("showing 1 of 2 logins\n"), "{limited}");

    let (result, dry) = command(config, "logins revoke --realm idp --all-users --dry-run").await;
    result.unwrap();
    assert!(dry.ends_with("dry run: would revoke 2 logins\n"), "{dry}");
    assert_eq!(coupled.runtime.find_logins(&all).await.unwrap().len(), 2);
    let (_, none) = command(
        config,
        "logins revoke --realm idp --username alice --client cli",
    )
    .await;
    let none: Vec<_> = none.lines().collect();
    assert_eq!(none.len(), 2, "{none:?}");
    assert!(none[0].starts_with("CLIENT  METHOD"));
    assert!(none[1].starts_with("revoked 0 logins;"));
    assert!(!logs_contain("admin_revoke"));

    // A revocation shows the logins it selected first, as the dry run did.
    let (result, revoked) = command(config, "logins revoke --realm idp --all-users").await;
    result.unwrap();
    let (selected, summary) = revoked.trim_end().rsplit_once('\n').unwrap();
    assert_eq!(selected, dry.trim_end().rsplit_once('\n').unwrap().0);
    assert_eq!(
        summary,
        "revoked 2 logins; upstream grants: 2 revoked at the provider, 0 not supported \
         there, 0 failed, 0 skipped"
    );
    let mut sent = coupled.idp.state.revoked.lock().unwrap().clone();
    sent.sort();
    let mut expected = [alice, bob];
    expected.sort();
    assert_eq!(sent, expected);
    assert!(coupled.runtime.find_logins(&all).await.unwrap().is_empty());
    let other = filter("other", None, None);
    assert_eq!(coupled.runtime.find_logins(&other).await.unwrap().len(), 1);
    assert!(logs_contain("reason=\"admin_revoke\""));
    assert!(logs_contain("username=bob"));
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
async fn disposable_valkey_a_failing_provider_ends_the_upstream_phase_and_each_grant_is_named() {
    let valkey = Valkey::start("authotron:admin-upstream-test").await;
    let coupled = coupled(|config| {
        config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
    })
    .await;
    // More than the failures that can complete: those allowed and those in flight.
    let users = MAX_CONSECUTIVE_UPSTREAM_FAILURES + 14;
    for user in 0..users {
        login(&coupled, "idp", &format!("user{user:02}"), "desktop").await;
    }
    let all = filter("idp", None, None);
    let found = coupled.runtime.find_logins(&all).await.unwrap();
    assert_eq!(found.len(), users);
    let state = &coupled.idp.state;
    state.revocation_fails.store(true, Ordering::SeqCst);
    let (result, report) = command(&coupled.config, "logins revoke --realm idp --all-users").await;
    assert_eq!(result, Ok(crate::admin::Finished::UpstreamLeft));
    assert!(report.contains(&format!(
        "revoked {users} logins; upstream grants: 0 revoked at the provider, 0 not supported \
         there, {users} failed, 0 skipped\n"
    )));
    let left: Vec<_> = report
        .lines()
        .filter_map(|line| line.strip_prefix("upstream grant left: "))
        .collect();
    assert_eq!(left.len(), users, "{report}");
    for login in &found {
        let named = format!(
            "{} {} (",
            family_ref(&login.family_id),
            login.grant.username
        );
        assert_eq!(
            left.iter().filter(|line| line.starts_with(&named)).count(),
            1
        );
    }
    // Revocations already waiting for an answer when the provider is given up on still
    // fail, at most one fewer than run at once; the rest are not attempted.
    let failed = left
        .iter()
        .filter(|line| line.ends_with("(failed)"))
        .count();
    let most = MAX_CONSECUTIVE_UPSTREAM_FAILURES + 7;
    assert!(
        (MAX_CONSECUTIVE_UPSTREAM_FAILURES..=most).contains(&failed),
        "{failed}"
    );
    let stopped = format!(
        "(not attempted after {MAX_CONSECUTIVE_UPSTREAM_FAILURES} failures in a row at its provider)"
    );
    let not_attempted = left.iter().filter(|line| line.ends_with(&stopped)).count();
    assert_eq!(failed + not_attempted, users);
    assert!(state.revoked.lock().unwrap().is_empty());
    assert!(coupled.runtime.find_logins(&all).await.unwrap().is_empty());
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
async fn disposable_valkey_one_failing_provider_is_given_up_alone() {
    let valkey = Valkey::start("authotron:admin-providers-test").await;
    let working = MockIdp::start().await;
    let coupled = coupled(|config| {
        config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
        // A second OIDC method in realm `idp2`, at a provider of its own.
        let methods = config["ui"]["oidc"].as_array_mut().unwrap();
        let mut second = methods[0].clone();
        second["id"] = json!("sso2");
        second["label"] = json!("SSO 2");
        second["realm"] = json!("idp2");
        second["issuer"] = json!(working.issuer);
        methods.push(second);
    })
    .await;
    // Older logins come later, so the working provider's are revoked after the
    // failing one is given up on.
    for user in 0..4 {
        login_through(&coupled, &working, "sso2", "idp2", &format!("second{user}")).await;
    }
    let failing = MAX_CONSECUTIVE_UPSTREAM_FAILURES + 14;
    for user in 0..failing {
        login(&coupled, "idp", &format!("user{user:02}"), "desktop").await;
    }
    coupled
        .idp
        .state
        .revocation_fails
        .store(true, Ordering::SeqCst);
    let runtime = &coupled.runtime;
    let mut logins = runtime
        .find_logins(&filter("idp", None, None))
        .await
        .unwrap();
    logins.extend(
        runtime
            .find_logins(&filter("idp2", None, None))
            .await
            .unwrap(),
    );
    assert_eq!(logins.len(), failing + 4);
    let revoked = runtime
        .revoke_found(&logins, &coupled.browser, &coupled.metrics)
        .await
        .unwrap();
    assert_eq!(revoked.families, failing + 4);
    assert_eq!(revoked.upstream_sent, 4);
    assert_eq!(working.state.revoked.lock().unwrap().len(), 4);
    assert_eq!(revoked.upstream_failed, failing);
    let not_attempted: Vec<_> = revoked
        .upstream_left
        .iter()
        .filter(|left| left.reason == LeftReason::NotAttempted)
        .collect();
    assert!(not_attempted.len() >= failing - MAX_CONSECUTIVE_UPSTREAM_FAILURES - 7);
    assert_eq!(revoked.upstream_left.len(), failing);
    // Only the failing provider's grants are left.
    let left = &revoked.upstream_left;
    assert!(left.iter().all(|left| left.username.starts_with("user")));
}

#[tokio::test]
async fn per_process_families_and_servers_without_refresh_tokens_have_no_logins_to_find() {
    let memory = coupled(|_| {}).await;
    let all = filter("idp", None, None);
    assert_eq!(
        memory.runtime.find_logins(&all).await.err(),
        Some(AdminError::PerProcess)
    );
    let without = coupled(|config| {
        config["oauth"]["clients"][0]["refresh_tokens"] = json!({"enabled": false});
    })
    .await;
    assert_eq!(
        without.runtime.find_logins(&all).await.err(),
        Some(AdminError::NoLogins)
    );
    let revoked = without
        .runtime
        .revoke_found(&[], &without.browser, &without.metrics)
        .await;
    assert_eq!(revoked.err(), Some(AdminError::NoLogins));
}
