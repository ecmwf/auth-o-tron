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
    refresh::RefreshToken,
    refresh_grant::refresh_dispatch,
    upstream::tests::{Coupled, Valkey, coupled},
};
use crate::oidc::mock::SUBJECT;
use serde_json::{Value, json};

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
    let grant = RefreshGrant {
        realm: realm.into(),
        username: username.into(),
        client_id: client.into(),
        upstream_coupled: realm == "idp",
        ..coupled.grant()
    };
    let upstream = (realm == "idp").then(|| coupled.idp.state.offline_token(SUBJECT));
    let sealed = upstream.as_ref().map(|token| coupled.seal(&grant, token));
    let backend = coupled.runtime.refresh.as_ref().unwrap();
    let now = coupled.runtime.now().await.unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    let token = RefreshToken::generate().unwrap();
    refresh_dispatch!(
        backend,
        issue(&grant, token.hash(), now, policy, sealed.as_deref())
    )
    .unwrap();
    upstream
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
