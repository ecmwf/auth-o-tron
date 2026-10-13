// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Upstream grants of refresh families coupled to an OIDC sign-in: the sealing keys,
//! and best-effort revocation at the provider (RFC 7009) when a coupled family ends.
//! Revocations run on one background worker, so token and revocation responses never
//! wait for the provider. When the queue is full a revocation is skipped and counted;
//! the provider's own offline-session expiry still ends the grant.

use super::{
    context::AuthenticatedAuthorization,
    refresh::{EndedUpstream, RefreshGrant},
    runtime::OAuthRuntime,
};
use crate::{
    browser::BrowserLoginState,
    metrics::{Metrics, UpstreamTokenEvent},
    oidc::{
        method::OidcMethod,
        upstream::{UpstreamBinding, UpstreamCipher, UpstreamGrant},
    },
};
use std::sync::Arc;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const REVOCATION_QUEUE: usize = 256;

/// One revocation for the worker. Deliberately not Debug.
struct Revocation {
    method: Arc<OidcMethod>,
    refresh_token: Zeroizing<String>,
    metrics: Metrics,
}

/// Sealing keys and the revocation queue. Deliberately not Debug.
pub(crate) struct Upstream {
    pub(super) cipher: UpstreamCipher,
    revocations: mpsc::Sender<Revocation>,
}

impl Upstream {
    /// Starts the revocation worker on the current Tokio runtime.
    pub(super) fn start(cipher: UpstreamCipher) -> Self {
        let (revocations, mut queue) = mpsc::channel::<Revocation>(REVOCATION_QUEUE);
        tokio::spawn(async move {
            while let Some(job) = queue.recv().await {
                let event = match job.method.revoke(&job.refresh_token).await {
                    Ok(true) => UpstreamTokenEvent::RevocationSent,
                    Ok(false) => UpstreamTokenEvent::RevocationUnsupported,
                    Err(error) => {
                        tracing::warn!(
                            event_name = "oauth.upstream.revocation_failed",
                            event_domain = "oauth",
                            method = %job.method.config().id,
                            reason = error.label(),
                            "upstream refresh token not revoked"
                        );
                        UpstreamTokenEvent::RevocationFailed
                    }
                };
                job.metrics.record_upstream_token(event);
            }
        });
        Self {
            cipher,
            revocations,
        }
    }
    /// Queues a revocation; `false` when the queue is full.
    fn queue(
        &self,
        method: &Arc<OidcMethod>,
        refresh_token: Zeroizing<String>,
        metrics: &Metrics,
    ) -> bool {
        self.revocations
            .try_send(Revocation {
                method: method.clone(),
                refresh_token,
                metrics: metrics.clone(),
            })
            .is_ok()
    }
}

/// The context a family's sealed upstream grant is bound to.
pub(super) fn binding<'a>(grant: &'a RefreshGrant, method: &'a OidcMethod) -> UpstreamBinding<'a> {
    UpstreamBinding {
        method: &grant.method,
        issuer: &method.config().issuer,
        client_id: &grant.client_id,
        realm: &grant.realm,
        username: &grant.username,
    }
}

impl OAuthRuntime {
    /// Whether a sign-in through `oidc` for `client_id` requests offline access: the
    /// method allows it, the client opts in, and sealing keys are configured.
    pub(crate) fn offline_access(&self, client_id: &str, oidc: &OidcMethod) -> bool {
        oidc.config().offline_access
            && self.upstream.is_some()
            && self.config.clients.iter().any(|client| {
                client.client_id == client_id
                    && client.refresh_tokens.enabled
                    && client.refresh_tokens.upstream_offline_access
            })
    }

    /// Seals the upstream grant of a sign-in; `None` without keys or on failure.
    pub(crate) fn seal_upstream(
        &self,
        binding: &UpstreamBinding<'_>,
        grant: &UpstreamGrant,
    ) -> Option<String> {
        self.upstream.as_ref()?.cipher.seal(binding, grant).ok()
    }

    /// Queues revocation of an upstream refresh token that no family will hold.
    pub(crate) fn revoke_upstream_token(
        &self,
        method: &Arc<OidcMethod>,
        refresh_token: Zeroizing<String>,
        metrics: &Metrics,
    ) {
        let queued = self
            .upstream
            .as_ref()
            .is_some_and(|upstream| upstream.queue(method, refresh_token, metrics));
        if !queued {
            metrics.record_upstream_token(UpstreamTokenEvent::RevocationSkipped);
        }
    }

    /// Revokes the upstream grant of an authorization that ends without a code.
    pub(crate) fn end_authorization_upstream(
        &self,
        context: &AuthenticatedAuthorization,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) {
        let Some(sealed) = context.upstream() else {
            return;
        };
        let request = context.transaction().request();
        let grant = RefreshGrant {
            client_id: request.client_id().into(),
            resource: request.resource().into(),
            scopes: context.authorized_scopes().to_vec(),
            username: context.as_user().username.clone(),
            realm: context.as_user().realm.clone(),
            provider_roles: context.provider_roles().to_vec(),
            method: context.method().into(),
            upstream_coupled: true,
        };
        let sealed = sealed.to_owned();
        self.end_upstream([EndedUpstream { grant, sealed }], browser, metrics);
    }

    /// Queues upstream revocation for each ended coupled family. A family whose method
    /// or key no longer opens its sealed grant is skipped and counted.
    pub(super) fn end_upstream(
        &self,
        ended: impl IntoIterator<Item = EndedUpstream>,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) {
        for family in ended {
            let queued = self.upstream.as_ref().is_some_and(|upstream| {
                let Some(method) = browser
                    .method(&family.grant.method)
                    .and_then(|method| method.oidc())
                else {
                    return false;
                };
                let Ok(grant) = upstream
                    .cipher
                    .open(&binding(&family.grant, method), &family.sealed)
                else {
                    return false;
                };
                let refresh_token = Zeroizing::new(grant.refresh_token().to_owned());
                upstream.queue(method, refresh_token, metrics)
            });
            if !queued {
                tracing::warn!(
                    event_name = "oauth.upstream.revocation_skipped",
                    event_domain = "oauth",
                    method = %family.grant.method,
                    "upstream refresh token of an ended family not revoked"
                );
                metrics.record_upstream_token(UpstreamTokenEvent::RevocationSkipped);
            }
        }
    }
}

#[cfg(all(test, unix))]
pub(super) mod tests;
