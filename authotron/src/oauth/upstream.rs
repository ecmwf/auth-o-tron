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
//! the provider's own offline-session expiry still ends the grant. Every outcome is
//! logged with the grant's client, method, realm, username and family reference, within
//! the span of the request that ended the grant.

use super::{
    audit::{NO_FAMILY, family_event},
    context::AuthenticatedAuthorization,
    refresh::RefreshGrant,
    runtime::OAuthRuntime,
};
use crate::{
    browser::BrowserLoginState,
    metrics::{Metrics, UpstreamTokenEvent},
    oidc::{
        OidcError,
        method::OidcMethod,
        upstream::{UpstreamBinding, UpstreamCipher, UpstreamGrant},
    },
};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::Instrument;
use zeroize::Zeroizing;

const REVOCATION_QUEUE: usize = 256;

/// Whose upstream grant a revocation ends, for its outcome log line.
pub(crate) struct RevocationAudit {
    client_id: String,
    method: String,
    realm: String,
    username: String,
    /// A family reference, or [`NO_FAMILY`].
    family: String,
}

impl RevocationAudit {
    /// A sign-in's upstream grant that never reached a family.
    pub(crate) fn sign_in(client_id: &str, method: &str, realm: &str, username: &str) -> Self {
        Self {
            client_id: client_id.into(),
            method: method.into(),
            realm: realm.into(),
            username: username.into(),
            family: NO_FAMILY.into(),
        }
    }
    fn of(grant: &RefreshGrant, family: &str) -> Self {
        Self {
            client_id: grant.client_id.clone(),
            method: grant.method.clone(),
            realm: grant.realm.clone(),
            username: grant.username.clone(),
            family: family.to_owned(),
        }
    }
    fn skipped(&self, metrics: &Metrics) {
        family_event!(
            warn,
            self,
            self.family,
            event_name = "oauth.upstream.revocation_skipped",
            "upstream refresh token not revoked: queue full, or grant cannot be opened"
        );
        metrics.record_upstream_token(UpstreamTokenEvent::RevocationSkipped);
    }
}

/// One revocation for the worker. Deliberately not Debug.
struct Revocation {
    method: Arc<OidcMethod>,
    refresh_token: Zeroizing<String>,
    metrics: Metrics,
    audit: RevocationAudit,
    span: tracing::Span,
}

impl Revocation {
    /// A revocation within the span of the current request.
    fn new(
        method: &Arc<OidcMethod>,
        refresh_token: Zeroizing<String>,
        audit: RevocationAudit,
        metrics: &Metrics,
    ) -> Self {
        Self {
            method: method.clone(),
            refresh_token,
            metrics: metrics.clone(),
            audit,
            span: tracing::Span::current(),
        }
    }
    async fn run(self) -> UpstreamTokenEvent {
        let outcome = self.method.revoke(&self.refresh_token).await;
        self.report(outcome)
    }
    /// Logs and counts the provider's answer.
    fn report(&self, outcome: Result<bool, OidcError>) -> UpstreamTokenEvent {
        let audit = &self.audit;
        let event = match outcome {
            Ok(true) => {
                family_event!(
                    info,
                    audit,
                    audit.family,
                    event_name = "oauth.upstream.revocation_sent",
                    "upstream refresh token revoked"
                );
                UpstreamTokenEvent::RevocationSent
            }
            Ok(false) => {
                family_event!(
                    info,
                    audit,
                    audit.family,
                    event_name = "oauth.upstream.revocation_unsupported",
                    "provider advertises no revocation endpoint"
                );
                UpstreamTokenEvent::RevocationUnsupported
            }
            Err(error) => {
                family_event!(
                    warn,
                    audit,
                    audit.family,
                    event_name = "oauth.upstream.revocation_failed",
                    reason = error.label(),
                    "upstream refresh token not revoked"
                );
                UpstreamTokenEvent::RevocationFailed
            }
        };
        self.metrics.record_upstream_token(event);
        event
    }
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
                let span = job.span.clone();
                job.run().instrument(span).await;
            }
        });
        Self {
            cipher,
            revocations,
        }
    }
    /// Queues a revocation; on a full queue it is returned for the skip log.
    fn queue(&self, revocation: Revocation) -> Result<(), RevocationAudit> {
        self.revocations
            .try_send(revocation)
            .map_err(|error| error.into_inner().audit)
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
        audit: RevocationAudit,
        metrics: &Metrics,
    ) {
        let Some(upstream) = &self.upstream else {
            return audit.skipped(metrics);
        };
        let revocation = Revocation::new(method, refresh_token, audit, metrics);
        if let Err(audit) = upstream.queue(revocation) {
            audit.skipped(metrics);
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
        self.revoke_sealed(&grant, sealed, NO_FAMILY, browser, metrics);
    }

    /// Queues upstream revocation of the sealed grant of `grant`, which no family holds
    /// any more; `family` is the ended family's reference or [`NO_FAMILY`]. A grant whose
    /// method or key no longer opens it is skipped and counted.
    pub(super) fn revoke_sealed(
        &self,
        grant: &RefreshGrant,
        sealed: &str,
        family: &str,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) {
        let Some((upstream, revocation)) = self.revocation(grant, sealed, family, browser, metrics)
        else {
            return;
        };
        if let Err(audit) = upstream.queue(revocation) {
            audit.skipped(metrics);
        }
    }

    /// Revokes the sealed grant of `grant` at the provider and waits for the answer, at
    /// most `timeout`, after which the revocation counts as failed. Nothing is queued,
    /// for a command that ends before a queue would drain.
    pub(super) async fn revoke_sealed_now(
        &self,
        grant: &RefreshGrant,
        sealed: &str,
        family: &str,
        browser: &BrowserLoginState,
        metrics: &Metrics,
        timeout: Duration,
    ) -> UpstreamTokenEvent {
        let Some((_, revocation)) = self.revocation(grant, sealed, family, browser, metrics) else {
            return UpstreamTokenEvent::RevocationSkipped;
        };
        let answer =
            tokio::time::timeout(timeout, revocation.method.revoke(&revocation.refresh_token))
                .await;
        revocation.report(answer.unwrap_or(Err(OidcError::Unavailable)))
    }

    /// The revocation of the sealed grant of `grant`, or `None`, logged and counted as
    /// skipped, when no configured method and key open it any more.
    fn revocation(
        &self,
        grant: &RefreshGrant,
        sealed: &str,
        family: &str,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Option<(&Upstream, Revocation)> {
        let audit = RevocationAudit::of(grant, family);
        let opened = self.upstream.as_ref().and_then(|upstream| {
            let method = browser.method(&grant.method)?.oidc()?;
            let opened = upstream.cipher.open(&binding(grant, method), sealed).ok()?;
            Some((upstream, method, opened))
        });
        let Some((upstream, method, opened)) = opened else {
            audit.skipped(metrics);
            return None;
        };
        let refresh_token = Zeroizing::new(opened.refresh_token().to_owned());
        Some((
            upstream,
            Revocation::new(method, refresh_token, audit, metrics),
        ))
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests;
