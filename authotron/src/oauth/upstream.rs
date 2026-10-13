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
    refresh::{EndedUpstream, RefreshGrant},
    runtime::OAuthRuntime,
};
use crate::{
    browser::BrowserLoginState,
    metrics::{Metrics, UpstreamTokenEvent},
    oidc::{
        method::OidcMethod,
        upstream::{UpstreamBinding, UpstreamCipher},
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
                upstream
                    .revocations
                    .try_send(Revocation {
                        method: method.clone(),
                        refresh_token: Zeroizing::new(grant.refresh_token().to_owned()),
                        metrics: metrics.clone(),
                    })
                    .is_ok()
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
