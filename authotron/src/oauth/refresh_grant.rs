// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Refresh-token issuance at code exchange, the `refresh_token` grant and RFC 7009
//! revocation. Every refresh re-runs augmentation and current policy before rotating.

use super::{
    authentication::projection,
    refresh::{
        Presented, RefreshGrant, RefreshStoreError, RefreshToken, Rotated, effective_absolute,
    },
    refresh_store::MemoryRefreshStore,
    runtime::OAuthRuntime,
    store::RedeemedAuthorization,
    tokens::{TokenError, TokenIssuer, TokenResponse},
    valkey_refresh::ValkeyRefreshStore,
};
use crate::{
    auth::Auth,
    config::{OAuthPolicyError, RefreshTokenPolicy},
    metrics::{Metrics, RefreshTokenEvent},
    models::user::User,
};
use std::time::Duration;

pub(crate) enum RefreshBackend {
    Memory(Box<MemoryRefreshStore>),
    Valkey(Box<ValkeyRefreshStore>),
}
macro_rules! refresh_dispatch {
    ($backend:expr, $method:ident($($arg:expr),*)) => {
        match $backend {
            RefreshBackend::Memory(store) => store.$method($($arg),*).await,
            RefreshBackend::Valkey(store) => store.$method($($arg),*).await,
        }
    };
}

/// Token-endpoint outcomes; mapped to RFC 6749 §5.2 / RFC 8707 error codes by the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshGrantError {
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    Unavailable,
}
impl From<RefreshStoreError> for RefreshGrantError {
    fn from(_: RefreshStoreError) -> Self {
        Self::Unavailable
    }
}

pub(crate) struct RefreshRequest<'a> {
    pub token: &'a str,
    pub client_id: &'a str,
    pub scope: Option<&'a str>,
    pub resource: Option<&'a str>,
}

/// Space-delimited scope narrowing (RFC 6749 §6). Valid: `read`, `read write`.
/// Invalid: empty, `read  write` (empty item), ` read`, `read read` (duplicate).
fn narrowed_scopes(
    requested: Option<&str>,
    granted: &[String],
) -> Result<Vec<String>, RefreshGrantError> {
    let Some(requested) = requested else {
        return Ok(granted.to_vec());
    };
    let mut scopes: Vec<String> = Vec::new();
    for scope in requested.split(' ') {
        if scope.is_empty()
            || scopes.iter().any(|s| s == scope)
            || !granted.iter().any(|s| s == scope)
        {
            return Err(RefreshGrantError::InvalidScope);
        }
        scopes.push(scope.into());
    }
    Ok(scopes)
}

impl OAuthRuntime {
    fn refresh_policy(&self, client_id: &str) -> Option<&RefreshTokenPolicy> {
        self.config
            .clients
            .iter()
            .find(|client| client.client_id == client_id)
            .map(|client| &client.refresh_tokens)
            .filter(|policy| policy.enabled)
    }
    pub(crate) fn refresh_supported(&self) -> bool {
        self.refresh.is_some()
    }
    /// Signs the access token for consumed code proof and, for opted-in clients,
    /// starts a refresh-token family bound to the same client, resource and scopes.
    pub(crate) async fn exchange(
        &self,
        proof: RedeemedAuthorization,
        metrics: &Metrics,
    ) -> Result<TokenResponse, RefreshGrantError> {
        let code = proof.grant();
        let grant = RefreshGrant {
            client_id: code.client_id().into(),
            resource: code.resource().into(),
            scopes: code.scopes().to_vec(),
            username: code.as_user().username.clone(),
            realm: code.as_user().realm.clone(),
            provider_roles: code.provider_roles().to_vec(),
        };
        let response = self
            .token(proof)
            .map_err(|_| RefreshGrantError::Unavailable)?;
        let (Some(backend), Some(policy)) = (&self.refresh, self.refresh_policy(&grant.client_id))
        else {
            return Ok(response);
        };
        let token = RefreshToken::generate()?;
        let now = self
            .now()
            .await
            .map_err(|_| RefreshGrantError::Unavailable)?;
        refresh_dispatch!(backend, issue(&grant, token.hash(), now, policy))?;
        metrics.record_refresh_token(RefreshTokenEvent::Issued);
        Ok(response.with_refresh_token(&token))
    }

    pub(crate) async fn refresh(
        &self,
        request: RefreshRequest<'_>,
        auth: &Auth,
        metrics: &Metrics,
        augmentation_timeout: Duration,
    ) -> Result<TokenResponse, RefreshGrantError> {
        use RefreshGrantError::*;
        let backend = self.refresh.as_ref().ok_or(InvalidGrant)?;
        let presented = RefreshToken::parse(request.token).ok_or(InvalidGrant)?;
        let hash = presented.hash();
        let now = self.now().await.map_err(|_| Unavailable)?;
        let family = match refresh_dispatch!(backend, lookup(&hash, now))? {
            Presented::Current(family) => family,
            Presented::Reused { .. } => {
                metrics.record_refresh_token(RefreshTokenEvent::ReuseDetected);
                metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
                return Err(InvalidGrant);
            }
            Presented::Grace | Presented::Missing => return Err(InvalidGrant),
        };
        // A token presented by another client is rejected without touching the family.
        if family.grant.client_id != request.client_id {
            return Err(InvalidGrant);
        }
        let family_id = family.family_id.clone();
        let revoke = move |reason: RefreshGrantError| async move {
            refresh_dispatch!(backend, revoke_family(&family_id))?;
            metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
            Err::<TokenResponse, _>(reason)
        };
        let Some(policy) = self.refresh_policy(request.client_id) else {
            return revoke(InvalidGrant).await;
        };
        let ceiling =
            match effective_absolute(family.created_at_ms, family.absolute_expires_at_ms, policy) {
                Some(ceiling) if now < ceiling => ceiling,
                _ => return revoke(InvalidGrant).await,
            };
        if request
            .resource
            .is_some_and(|resource| resource != family.grant.resource)
        {
            return Err(InvalidTarget);
        }
        let scopes = narrowed_scopes(request.scope, &family.grant.scopes)?;
        let user = User::new(
            family.grant.realm.clone(),
            family.grant.username.clone(),
            Some(family.grant.provider_roles.clone()),
            None,
            None,
            None,
        );
        let user = tokio::time::timeout(
            augmentation_timeout,
            auth.check_augmenters_strict(user, metrics),
        )
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)?;
        let user = projection(&user).map_err(|_| InvalidGrant)?;
        let issuer = TokenIssuer::new(&self.config, &self.keys).map_err(|_| Unavailable)?;
        let response = issuer
            .issue_refreshed(
                request.client_id,
                &family.grant.resource,
                &scopes,
                &user,
                now,
            )
            .map_err(|error| match error {
                TokenError::Policy(OAuthPolicyError::InvalidScope) => InvalidScope,
                TokenError::Policy(_) | TokenError::Identity => InvalidGrant,
                _ => Unavailable,
            })?;
        let next = RefreshToken::generate()?;
        match refresh_dispatch!(
            backend,
            rotate(
                &family.family_id,
                &hash,
                next.hash(),
                now,
                policy.idle_ttl_seconds,
                ceiling
            )
        )? {
            Rotated::Rotated => {
                metrics.record_refresh_token(RefreshTokenEvent::Rotated);
                Ok(response.with_refresh_token(&next))
            }
            Rotated::Stale => Err(InvalidGrant),
        }
    }

    /// RFC 7009 §2.2: unknown, malformed or foreign tokens succeed without effect.
    pub(crate) async fn revoke(
        &self,
        token: &str,
        client_id: &str,
        metrics: &Metrics,
    ) -> Result<(), RefreshGrantError> {
        let (Some(backend), Some(token)) = (&self.refresh, RefreshToken::parse(token)) else {
            return Ok(());
        };
        if refresh_dispatch!(backend, revoke_token(&token.hash(), client_id))? {
            metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_narrowing_accepts_only_unique_granted_subsets() {
        let granted = vec!["read".to_string(), "write".to_string()];
        assert_eq!(narrowed_scopes(None, &granted), Ok(granted.clone()));
        assert_eq!(
            narrowed_scopes(Some("write"), &granted),
            Ok(vec!["write".into()])
        );
        assert_eq!(
            narrowed_scopes(Some("write read"), &granted),
            Ok(vec!["write".into(), "read".into()])
        );
        for invalid in [
            "",
            " read",
            "read ",
            "read  write",
            "read read",
            "admin",
            "read admin",
        ] {
            assert_eq!(
                narrowed_scopes(Some(invalid), &granted),
                Err(RefreshGrantError::InvalidScope),
                "{invalid:?}"
            );
        }
    }
}
