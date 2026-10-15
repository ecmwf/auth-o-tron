// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Typed, policy-checked access tokens issued from atomic code-redemption proof.

use super::{
    code_grant::CodeGrant, keys::KeyManager, refresh::RefreshToken, store::RedeemedAuthorization,
};
use crate::config::{OAuthConfig, OAuthPolicyError};
use authotron_types::User;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header, encode};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Configuration,
    Identity,
    Policy(OAuthPolicyError),
    Time,
    Signing,
    Size,
    Redemption,
}
impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OAuth token issuance: {self:?}")
    }
}
impl std::error::Error for TokenError {}

/// A bearer credential: deliberately not Debug. Serialized by the HTTP token endpoint.
#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}
impl TokenResponse {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
    pub(super) fn with_refresh_token(mut self, token: &RefreshToken) -> Self {
        self.refresh_token = Some(token.as_secret_str().into());
        self
    }
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: String,
    aud: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
    client_id: &'a str,
    scope: String,
    /// The user's realm, only for resources with identity claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    realm: Option<&'a str>,
    roles: Vec<String>,
}

/// Keeps configuration and validated signing keys immutably borrowed for its lifetime.
pub struct TokenIssuer<'a> {
    config: &'a OAuthConfig,
    keys: &'a KeyManager,
}
impl<'a> TokenIssuer<'a> {
    pub fn new(config: &'a OAuthConfig, keys: &'a KeyManager) -> Result<Self, TokenError> {
        config.validate().map_err(|_| TokenError::Configuration)?;
        if config
            .issuer
            .as_ref()
            .is_none_or(|issuer| issuer.len() > 2048)
            || config
                .signing
                .as_ref()
                .is_some_and(|signing| !keys.matches_config(signing))
        {
            return Err(TokenError::Configuration);
        }
        Ok(Self { config, keys })
    }
    /// Consumes atomic code-redemption proof, with no request-selected grant overrides.
    pub fn issue_from_redeemed(
        &self,
        redeemed: RedeemedAuthorization,
    ) -> Result<TokenResponse, TokenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::Time)?
            .as_millis()
            .try_into()
            .map_err(|_| TokenError::Time)?;
        self.issue_from_redeemed_at(redeemed, now)
    }
    fn issue_from_redeemed_at(
        &self,
        redeemed: RedeemedAuthorization,
        now_ms: u64,
    ) -> Result<TokenResponse, TokenError> {
        if Some(redeemed.issuer()) != self.config.issuer.as_deref() {
            return Err(TokenError::Redemption);
        }
        let bytes = redeemed
            .grant()
            .encode()
            .map_err(|_| TokenError::Redemption)?;
        let grant =
            CodeGrant::decode(&bytes, self.config, now_ms).map_err(|_| TokenError::Redemption)?;
        // Reuse the fixed signer, identity bounds and required-role projection at this same time.
        self.issue_at(
            grant.client_id(),
            grant.resource(),
            grant.scopes(),
            grant.as_user(),
            now_ms / 1000,
        )
    }
    /// Refresh-grant issuance: the caller supplies a freshly augmented identity and the
    /// family's bound client/resource; current scope policy is re-evaluated here.
    pub(super) fn issue_refreshed(
        &self,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        user: &User,
        now_ms: u64,
    ) -> Result<TokenResponse, TokenError> {
        self.issue_at(client_id, resource, scopes, user, now_ms / 1000)
    }
    /// Exercises signing directly in unit tests without constructing redemption proof.
    #[cfg(test)]
    fn issue_access_token(
        &self,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        verified_user: &User,
    ) -> Result<TokenResponse, TokenError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::Time)?
            .as_secs();
        self.issue_at(client_id, resource, scopes, verified_user, now)
    }
    fn issue_at(
        &self,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        user: &User,
        now: u64,
    ) -> Result<TokenResponse, TokenError> {
        let bounded =
            |s: &str| !s.trim().is_empty() && s.len() <= 128 && !s.chars().any(char::is_control);
        if !bounded(&user.username)
            || !bounded(&user.realm)
            || user.roles.len() > 64
            || !user.roles.iter().all(|r| bounded(r))
        {
            return Err(TokenError::Identity);
        }
        let granted = self
            .config
            .authorize_scopes(client_id, resource, scopes, user)
            .map_err(TokenError::Policy)?;
        let policy = self
            .config
            .resources
            .iter()
            .find(|r| r.resource == resource)
            .ok_or(TokenError::Configuration)?;
        // Identity claims name the user's roles, at most 64 since the identity check
        // above bounds them; otherwise `roles` lists the granted scopes' required roles.
        let (realm, roles) = match &policy.identity_claims {
            Some(claims) => (Some(user.realm.as_str()), claims.select(&user.roles)),
            None => {
                let mut roles = Vec::new();
                for scope in &granted.0 {
                    let permission = policy
                        .scopes
                        .iter()
                        .find(|s| &s.name == scope)
                        .ok_or(TokenError::Configuration)?;
                    for role in &permission.required_roles {
                        if !roles.contains(role) {
                            roles.push(role.clone());
                        }
                    }
                }
                (None, roles)
            }
        };
        if roles.len() > 64 {
            return Err(TokenError::Identity);
        }
        let ttl = self.config.access_token_ttl_seconds;
        let exp = now
            .checked_add(ttl)
            .filter(|exp| *exp <= 253402300799)
            .ok_or(TokenError::Time)?;
        let issuer = self
            .config
            .issuer
            .as_deref()
            .ok_or(TokenError::Configuration)?;
        let scope = granted.0.join(" ");
        let claims = Claims {
            iss: issuer,
            sub: subject(issuer, &user.realm, &user.username),
            aud: resource,
            iat: now,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            client_id,
            scope: scope.clone(),
            realm,
            roles,
        };
        let (kid, key) = self.keys.active_signer();
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(kid.into());
        let access_token = encode(&header, &claims, key).map_err(|_| TokenError::Signing)?;
        if access_token.len() > 32 * 1024 {
            return Err(TokenError::Size);
        }
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ttl,
            scope,
            refresh_token: None,
        })
    }
}

fn subject(issuer: &str, realm: &str, username: &str) -> String {
    let mut digest = Sha256::new();
    for value in [issuer, realm, username] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!(
        "urn:authotron:subject:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::OAuthSigningConfig;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use serde_json::{Value, json};
    use std::io::Write;
    const ISS: &str = "https://login.example.org/";
    const RESOURCE: &str = "https://mcp.example.org/mcp";

    fn fixture() -> (tempfile::NamedTempFile, OAuthConfig, KeyManager, User) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let pem = super::super::keys::tests::keys()[0]
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        let signing: OAuthSigningConfig = serde_json::from_value(json!({"active_kid": "active", "keys": [{"kid": "active", "private_key_file": file.path()}]})).unwrap();
        let keys = KeyManager::load(&signing).unwrap();
        let config = serde_json::from_value(json!({"issuer": ISS, "signing": signing,
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": RESOURCE, "scopes": ["read", "open"]}]}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader", "member"]}, {"name": "open", "required_roles": []}]}]})).unwrap();
        let user = User {
            username: "alice".into(),
            realm: "local".into(),
            roles: vec!["reader".into(), "member".into(), "unrelated".into()],
            attributes: [("credential".into(), "must-not-appear".into())].into(),
            ..Default::default()
        };
        (file, config, keys, user)
    }
    fn validation() -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISS]);
        validation.set_audience(&[RESOURCE]);
        validation
    }
    fn decoding(keys: &KeyManager) -> DecodingKey {
        let public = &keys.jwks().keys[0];
        DecodingKey::from_rsa_components(&public.n, &public.e).unwrap()
    }
    async fn redeemed(
        config: &OAuthConfig,
    ) -> (
        super::super::store::MemoryTransactionStore,
        super::super::codes::IssuedCode,
        RedeemedAuthorization,
    ) {
        use super::super::{
            codes::CodeIssueOutcome,
            context::AuthenticatedAuthorization,
            store::{MemoryTransactionStore, tests::request},
        };
        let (_, _, identity) = super::super::context::tests::fixture().await;
        let store = MemoryTransactionStore::new(std::sync::Arc::new(config.clone())).unwrap();
        let created = store.create(request(config), [7; 32]).await.unwrap();
        let source = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let now = identity.verified_at_ms();
        let context =
            AuthenticatedAuthorization::new_bound(source, identity, &[7; 32], config, now).unwrap();
        store
            .promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let csrf = store.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        let CodeIssueOutcome::Issued(code) = store
            .issue_code(&created.id, &[7; 32], csrf.as_secret_str(), "approve")
            .await
            .unwrap()
        else {
            panic!("issued code required")
        };
        let proof = redeem(&store, &code).await.unwrap();
        (store, code, proof)
    }
    async fn redeem(
        store: &super::super::store::MemoryTransactionStore,
        code: &super::super::codes::IssuedCode,
    ) -> Result<RedeemedAuthorization, super::super::codes::CodeStoreError> {
        store
            .redeem_code(
                code.code(),
                "desktop",
                code.redirect_uri(),
                RESOURCE,
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            )
            .await
    }
    #[tokio::test]
    async fn redeemed_bridge_signs_only_stored_grant_and_keeps_code_consumed() {
        let (_file, mut config, keys, _) = fixture();
        config.resources[0].scopes[0].required_roles = vec!["reader".into()];
        let (store, code, proof) = redeemed(&config).await;
        let ceiling = proof.grant().expires_at_ms();
        let response = TokenIssuer::new(&config, &keys)
            .unwrap()
            .issue_from_redeemed(proof)
            .unwrap();
        let header = decode_header(response.access_token()).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.kid.as_deref(), Some(keys.active_kid()));
        let claims = decode::<Value>(response.access_token(), &decoding(&keys), &validation())
            .unwrap()
            .claims;
        assert_eq!(claims["iss"], ISS);
        assert_eq!(claims["aud"], RESOURCE);
        assert_eq!(claims["client_id"], "desktop");
        assert_eq!(claims["scope"], "read");
        assert_eq!(claims["roles"], json!(["reader"]));
        assert_eq!(claims["sub"], subject(ISS, "local", "alice"));
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            config.access_token_ttl_seconds
        );
        assert!(claims["exp"].as_u64().unwrap() * 1000 > ceiling);
        assert_eq!(
            redeem(&store, &code).await.err(),
            Some(super::super::codes::CodeStoreError::Missing)
        );
    }
    #[tokio::test]
    async fn redeemed_bridge_rechecks_literal_issuer_policy_ttl_freshness_and_time() {
        let (_file, config, keys, _) = fixture();
        for case in 0..8 {
            let (store, code, proof) = redeemed(&config).await;
            let mut current = config.clone();
            let mut now = proof.grant().issued_at_ms();
            match case {
                0 => current.issuer = Some("https://other.example.org/".into()),
                1 => current.issuer = Some(ISS.trim_end_matches('/').into()),
                2 => current.resources[0].scopes[0]
                    .required_roles
                    .push("revoked".into()),
                3 => current.clients[0].resources.clear(),
                4 => {
                    current.authorization_code_ttl_seconds = 30;
                    now += 30_000;
                }
                5 => {
                    current.max_authentication_age_seconds = 1;
                    now = proof.grant().verified_at_ms() + 1000;
                }
                6 => now -= 1,
                _ => now = proof.grant().expires_at_ms(),
            }
            let issuer = TokenIssuer::new(&current, &keys).unwrap();
            assert_eq!(
                issuer.issue_from_redeemed_at(proof, now).err(),
                Some(TokenError::Redemption)
            );
            assert_eq!(
                redeem(&store, &code).await.err(),
                Some(super::super::codes::CodeStoreError::Missing)
            );
        }
    }
    #[tokio::test]
    async fn signing_failure_after_redemption_does_not_restore_code() {
        let (_file, config, mut keys, _) = fixture();
        let (store, code, proof) = redeemed(&config).await;
        // Fault injection affects only the test key manager, after validated RSA loading.
        super::super::keys::tests::break_signer(&mut keys);
        let issuer = TokenIssuer::new(&config, &keys).unwrap();
        assert_eq!(
            issuer.issue_from_redeemed(proof).err(),
            Some(TokenError::Signing)
        );
        assert_eq!(
            redeem(&store, &code).await.err(),
            Some(super::super::codes::CodeStoreError::Missing)
        );
    }
    #[test]
    fn fixed_header_claims_projection_and_validation() {
        let (_file, config, keys, user) = fixture();
        let issuer = TokenIssuer::new(&config, &keys).unwrap();
        let scopes = vec!["open".into(), "read".into()];
        let response = issuer
            .issue_access_token("desktop", RESOURCE, &scopes, &user)
            .unwrap();
        let header = decode_header(response.access_token()).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.kid.as_deref(), Some(keys.active_kid()));
        let claims = decode::<Value>(response.access_token(), &decoding(&keys), &validation())
            .unwrap()
            .claims;
        assert_eq!(claims["iss"], ISS);
        assert_eq!(claims["aud"], RESOURCE);
        assert_eq!(claims["client_id"], "desktop");
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            300
        );
        assert_eq!(claims["roles"], json!(["reader", "member"]));
        assert_eq!(claims["scope"], "open read");
        let object = claims.as_object().unwrap();
        let mut names = object.keys().map(String::as_str).collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names.join(" "),
            "aud client_id exp iat iss jti roles scope sub"
        );
        let other = issuer
            .issue_access_token("desktop", RESOURCE, &scopes, &user)
            .unwrap();
        let other = decode::<Value>(other.access_token(), &decoding(&keys), &validation())
            .unwrap()
            .claims;
        assert_eq!(claims["sub"], other["sub"]);
        assert_ne!(claims["jti"], other["jti"]);
        let jti = uuid::Uuid::parse_str(claims["jti"].as_str().unwrap()).unwrap();
        assert_eq!(jti.get_version_num(), 4);
        let key = decoding(&keys);
        let token = response.access_token();
        for (iss, aud) in [
            ("https://wrong.example.org", RESOURCE),
            (ISS, "https://other.example.org/mcp"),
        ] {
            let mut v = validation();
            v.set_issuer(&[iss]);
            v.set_audience(&[aud]);
            assert!(decode::<Value>(token, &key, &v).is_err());
        }
        assert!(
            decode::<Value>(
                token,
                &DecodingKey::from_secret(b"legacy"),
                &Validation::new(Algorithm::HS256)
            )
            .is_err()
        );
        let refresh = RefreshToken::generate().unwrap();
        let with_refresh = serde_json::to_value(
            issuer
                .issue_access_token("desktop", RESOURCE, &scopes, &user)
                .unwrap()
                .with_refresh_token(&refresh),
        )
        .unwrap();
        assert_eq!(with_refresh["refresh_token"], refresh.as_secret_str());
        // Signing alone never issues a refresh token; only an opted-in exchange adds one.
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["token_type"], "Bearer");
        assert_eq!(response["expires_in"], 300);
        assert!(response.get("refresh_token").is_none());
    }
    #[test]
    fn identity_claims_carry_the_realm_and_the_named_roles_of_the_user() {
        let (_file, mut config, keys, mut user) = fixture();
        let claims_of = |config: &OAuthConfig, user: &User| {
            let issuer = TokenIssuer::new(config, &keys).unwrap();
            let response = issuer.issue_access_token("desktop", RESOURCE, &["read".into()], user);
            let token = response.unwrap();
            decode::<Value>(token.access_token(), &decoding(&keys), &validation())
                .unwrap()
                .claims
        };
        user.roles.push("reader".into());
        for (named, expected) in [
            (
                json!(["unrelated", "reader", "absent"]),
                json!(["reader", "unrelated"]),
            ),
            (json!(["*"]), json!(["member", "reader", "unrelated"])),
            (json!(["absent"]), json!([])),
        ] {
            config.resources[0].identity_claims =
                Some(serde_json::from_value(json!({"roles": named})).unwrap());
            let claims = claims_of(&config, &user);
            assert_eq!(claims["realm"], "local");
            assert_eq!(claims["roles"], expected, "{named}");
            // Scope checks are unchanged: `read` still needs `reader` and `member`.
            assert_eq!(claims["scope"], "read");
        }
        // Every role a token can carry: the identity check allows at most 64.
        config.resources[0].identity_claims =
            Some(serde_json::from_value(json!({"roles": ["*"]})).unwrap());
        user.roles = (0..62).map(|n| format!("role-{n:02}")).collect();
        user.roles.extend(["member".into(), "reader".into()]);
        let claims = claims_of(&config, &user);
        assert_eq!(claims["roles"].as_array().unwrap().len(), 64);
        user.roles.push("role-64".into());
        let issuer = TokenIssuer::new(&config, &keys).unwrap();
        let refused = issuer.issue_access_token("desktop", RESOURCE, &["read".into()], &user);
        assert_eq!(refused.err(), Some(TokenError::Identity));
        // Without identity claims there is no realm claim, and `roles` stays the union
        // of the granted scopes' required roles, whatever else the user holds.
        config.resources[0].identity_claims = None;
        user.roles = ["unrelated", "member", "reader", "admin"]
            .map(String::from)
            .into();
        let claims = claims_of(&config, &user);
        assert!(claims.get("realm").is_none());
        assert_eq!(claims["roles"], json!(["reader", "member"]));
    }
    #[test]
    fn policy_identity_time_and_signing_binding_fail_closed() {
        let (_file, mut config, keys, mut user) = fixture();
        let issuer = TokenIssuer::new(&config, &keys).unwrap();
        let issue = |scope: &str, user: &User| {
            issuer.issue_access_token("desktop", RESOURCE, &[scope.into()], user)
        };
        for (client, resource, scopes) in [
            ("other", RESOURCE, vec!["read".into()]),
            (
                "desktop",
                "https://other.example.org/mcp",
                vec!["read".into()],
            ),
            ("desktop", RESOURCE, vec!["unknown".into()]),
        ] {
            assert!(matches!(
                issuer.issue_access_token(client, resource, &scopes, &user),
                Err(TokenError::Policy(_))
            ));
        }
        assert!(matches!(
            issuer.issue_at("desktop", RESOURCE, &["open".into()], &user, u64::MAX),
            Err(TokenError::Time)
        ));
        user.roles.clear();
        user.scopes.insert(RESOURCE.into(), vec!["read".into()]);
        assert!(issue("read", &user).is_err());
        assert!(issue("open", &user).is_ok());
        user.realm = "other".into();
        assert!(issue("open", &user).is_err());
        user.realm = "local".into();
        user.roles = vec!["x".into(); 65];
        assert_eq!(issue("open", &user).err(), Some(TokenError::Identity));
        let signing = config.signing.as_mut().unwrap();
        signing.keys[0].private_key_file = Some("/different/key.pem".into());
        assert!(matches!(
            TokenIssuer::new(&config, &keys),
            Err(TokenError::Configuration)
        ));
        config.signing = None;
        config.issuer = None;
        assert!(matches!(
            TokenIssuer::new(&config, &keys),
            Err(TokenError::Configuration)
        ));
        assert_ne!(subject(ISS, "ab", "c"), subject(ISS, "a", "bc"));
        assert_ne!(
            subject(ISS, "local", "alice"),
            subject("https://other.example.org", "local", "alice")
        );
    }
}
