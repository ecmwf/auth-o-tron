// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Maps validated ID token claims to an Auth-O-Tron identity: the configured username
//! claim, roles only through the explicit `role_map`, and the display attributes the
//! account page shows. Augmentation runs afterwards, as for every browser method. The
//! display name is kept apart from the identity.

use super::{OidcError, id_token::IdTokenClaims};
use crate::{
    config::{OidcMethodConfig, UsernameClaim},
    models::user::User,
};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

const USERNAME_BYTES: usize = 128;
const EMAIL_BYTES: usize = 320;
const DISPLAY_NAME_BYTES: usize = 256;
const MAX_UPSTREAM_ROLES: usize = 256;
/// Longest display name, in characters after trimming.
pub const DISPLAY_NAME_CHARS: usize = 64;

fn bounded(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

/// Only a JSON `true` counts; `"true"` strings and absent claims do not.
fn email_verified(claims: &Map<String, Value>) -> bool {
    claims.get("email_verified") == Some(&Value::Bool(true))
}

/// Follows a validated dotted path such as `realm_access.roles` through nested objects.
fn claim_at<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = path.split('.');
    let mut value = claims.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

/// Local roles granted by `role_map` for the upstream roles in `roles_claim`, sorted and
/// unique. A missing claim grants none; a claim that is not a string array of at most
/// 256 entries is an invalid identity.
fn mapped_roles(
    config: &OidcMethodConfig,
    claims: &Map<String, Value>,
) -> Result<Vec<String>, OidcError> {
    let Some(path) = &config.roles_claim else {
        return Ok(Vec::new());
    };
    let Some(value) = claim_at(claims, path) else {
        return Ok(Vec::new());
    };
    let upstream = value
        .as_array()
        .filter(|roles| roles.len() <= MAX_UPSTREAM_ROLES)
        .ok_or(OidcError::InvalidIdentity)?;
    let mut roles = BTreeSet::new();
    for role in upstream {
        let role = role.as_str().ok_or(OidcError::InvalidIdentity)?;
        if let Some(local) = config.role_map.get(role) {
            roles.insert(local.clone());
        }
    }
    Ok(roles.into_iter().collect())
}

/// Builds the identity for `config.realm`. Provider roles are only those mapped by
/// `role_map`; `email` is kept only when verified, `name` becomes `display_name`.
pub fn map_identity(config: &OidcMethodConfig, token: &IdTokenClaims) -> Result<User, OidcError> {
    let claims = &token.claims;
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    let username = match config.username_claim {
        UsernameClaim::Sub => Some(token.sub.as_str()),
        UsernameClaim::PreferredUsername => text("preferred_username"),
        UsernameClaim::Email => text("email").filter(|_| email_verified(claims)),
    }
    .filter(|username| bounded(username, USERNAME_BYTES))
    .ok_or(OidcError::InvalidIdentity)?;
    let roles = mapped_roles(config, claims)?;
    let mut attributes = HashMap::new();
    if let Some(email) = text("email").filter(|email| bounded(email, EMAIL_BYTES))
        && email_verified(claims)
    {
        attributes.insert("email".to_owned(), email.to_owned());
    }
    if let Some(name) = text("name").filter(|name| bounded(name, DISPLAY_NAME_BYTES)) {
        attributes.insert("display_name".to_owned(), name.to_owned());
    }
    Ok(User::new(
        config.realm.clone(),
        username.to_owned(),
        Some(roles),
        Some(attributes),
        None,
        None,
    ))
}

/// `value` trimmed, when it is 1-64 characters without control characters. Valid:
/// `" alice "` (as `alice`), `"Ada <Lovelace>"` (escaped where shown). Invalid: `""`,
/// `"a\u{7}b"`, `"a\nb"`, 65 characters.
pub fn display_text(value: &str) -> Option<&str> {
    let value = value.trim();
    let length = value.chars().count();
    ((1..=DISPLAY_NAME_CHARS).contains(&length) && !value.chars().any(char::is_control))
        .then_some(value)
}

/// The name shown for a sign-in: the string at `display_name_claim`, if it is a valid
/// [`display_text`]; otherwise `None`, and pages show the username. It takes no part in
/// authorization, roles, augmentation, tokens or the username.
pub fn display_name(config: &OidcMethodConfig, token: &IdTokenClaims) -> Option<String> {
    claim_at(&token.claims, &config.display_name_claim)
        .and_then(Value::as_str)
        .and_then(display_text)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(changes: Value) -> OidcMethodConfig {
        let mut value = json!({
            "id": "sso", "label": "SSO", "realm": "idp", "issuer": "https://idp.example.org",
            "client_id": "authotron", "client_auth": "none"
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        let config: OidcMethodConfig = serde_json::from_value(value).unwrap();
        config.validate().unwrap();
        config
    }
    fn token(claims: Value) -> IdTokenClaims {
        let claims = claims.as_object().unwrap().clone();
        IdTokenClaims {
            sub: claims["sub"].as_str().unwrap().to_owned(),
            claims,
        }
    }
    fn alice() -> Value {
        json!({
            "sub": "0f1d4c2e-0000-4000-8000-000000000001", "preferred_username": "alice",
            "email": "alice@example.org", "email_verified": true, "name": "Alice Demo",
            "realm_access": {"roles": ["mcp-demo", "offline_access", "admins"]},
            "groups": ["mcp-demo"]
        })
    }

    #[test]
    fn subject_is_the_default_username_and_upstream_roles_are_off() {
        let user = map_identity(&config(json!({})), &token(alice())).unwrap();
        assert_eq!(user.realm, "idp");
        assert_eq!(user.username, "0f1d4c2e-0000-4000-8000-000000000001");
        assert!(user.roles.is_empty());
        assert_eq!(
            user.attributes,
            HashMap::from([
                ("email".to_owned(), "alice@example.org".to_owned()),
                ("display_name".to_owned(), "Alice Demo".to_owned())
            ])
        );
        assert!(user.scopes.is_empty());
    }

    #[test]
    fn mutable_username_claims_are_opt_in_and_email_must_be_verified() {
        let preferred = config(json!({"username_claim": "preferred_username"}));
        assert_eq!(
            map_identity(&preferred, &token(alice())).unwrap().username,
            "alice"
        );
        let email = config(json!({"username_claim": "email"}));
        assert_eq!(
            map_identity(&email, &token(alice())).unwrap().username,
            "alice@example.org"
        );
        for verified in [json!(false), json!("true"), Value::Null] {
            let mut claims = alice();
            claims["email_verified"] = verified;
            let identity = map_identity(&email, &token(claims.clone()));
            assert_eq!(identity.err(), Some(OidcError::InvalidIdentity));
            // An unverified email is never shown either.
            let user = map_identity(&config(json!({})), &token(claims)).unwrap();
            assert!(!user.attributes.contains_key("email"));
        }
        for username in [
            json!(" "),
            json!("a\u{7}b"),
            json!("u".repeat(129)),
            json!(7),
        ] {
            let mut claims = alice();
            claims["preferred_username"] = username.clone();
            assert!(
                map_identity(&preferred, &token(claims)).is_err(),
                "{username}"
            );
        }
        let mut long_subject = alice();
        long_subject["sub"] = json!("s".repeat(129));
        assert!(map_identity(&config(json!({})), &token(long_subject)).is_err());
    }

    #[test]
    fn roles_come_only_from_the_role_map_allowlist() {
        let mapped = config(json!({
            "roles_claim": "realm_access.roles",
            "role_map": {"mcp-demo": "mcp-demo", "admins": "operator", "absent": "unused"}
        }));
        let user = map_identity(&mapped, &token(alice())).unwrap();
        assert_eq!(user.roles, ["mcp-demo", "operator"]);
        let groups = config(json!({"roles_claim": "groups", "role_map": {"mcp-demo": "reader"}}));
        assert_eq!(
            map_identity(&groups, &token(alice())).unwrap().roles,
            ["reader"]
        );
        let mut without = alice();
        without.as_object_mut().unwrap().remove("realm_access");
        assert!(
            map_identity(&mapped, &token(without))
                .unwrap()
                .roles
                .is_empty()
        );
        for invalid in [
            json!({"roles": "mcp-demo"}),
            json!({"roles": ["mcp-demo", 7]}),
            json!({"roles": vec!["x"; MAX_UPSTREAM_ROLES + 1]}),
        ] {
            let mut claims = alice();
            claims["realm_access"] = invalid;
            assert_eq!(
                map_identity(&mapped, &token(claims)).err(),
                Some(OidcError::InvalidIdentity)
            );
        }
    }

    #[test]
    fn display_name_comes_from_its_claim_and_falls_back_when_unusable() {
        let default = config(json!({}));
        assert_eq!(
            display_name(&default, &token(alice())).as_deref(),
            Some("alice")
        );
        let full = config(json!({"display_name_claim": "name"}));
        assert_eq!(
            display_name(&full, &token(alice())).as_deref(),
            Some("Alice Demo")
        );
        let nested = config(json!({"display_name_claim": "profile.short"}));
        let mut claims = alice();
        claims["profile"] = json!({"short": "  Ali  "});
        assert_eq!(
            display_name(&nested, &token(claims)).as_deref(),
            Some("Ali")
        );
        // HTML is kept as text here and escaped where it is shown.
        let mut claims = alice();
        claims["preferred_username"] = json!("<b>alice</b>");
        assert_eq!(
            display_name(&default, &token(claims)).as_deref(),
            Some("<b>alice</b>")
        );
        for unusable in [
            json!("a\u{7}b"),
            json!("line\nbreak"),
            json!("   "),
            json!("n".repeat(DISPLAY_NAME_CHARS + 1)),
            json!(7),
            json!(["alice"]),
        ] {
            let mut claims = alice();
            claims["preferred_username"] = unusable.clone();
            assert_eq!(display_name(&default, &token(claims)), None, "{unusable}");
        }
        let mut claims = alice();
        claims.as_object_mut().unwrap().remove("preferred_username");
        assert_eq!(display_name(&default, &token(claims.clone())), None);
        // The display name never changes the mapped identity.
        assert_eq!(
            map_identity(&default, &token(claims)).unwrap().username,
            map_identity(&default, &token(alice())).unwrap().username
        );
        let boundary = "é".repeat(DISPLAY_NAME_CHARS);
        assert_eq!(display_text(&boundary), Some(boundary.as_str()));
    }

    #[test]
    fn oversized_or_control_display_attributes_are_dropped() {
        let mut claims = alice();
        claims["email"] = json!(format!("{}@example.org", "e".repeat(EMAIL_BYTES)));
        claims["name"] = json!("Alice\nDemo");
        let user = map_identity(&config(json!({})), &token(claims)).unwrap();
        assert!(user.attributes.is_empty());
    }
}
