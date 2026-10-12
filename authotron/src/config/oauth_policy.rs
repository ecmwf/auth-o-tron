// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit resource permissions for OAuth grants; no authentication or I/O.

use super::OAuthConfig;
use authotron_types::User;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthResource {
    pub resource: String,
    #[schemars(length(min = 1, max = 16))]
    pub allowed_realms: Vec<String>,
    #[schemars(length(min = 1, max = 32))]
    pub scopes: Vec<ResourceScope>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope {
    pub name: String,
    #[schemars(length(max = 32))]
    pub required_roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientResource {
    pub resource: String,
    #[schemars(length(min = 1, max = 32))]
    pub scopes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GrantedScopes(pub Vec<String>);

/// Fixed diagnostics contain no identity, attributes, or submitted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthPolicyError {
    InvalidConfiguration,
    InvalidClient,
    InvalidResource,
    InvalidScope,
    AccessDenied,
}

fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn realm(value: &str) -> bool {
    text(value)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

/// RFC 6749 scope-token: valid `notifications:read`; invalid `read write`.
fn scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| matches!(c, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn unique<T: Eq + std::hash::Hash>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn find<T>(entries: &[T], mut predicate: impl FnMut(&T) -> bool) -> Option<&T> {
    entries.iter().find(|entry| predicate(entry))
}

/// Valid `https://mcp.example.org/mcp`; invalid `https://MCP.example.org/mcp?x=1`.
fn resource_uri(value: &str) -> bool {
    if value.len() > 2048 || !super::oauth::valid_percent_triplets(value) {
        return false;
    }
    let Ok(uri) = value.parse::<http::Uri>() else {
        return false;
    };
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && url.host_str().is_some()
        && !value.contains(['@', '\\'])
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && url.username().is_empty()
        && url.password().is_none()
        && url.port() != Some(0)
        && url.query().is_none()
        && url.fragment().is_none()
        && (value == url.as_str()
            || (url.path() == "/" && url.as_str().strip_suffix('/') == Some(value)))
}

impl OAuthConfig {
    pub(super) fn validate_resources(&self) -> Result<(), &'static str> {
        let error =
            "invalid OAuth resource/scope policy: check bounds, unique names and client references";
        if self.resources.len() > 64 || !unique(self.resources.iter().map(|r| &r.resource)) {
            return Err(error);
        }
        for resource in &self.resources {
            if !resource_uri(&resource.resource)
                || !(1..=16).contains(&resource.allowed_realms.len())
                || !resource.allowed_realms.iter().all(|r| realm(r))
                || !unique(&resource.allowed_realms)
                || !(1..=32).contains(&resource.scopes.len())
                || !unique(resource.scopes.iter().map(|s| &s.name))
                || resource.scopes.iter().any(|s| {
                    !scope(&s.name)
                        || s.required_roles.len() > 32
                        || !s.required_roles.iter().all(|r| text(r))
                        || !unique(&s.required_roles)
                })
            {
                return Err(error);
            }
        }
        for client in &self.clients {
            if client.resources.len() > 64 || !unique(client.resources.iter().map(|r| &r.resource))
            {
                return Err(error);
            }
            for binding in &client.resources {
                let registered =
                    find(&self.resources, |r| r.resource == binding.resource).ok_or(error)?;
                if !(1..=32).contains(&binding.scopes.len())
                    || !unique(&binding.scopes)
                    || binding
                        .scopes
                        .iter()
                        .any(|s| !registered.scopes.iter().any(|known| &known.name == s))
                {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Caller must supply a freshly verified identity with trusted, successful augmentation.
    /// Identity role data must be bounded by the caller before policy evaluation.
    /// This function does not authenticate users or repair fail-open augmentation upstream.
    pub fn authorize_scopes(
        &self,
        client_id: &str,
        resource: &str,
        requested_scopes: &[String],
        verified_user: &User,
    ) -> Result<GrantedScopes, OAuthPolicyError> {
        use OAuthPolicyError::*;
        self.validate().map_err(|_| InvalidConfiguration)?;
        let client = find(&self.clients, |c| c.client_id == client_id).ok_or(InvalidClient)?;
        let policy = find(&self.resources, |r| r.resource == resource).ok_or(InvalidResource)?;
        let binding = find(&client.resources, |r| r.resource == resource).ok_or(AccessDenied)?;
        if !(1..=32).contains(&requested_scopes.len())
            || !unique(requested_scopes)
            || !requested_scopes.iter().all(|s| scope(s))
        {
            return Err(InvalidScope);
        }
        if !text(&verified_user.username)
            || !realm(&verified_user.realm)
            || !policy.allowed_realms.contains(&verified_user.realm)
        {
            return Err(AccessDenied);
        }
        for requested in requested_scopes {
            let permission = find(&policy.scopes, |s| &s.name == requested).ok_or(InvalidScope)?;
            if !binding.scopes.contains(requested)
                || !permission
                    .required_roles
                    .iter()
                    .all(|r| verified_user.roles.contains(r))
            {
                return Err(AccessDenied);
            }
        }
        Ok(GrantedScopes(requested_scopes.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OAuthPolicyError::*;
    use serde_json::{Value, json};
    const RESOURCE: &str = "https://mcp.example.org/mcp";

    fn fixture() -> Value {
        json!({"clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": RESOURCE, "scopes": ["read", "open"]}]}], "resources": [{"resource": RESOURCE, "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader", "member"]}, {"name": "open", "required_roles": []}, {"name": "admin", "required_roles": []}]}]})
    }

    fn grant(
        config: &OAuthConfig,
        scopes: &[&str],
        user: &User,
    ) -> Result<GrantedScopes, OAuthPolicyError> {
        config.authorize_scopes(
            "desktop",
            RESOURCE,
            &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            user,
        )
    }

    #[test]
    fn grants_are_explicit_and_require_every_role_and_trusted_realm() {
        let config: OAuthConfig = serde_json::from_value(fixture()).unwrap();
        let mut user = User {
            username: "alice".into(),
            realm: "local".into(),
            roles: vec!["reader".into(), "member".into(), "unmapped".into()],
            ..Default::default()
        };
        assert_eq!(
            grant(&config, &["open", "read"], &user),
            Ok(GrantedScopes(vec!["open".into(), "read".into()]))
        );
        user.roles.pop();
        user.roles.pop();
        user.attributes
            .insert("roles".into(), "reader member".into());
        user.scopes.insert(RESOURCE.into(), vec!["read".into()]);
        assert_eq!(grant(&config, &["open", "read"], &user), Err(AccessDenied));
        user.roles.clear();
        assert!(grant(&config, &["open"], &user).is_ok());
        user.realm = "other".into();
        assert_eq!(grant(&config, &["open"], &user), Err(AccessDenied));
        user.realm = "local".into();
        user.username.clear();
        assert_eq!(grant(&config, &["open"], &user), Err(AccessDenied));
    }

    #[test]
    fn requests_fail_without_narrowing_or_implicit_grants() {
        let mut config: OAuthConfig = serde_json::from_value(fixture()).unwrap();
        let user = User {
            username: "alice".into(),
            realm: "local".into(),
            ..Default::default()
        };
        for scopes in [
            vec![],
            vec!["open", "open"],
            vec!["open", "unknown"],
            vec!["read write"],
            vec!["unmapped"],
            vec!["open"; 33],
        ] {
            assert_eq!(grant(&config, &scopes, &user), Err(InvalidScope));
        }
        assert_eq!(grant(&config, &["admin"], &user), Err(AccessDenied));
        assert_eq!(
            config.authorize_scopes("unknown", RESOURCE, &["open".into()], &user),
            Err(InvalidClient)
        );
        for suffix in ["/", "/child", "?x=1"] {
            let resource = format!("{RESOURCE}{suffix}");
            assert_eq!(
                config.authorize_scopes("desktop", &resource, &["open".into()], &user),
                Err(InvalidResource)
            );
        }
        config.clients[0].resources.clear();
        assert_eq!(grant(&config, &["open"], &user), Err(AccessDenied));
    }

    #[test]
    fn malformed_policy_and_duplicate_or_dangling_references_are_rejected() {
        for (pointer, value) in [
            ("/resources/0/resource", json!("http://m.example.org/mcp")),
            ("/resources/0/allowed_realms", json!([])),
            ("/resources/0/allowed_realms", json!(["local", "local"])),
            ("/resources/0/scopes/0/name", json!("read write")),
            ("/resources/0/scopes/0/required_roles", json!(["reader\n"])),
            (
                "/clients/0/resources/0/resource",
                json!("https://x.org/mcp"),
            ),
            ("/clients/0/resources/0/scopes", json!(["unknown"])),
            ("/clients/0/resources/0/scopes", json!(["open", "open"])),
        ] {
            let mut input = fixture();
            *input.pointer_mut(pointer).unwrap() = value;
            let config: OAuthConfig = serde_json::from_value(input).unwrap();
            assert!(config.validate().is_err(), "{pointer}");
            assert_eq!(
                grant(&config, &["open"], &User::default()),
                Err(InvalidConfiguration)
            );
        }
        for pointer in ["/resources", "/resources/0/scopes", "/clients/0/resources"] {
            let mut input = fixture();
            let array = input.pointer_mut(pointer).unwrap().as_array_mut().unwrap();
            array.push(array[0].clone());
            assert!(
                serde_json::from_value::<OAuthConfig>(input)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn canonical_resources_accept_both_root_forms_without_normalizing_requests() {
        for uri in ["https://mcp.example.org", "https://mcp.example.org/"] {
            assert!(resource_uri(uri));
        }
        for uri in [
            "HTTPS://mcp.example.org/mcp",
            "https://MCP.example.org/mcp",
            "https://MCP.example.org",
            "https://mcp.example.org:443",
            "https://mcp.example.org:443/mcp",
            "https://mcp.example.org:0/mcp",
            "https://mcp.example.org:/mcp",
            "https:///mcp",
            "https://mcp.example.org/a/../mcp",
            "https://user@mcp.example.org/mcp",
            "https://mcp.example.org/mcp?q=1",
            "https://mcp.example.org/mcp#fragment",
        ] {
            assert!(!resource_uri(uri), "{uri}");
        }
        let mut config: OAuthConfig = serde_json::from_value(fixture()).unwrap();
        let root = "https://mcp.example.org";
        config.resources[0].resource = root.into();
        config.clients[0].resources[0].resource = root.into();
        let user = User {
            username: "alice".into(),
            realm: "local".into(),
            ..Default::default()
        };
        assert!(
            config
                .authorize_scopes("desktop", root, &["open".into()], &user)
                .is_ok()
        );
        assert_eq!(
            config.authorize_scopes("desktop", &format!("{root}/"), &["open".into()], &user),
            Err(OAuthPolicyError::InvalidResource)
        );
    }
}
