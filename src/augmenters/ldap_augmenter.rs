use std::sync::Arc;

use async_trait::async_trait;
use cached::proc_macro::cached;
use futures::lock::Mutex;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::augmenters::Augmenter;
use crate::models::user::User;

/// Configuration required to connect to LDAP and fetch user roles.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Hash, PartialEq, Eq, Clone)]
pub struct LDAPAugmenterConfig {
    pub name: String,
    pub realm: String,
    pub uri: String,
    pub search_base: String,
    pub filter: Option<String>,
    pub ldap_user: String,
    pub ldap_password: String,
}

/// An augmenter that queries LDAP for additional user roles.
pub struct LDAPAugmenter {
    config: LDAPAugmenterConfig,
}

impl LDAPAugmenter {
    /// Creates a new LDAPAugmenter with the given config.
    pub fn new(config: &LDAPAugmenterConfig) -> LDAPAugmenter {
        info!(
            "Creating LDAPAugmenter for realm='{}', name='{}'",
            config.realm, config.name
        );
        LDAPAugmenter {
            config: config.clone(),
        }
    }
}

/// A helper that attempts to parse out the "CN" component from a full LDAP DN string.
fn parse_cn(role: &str) -> Option<String> {
    role.split(',').find_map(|part| {
        let mut split = part.splitn(2, '=');
        match (split.next(), split.next()) {
            (Some("CN"), Some(cn)) => Some(cn.to_string()),
            _ => None,
        }
    })
}

/// This function looks up user roles in LDAP, caching results for 120 seconds.
/// We bind with a service account, search for the user by `uid`, and parse "memberOf" attributes.
#[cached(time = 120, sync_writes = "default")]
async fn retrieve_ldap_user_roles(
    config: LDAPAugmenterConfig,
    uid: String,
) -> Result<Vec<String>, String> {
    debug!(
        "Connecting to LDAP at {}, searching for user CN={}",
        config.uri, uid
    );

    let (conn, mut ldap) = LdapConnAsync::new(&config.uri)
        .await
        .map_err(|e| e.to_string())?;
    ldap3::drive!(conn);

    // We do a simple bind using the configured service account
    let bind_dn = format!(
        "CN={},OU=Connectors,OU=Service Accounts,DC=ecmwf,DC=int",
        &config.ldap_user
    );
    ldap.simple_bind(&bind_dn, &config.ldap_password)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let search_filter = format!("(&(objectClass=person)(cn={}))", uid);
    let (results, _res) = ldap
        .search(
            &config.search_base,
            Scope::Subtree,
            &search_filter,
            vec!["memberOf"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut roles = Vec::new();
    for entry in results {
        let search_entry = SearchEntry::construct(entry);
        if let Some(member_of) = search_entry.attrs.get("memberOf") {
            for role_dn in member_of {
                // If a filter is provided, only capture roles containing that string
                let passes_filter = config.filter.as_deref().is_none_or(|f| role_dn.contains(f));
                if passes_filter && let Some(cn) = parse_cn(role_dn) {
                    roles.push(cn);
                }
            }
        }
    }

    Ok(roles)
}

#[async_trait]
impl Augmenter for LDAPAugmenter {
    /// The display name for logs.
    fn get_name(&self) -> &str {
        &self.config.name
    }

    /// The realm this augmenter applies to.
    fn get_realm(&self) -> &str {
        &self.config.realm
    }

    /// The type is "ldap", though we don't typically match on this for augmentation.
    fn get_type(&self) -> &str {
        "ldap"
    }

    /// Adds additional roles to the user from LDAP, if the realms match.
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String> {
        let user_guard = user.lock().await;
        let realm = &user_guard.realm.clone();
        let username = &user_guard.username.clone();
        drop(user_guard);
        if realm != self.get_realm() {
            return Err(format!(
                "Attempted to augment user in the wrong realm. Expected '{}', got '{}'",
                self.get_realm(),
                realm
            ));
        }

        info!("Retrieving LDAP roles for user '{}'", username);
        match retrieve_ldap_user_roles(self.config.clone(), username.clone()).await {
            Ok(roles) => {
                info!(
                    "Fetched {} roles from LDAP for user '{}'",
                    roles.len(),
                    username
                );
                user.lock().await.roles.extend(roles);
                Ok(())
            }
            Err(err) => {
                warn!("Failed to retrieve LDAP user roles: {}", err);
                Err(format!("Failed to retrieve LDAP user roles: {}", err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a valid DN returns the correct CN.
    #[test]
    fn test_parse_cn_valid() {
        let dn = "CN=SomeRole,OU=SomeOU,DC=example,DC=com";
        assert_eq!(parse_cn(dn), Some("SomeRole".to_string()));
    }

    /// Test that a DN with no CN returns None.
    #[test]
    fn test_parse_cn_invalid() {
        let dn = "OU=SomeOU,DC=example,DC=com";
        assert_eq!(parse_cn(dn), None);
    }

    /// Test that when multiple parts are present, the first CN is returned.
    #[test]
    fn test_parse_cn_multiple_entries() {
        let dn = "OU=SomeOU,CN=RoleA,CN=RoleB,DC=example,DC=com";
        assert_eq!(parse_cn(dn), Some("RoleA".to_string()));
    }
}
