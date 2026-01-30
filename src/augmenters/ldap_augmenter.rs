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
    pub filters: Option<Vec<String>>, // When provided, prefix roles with "filter/CN"
    pub bind_dn: Option<String>, // Optional explicit bind DN; overrides ldap_user-derived default
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

/// Split a DN (or DN fragment) into ordered key/value components.
fn parse_dn_components(input: &str) -> Vec<(String, String)> {
    input
        .split(',')
        .filter_map(|part| {
            let mut split = part.splitn(2, '=');
            match (split.next().map(str::trim), split.next().map(str::trim)) {
                (Some(k), Some(v)) if !k.is_empty() && !v.is_empty() => {
                    Some((k.to_string(), v.to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

/// Try to match a filter (DN fragment) against the role's DN components. If matched,
/// return the path of attribute values from the matched ancestor down to the CN.
fn match_filter_path(role_attrs: &[(String, String)], filter: &str) -> Result<Option<String>, String> {
    let filter_attrs = parse_dn_components(filter);
    if filter_attrs.is_empty() {
        return Err(format!("Invalid LDAP filter '{}': expected key=value segments", filter));
    }

    // Support filters written root->leaf (common for humans) or leaf->root (DN order)
    // by attempting both orientations.
    let mut orientations = vec![filter_attrs.clone()];
    let mut reversed = filter_attrs;
    reversed.reverse();
    orientations.push(reversed);

    for attrs in orientations {
        let len = attrs.len();
        if len == 0 || len > role_attrs.len() {
            continue;
        }

        for start in 0..=role_attrs.len() - len {
            let window = &role_attrs[start..start + len];
            let matches = window
                .iter()
                .zip(attrs.iter())
                .all(|((rk, rv), (fk, fv))| rk.eq_ignore_ascii_case(fk) && rv.eq_ignore_ascii_case(fv));

            if matches {
                let end = start + len - 1; // ancestor index within the matched window
                let path: Vec<String> = role_attrs[..=end]
                    .iter()
                    .rev()
                    .map(|(_, v)| v.clone())
                    .collect();
                return Ok(Some(path.join("/")));
            }
        }
    }

    Ok(None)
}

fn collect_roles_from_dn(
    role_dn: &str,
    single_filter: &Option<String>,
    filters: &Option<Vec<String>>,
) -> Vec<String> {
    let role_attrs = parse_dn_components(role_dn);
    let Some(cn) = parse_cn(role_dn) else {
        return Vec::new();
    };

    if let Some(filter_list) = filters {
        let mut roles = Vec::new();
        for filter in filter_list {
            if let Ok(Some(path)) = match_filter_path(&role_attrs, filter) {
                roles.push(path);
            }
        }
        return roles;
    }

    if single_filter.as_deref().is_none_or(|f| role_dn.contains(f)) {
        return vec![cn];
    }

    Vec::new()
}

fn validate_filters(filters: &Option<Vec<String>>) -> Result<(), String> {
    if let Some(filter_list) = filters {
        for filter in filter_list {
            if parse_dn_components(filter).is_empty() {
                return Err(format!("Invalid LDAP filter '{}': expected key=value segments", filter));
            }
        }
    }
    Ok(())
}

fn compute_bind_dn(config: &LDAPAugmenterConfig) -> String {
    if let Some(custom) = &config.bind_dn {
        return custom.clone();
    }

    format!(
        "CN={},OU=Connectors,OU=Service Accounts,DC=ecmwf,DC=int",
        &config.ldap_user
    )
}

/// This function looks up user roles in LDAP, caching results for 120 seconds.
/// We bind with a service account, search for the user by `uid`, and parse "memberOf" attributes.
/// With `filters` configured, we parse each filter as a DN fragment; when it matches part of the
/// user's DN we emit the path of attribute values from that match down to the CN. Legacy single
/// `filter` keeps returning just the CN when matched.
#[cached(time = 120, sync_writes = "default")]
async fn retrieve_ldap_user_roles(
    config: LDAPAugmenterConfig,
    uid: String,
) -> Result<Vec<String>, String> {
    validate_filters(&config.filters)?;

    debug!(
        "Connecting to LDAP at {}, searching for user CN={}",
        config.uri, uid
    );

    let (conn, mut ldap) = LdapConnAsync::new(&config.uri)
        .await
        .map_err(|e| e.to_string())?;
    ldap3::drive!(conn);

    // We do a simple bind using the configured service account
    let bind_dn = compute_bind_dn(&config);
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
                let mut extracted = collect_roles_from_dn(role_dn, &config.filter, &config.filters);
                roles.append(&mut extracted);
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

    #[test]
    fn test_parse_dn_components_basic() {
        let parts = parse_dn_components("OU=TeamA,CN=Role");
        assert_eq!(
            parts,
            vec![
                ("OU".to_string(), "TeamA".to_string()),
                ("CN".to_string(), "Role".to_string())
            ]
        );
    }

    #[test]
    fn test_validate_filters_rejects_malformed() {
        let filters = Some(vec!["Invalid".to_string(), "OU=TeamB".to_string()]);
        assert!(validate_filters(&filters).is_err());
    }

    #[test]
    fn test_compute_bind_dn_default() {
        let cfg = LDAPAugmenterConfig {
            name: "test".to_string(),
            realm: "r".to_string(),
            uri: "u".to_string(),
            search_base: "dc".to_string(),
            filter: None,
            filters: None,
            bind_dn: None,
            ldap_user: "svc".to_string(),
            ldap_password: "p".to_string(),
        };

        assert_eq!(
            compute_bind_dn(&cfg),
            "CN=svc,OU=Connectors,OU=Service Accounts,DC=ecmwf,DC=int"
        );
    }

    #[test]
    fn test_compute_bind_dn_override() {
        let cfg = LDAPAugmenterConfig {
            name: "test".to_string(),
            realm: "r".to_string(),
            uri: "u".to_string(),
            search_base: "dc".to_string(),
            filter: None,
            filters: None,
            bind_dn: Some("CN=custom,DC=example".to_string()),
            ldap_user: "svc".to_string(),
            ldap_password: "p".to_string(),
        };

        assert_eq!(compute_bind_dn(&cfg), "CN=custom,DC=example");
    }

    /// Test legacy single-filter behaviour keeps returning just the CN.
    #[test]
    fn test_collect_roles_single_filter() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamA,DC=example,DC=com",
            &Some("TeamA".to_string()),
            &None,
        );

        assert_eq!(roles, vec!["SomeRole".to_string()]);
    }

    /// Test multi-filter behaviour returns path/CN for matches (ancestor includes children).
    #[test]
    fn test_collect_roles_multiple_filters() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamB,OU=TeamA,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamA".to_string(), "OU=TeamB".to_string()]),
        );

        assert_eq!(
            roles,
            vec![
                "TeamA/TeamB/SomeRole".to_string(),
                "TeamB/SomeRole".to_string()
            ]
        );
    }

    #[test]
    fn test_collect_roles_multiple_filters_multi_attribute_root_order() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamB,OU=TeamA,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamA,OU=TeamB".to_string()]),
        );

        assert_eq!(roles, vec!["TeamA/TeamB/SomeRole".to_string()]);
    }

    #[test]
    fn test_collect_roles_multiple_filters_multi_attribute_dn_order() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamB,OU=TeamA,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamB,OU=TeamA".to_string()]),
        );

        assert_eq!(roles, vec!["TeamA/TeamB/SomeRole".to_string()]);
    }

    #[test]
    fn test_collect_roles_multiple_filters_non_contiguous_no_match() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamC,OU=TeamB,OU=TeamA,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamA,OU=TeamC".to_string()]),
        );

        // Filter fragments must be contiguous in the role DN; this should not match.
        assert!(roles.is_empty());
    }

    /// Test multi-filter configuration yields no roles when nothing matches.
    #[test]
    fn test_collect_roles_multiple_filters_no_match() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamC,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamA".to_string(), "OU=TeamB".to_string()]),
        );

        assert!(roles.is_empty());
    }
}
