// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::sync::Arc;

use async_trait::async_trait;
use cached::Return;
use cached::proc_macro::cached;
use futures::lock::Mutex;
use ldap3::{LdapConnAsync, Scope, SearchEntry, SearchOptions};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info};

use crate::augmenters::Augmenter;
use crate::models::user::User;
use crate::utils::log_throttle::should_emit;

const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);
const LDAP_ENTRY_LIMIT: usize = 16;
const LDAP_ATTRIBUTE_LIMIT: usize = 16;
const LDAP_ATTRIBUTE_NAME_BYTES: usize = 128;
const LDAP_VALUE_LIMIT: usize = 512;
const LDAP_VALUE_BYTES: usize = 4096;
const LDAP_DN_BYTES: usize = 4096;
const LDAP_ROLE_LIMIT: usize = 256;
const LDAP_ROLE_BYTES: usize = 1024;
const LDAP_TOTAL_BYTES: usize = 128 * 1024;
const LDAP_LIMIT_ERROR: &str = "LDAP role lookup exceeds configured safety limits";
const LDAP_LOOKUP_ERROR: &str = "LDAP role lookup failed";

/// Limits application-owned lookup data, not the LDAP transport decoder's frames.
#[derive(Default)]
struct RoleLookup {
    entries: usize,
    values: usize,
    bytes: usize,
    roles: Vec<String>,
}

impl RoleLookup {
    fn finish(self, result: ldap3::LdapResult) -> Result<Vec<String>, String> {
        result.success().map_err(|_| LDAP_LOOKUP_ERROR)?;
        Ok(self.roles)
    }

    fn charge(&mut self, bytes: usize) -> Result<(), String> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(LDAP_LIMIT_ERROR)?;
        if self.bytes > LDAP_TOTAL_BYTES {
            return Err(LDAP_LIMIT_ERROR.into());
        }
        Ok(())
    }

    fn value(&mut self, bytes: usize) -> Result<(), String> {
        self.values += 1;
        if self.values > LDAP_VALUE_LIMIT || bytes > LDAP_VALUE_BYTES {
            return Err(LDAP_LIMIT_ERROR.into());
        }
        self.charge(bytes)
    }

    fn entry(&mut self, entry: &SearchEntry, config: &LDAPAugmenterConfig) -> Result<(), String> {
        self.entries += 1;
        if self.entries > LDAP_ENTRY_LIMIT
            || entry.dn.len() > LDAP_DN_BYTES
            || entry.attrs.len() + entry.bin_attrs.len() > LDAP_ATTRIBUTE_LIMIT
        {
            return Err(LDAP_LIMIT_ERROR.into());
        }
        self.charge(entry.dn.len())?;
        // Validate every returned attribute, including unexpected and binary data,
        // before parsing memberOf DNs or copying any derived roles.
        for (name, values) in &entry.attrs {
            if name.len() > LDAP_ATTRIBUTE_NAME_BYTES || values.len() > LDAP_VALUE_LIMIT {
                return Err(LDAP_LIMIT_ERROR.into());
            }
            self.charge(name.len())?;
            for value in values {
                self.value(value.len())?;
            }
        }
        for (name, values) in &entry.bin_attrs {
            if name.len() > LDAP_ATTRIBUTE_NAME_BYTES || values.len() > LDAP_VALUE_LIMIT {
                return Err(LDAP_LIMIT_ERROR.into());
            }
            self.charge(name.len())?;
            for value in values {
                self.value(value.len())?;
            }
        }
        // A binary memberOf cannot supply a complete set of textual entitlements.
        if entry
            .bin_attrs
            .keys()
            .any(|name| name.eq_ignore_ascii_case("memberOf"))
        {
            return Err(LDAP_LOOKUP_ERROR.into());
        }
        for (_, values) in entry
            .attrs
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("memberOf"))
        {
            for dn in values {
                for role in collect_roles_from_dn(dn, &config.filter, &config.filters) {
                    if self.roles.len() >= LDAP_ROLE_LIMIT || role.len() > LDAP_ROLE_BYTES {
                        return Err(LDAP_LIMIT_ERROR.into());
                    }
                    self.charge(role.len())?;
                    self.roles.push(role);
                }
            }
        }
        Ok(())
    }
}

/// Closing/cancelling a lookup must also stop its detached transport driver.
struct ConnectionDriver(tokio::task::JoinHandle<()>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Configuration required to connect to LDAP and fetch user roles.
#[derive(Deserialize, Serialize, JsonSchema, Debug, Hash, PartialEq, Eq, Clone)]
pub struct LDAPAugmenterConfig {
    pub name: String,
    pub realm: String,
    pub uri: String,
    pub search_base: String,
    pub filter: Option<String>,
    pub filters: Option<Vec<String>>, // When provided, roles are derived as value-paths (e.g. "/TeamA/TeamB/Role")
    pub bind_dn: Option<String>,      // LDAP User DN to bind with
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
            event_name = "augmenters.ldap.initialization",
            event_domain = "augmenters",
            augmenter_name = config.name.as_str(),
            realm = config.realm.as_str(),
            "creating LDAP augmenter"
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
fn match_filter_path(
    role_attrs: &[(String, String)],
    filter: &str,
) -> Result<Option<String>, String> {
    let filter_attrs = parse_dn_components(filter);
    if filter_attrs.is_empty() {
        return Err(format!(
            "Invalid LDAP filter '{}': expected key=value segments",
            filter
        ));
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
            let matches = window.iter().zip(attrs.iter()).all(|((rk, rv), (fk, fv))| {
                rk.eq_ignore_ascii_case(fk) && rv.eq_ignore_ascii_case(fv)
            });

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
                roles.push(format!("/{}", path));
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
                return Err("Invalid LDAP role filter: expected key=value segments".into());
            }
        }
    }
    Ok(())
}

/// This function looks up user roles in LDAP, caching results for 120 seconds.
/// We bind with a service account, search for the user by `uid`, and parse "memberOf" attributes.
/// With `filters` configured, we parse each filter as a DN fragment; when it matches part of the
/// user's DN we emit the path of attribute values from that match down to the CN. Legacy single
/// `filter` keeps returning just the CN when matched.
#[cached(
    time = 120,
    size = 256,
    result = true,
    with_cached_flag = true,
    sync_writes = "default"
)]
async fn retrieve_ldap_user_roles(
    config: LDAPAugmenterConfig,
    uid: String,
) -> Result<Return<Vec<String>>, String> {
    if uid.len() > 256
        || config
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > LDAP_DN_BYTES)
        || config.filters.as_ref().is_some_and(|filters| {
            filters.len() > 32 || filters.iter().any(|filter| filter.len() > LDAP_DN_BYTES)
        })
    {
        return Err(LDAP_LIMIT_ERROR.into());
    }
    validate_filters(&config.filters)?;

    debug!(
        event_name = "augmenters.ldap.lookup.connecting",
        event_domain = "augmenters",
        username = uid.as_str(),
        "connecting to LDAP to retrieve user roles"
    );

    let (conn, mut ldap) = LdapConnAsync::new(&config.uri)
        .await
        .map_err(|_| LDAP_LOOKUP_ERROR)?;
    let _driver = ConnectionDriver(tokio::spawn(async move {
        let _ = conn.drive().await;
    }));

    // We do a simple bind using the configured service account
    let bind_dn = config
        .bind_dn
        .as_deref()
        .ok_or_else(|| "No bind DN provided for LDAP augmenter.".to_string())?;
    ldap.simple_bind(bind_dn, &config.ldap_password)
        .await
        .map_err(|_| LDAP_LOOKUP_ERROR)?
        .success()
        .map_err(|_| LDAP_LOOKUP_ERROR)?;

    let search_filter = format!("(&(objectClass=person)(cn={}))", ldap3::ldap_escape(&uid));
    let mut stream = ldap
        .with_search_options(SearchOptions::new().sizelimit(LDAP_ENTRY_LIMIT as i32))
        .streaming_search(
            &config.search_base,
            Scope::Subtree,
            &search_filter,
            vec!["memberOf"],
        )
        .await
        .map_err(|_| LDAP_LOOKUP_ERROR)?;

    let mut lookup = RoleLookup::default();
    while let Some(entry) = stream.next().await.map_err(|_| LDAP_LOOKUP_ERROR)? {
        // Referrals/intermediate messages do not establish complete local roles.
        if entry.is_ref() || entry.is_intermediate() {
            return Err(LDAP_LOOKUP_ERROR.into());
        }
        if lookup.entries >= LDAP_ENTRY_LIMIT {
            return Err(LDAP_LIMIT_ERROR.into());
        }
        let search_entry = SearchEntry::construct(entry);
        lookup.entry(&search_entry, &config)?;
    }
    // sizeLimitExceeded and all other non-success results discard the entire
    // local accumulator; neither partial results nor failures enter the cache.
    Ok(Return::new(lookup.finish(stream.finish().await)?))
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
        if user_guard.username.len() > 256 {
            return Err(LDAP_LIMIT_ERROR.into());
        }
        let realm = user_guard.realm.clone();
        let username = user_guard.username.clone();
        drop(user_guard);
        if realm != self.get_realm() {
            return Err("LDAP augmenter realm mismatch".into());
        }

        debug!(
            event_name = "augmenters.ldap.lookup.started",
            event_domain = "augmenters",
            augmenter_name = self.config.name.as_str(),
            augmenter_type = "ldap",
            username = username.as_str(),
            realm = realm.as_str(),
            "retrieving LDAP roles for user"
        );
        match retrieve_ldap_user_roles(self.config.clone(), username.clone()).await {
            Ok(roles) => {
                if roles.was_cached
                    && let Some(suppressed_count) =
                        should_emit("augmenters.ldap.lookup.cache.hit", CACHE_HIT_LOG_WINDOW)
                {
                    debug!(
                        event_name = "augmenters.ldap.lookup.cache.hit",
                        event_domain = "augmenters",
                        augmenter_name = self.config.name.as_str(),
                        augmenter_type = "ldap",
                        cache_result = "hit",
                        cache_ttl_seconds = 120,
                        cache_key_type = "username",
                        suppressed_count,
                        "LDAP role lookup served from cache"
                    );
                }

                let fetched_roles_count = roles.len();
                if fetched_roles_count == 0 {
                    debug!(
                        event_name = "augmenters.ldap.no_change",
                        event_domain = "augmenters",
                        augmenter_name = self.config.name.as_str(),
                        augmenter_type = "ldap",
                        username = username.as_str(),
                        realm = realm.as_str(),
                        "LDAP augmenter returned no roles"
                    );
                } else {
                    user.lock().await.roles.extend((*roles).clone());
                    info!(
                        event_name = "augmenters.ldap.roles_added",
                        event_domain = "augmenters",
                        augmenter_name = self.config.name.as_str(),
                        augmenter_type = "ldap",
                        username = username.as_str(),
                        realm = realm.as_str(),
                        added_roles_count = fetched_roles_count,
                        "LDAP augmenter added roles"
                    );
                }
                Ok(())
            }
            Err(err) => {
                debug!(
                    event_name = "augmenters.ldap.lookup.failed",
                    event_domain = "augmenters",
                    augmenter_name = self.config.name.as_str(),
                    augmenter_type = "ldap",
                    username = username.as_str(),
                    realm = realm.as_str(),
                    error = err.as_str(),
                    "LDAP role lookup failed"
                );
                Err(format!("Failed to retrieve LDAP user roles: {}", err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LDAPAugmenterConfig {
        LDAPAugmenterConfig {
            name: "test-ldap".into(),
            realm: "test".into(),
            uri: "ldap://127.0.0.1:1".into(),
            search_base: "dc=example,dc=test".into(),
            filter: None,
            filters: None,
            bind_dn: Some("cn=public-fixture".into()),
            ldap_password: "public-test-password".into(),
        }
    }

    fn entry(dn: &str, roles: Vec<String>) -> SearchEntry {
        SearchEntry {
            dn: dn.into(),
            attrs: std::collections::HashMap::from([("memberOf".into(), roles)]),
            bin_attrs: Default::default(),
        }
    }

    #[test]
    fn ldap_lookup_accepts_exact_entry_value_dn_and_role_bounds() {
        let mut lookup = RoleLookup::default();
        let mut data = entry(&"d".repeat(LDAP_DN_BYTES), vec![]);
        // 256 textual roles, plus 256 ignored values, at the overall value-count limit.
        data.attrs
            .insert("memberOf".into(), vec!["CN=role".into(); LDAP_ROLE_LIMIT]);
        data.attrs.insert(
            "ignored".into(),
            vec![String::new(); LDAP_VALUE_LIMIT - LDAP_ROLE_LIMIT],
        );
        lookup.entry(&data, &config()).unwrap();
        for _ in 1..LDAP_ENTRY_LIMIT {
            lookup.entry(&entry("", vec![]), &config()).unwrap();
        }
        assert_eq!(lookup.entries, LDAP_ENTRY_LIMIT);
        assert_eq!(lookup.values, LDAP_VALUE_LIMIT);
        assert_eq!(lookup.roles.len(), LDAP_ROLE_LIMIT);
        let mut lookup = RoleLookup::default();
        lookup
            .entry(
                &entry("", vec![format!("CN={}", "r".repeat(LDAP_ROLE_BYTES))]),
                &config(),
            )
            .unwrap();
        assert_eq!(lookup.roles[0].len(), LDAP_ROLE_BYTES);
        let mut lookup = RoleLookup::default();
        let mut value_entry = entry("", vec![]);
        value_entry
            .bin_attrs
            .insert("ignored".into(), vec![vec![0; LDAP_VALUE_BYTES]]);
        lookup.entry(&value_entry, &config()).unwrap();
    }

    #[test]
    fn ldap_lookup_rejects_entry_attribute_value_dn_and_role_excess() {
        for case in [
            "entries",
            "attributes",
            "attribute-name",
            "values",
            "value-bytes",
            "binary-bytes",
            "dn",
            "roles",
            "role-bytes",
            "binary-memberof",
        ] {
            let mut lookup = RoleLookup::default();
            let mut data = entry("CN=public-user", vec!["CN=normal".into()]);
            match case {
                "entries" => lookup.entries = LDAP_ENTRY_LIMIT,
                "attributes" => {
                    for n in 0..LDAP_ATTRIBUTE_LIMIT {
                        data.attrs.insert(format!("extra-{n}"), vec![]);
                    }
                }
                "attribute-name" => {
                    data.attrs
                        .insert("n".repeat(LDAP_ATTRIBUTE_NAME_BYTES + 1), vec![]);
                }
                "values" => {
                    data.attrs
                        .insert("ignored".into(), vec![String::new(); LDAP_VALUE_LIMIT]);
                }
                "value-bytes" => {
                    data.attrs
                        .insert("ignored".into(), vec!["x".repeat(LDAP_VALUE_BYTES + 1)]);
                }
                "binary-bytes" => {
                    data.bin_attrs
                        .insert("ignored".into(), vec![vec![0; LDAP_VALUE_BYTES + 1]]);
                }
                "dn" => data.dn = "d".repeat(LDAP_DN_BYTES + 1),
                "roles" => {
                    data.attrs.insert(
                        "memberOf".into(),
                        vec!["CN=normal".into(); LDAP_ROLE_LIMIT + 1],
                    );
                }
                "role-bytes" => {
                    data.attrs.insert(
                        "memberOf".into(),
                        vec![format!("CN={}", "r".repeat(LDAP_ROLE_BYTES + 1))],
                    );
                }
                "binary-memberof" => {
                    data.bin_attrs.insert("memberOf".into(), vec![vec![255]]);
                }
                _ => unreachable!(),
            }
            let error = lookup.entry(&data, &config()).unwrap_err();
            assert!(!error.contains("public-user"), "{case}");
            assert!(error == LDAP_LIMIT_ERROR || error == LDAP_LOOKUP_ERROR);
        }
    }

    #[test]
    fn ldap_lookup_aggregate_counts_raw_and_derived_bytes_without_partial_user_mutation() {
        let mut lookup = RoleLookup::default();
        let data = entry("", vec!["CN=role".into()]);
        // memberOf name (8), input DN (7), derived role (4) all count.
        lookup.bytes = LDAP_TOTAL_BYTES - 19;
        lookup.entry(&data, &config()).unwrap();
        assert_eq!(lookup.bytes, LDAP_TOTAL_BYTES);
        assert!(lookup.entry(&data, &config()).is_err());

        let mut user = User::new(
            "test".into(),
            "public-user".into(),
            Some(vec!["existing".into()]),
            None,
            None,
            None,
        );
        let outcome = (|| {
            let mut lookup = RoleLookup::default();
            lookup.entry(&entry("", vec!["CN=good".into()]), &config())?;
            lookup.entry(
                &entry("", vec![format!("CN={}", "x".repeat(LDAP_ROLE_BYTES + 1))]),
                &config(),
            )?;
            Ok::<_, String>(lookup.roles)
        })();
        if let Ok(roles) = outcome {
            user.roles.extend(roles);
        }
        assert_eq!(user.roles, ["existing"]);
    }

    #[tokio::test]
    async fn ldap_cache_evicts_at_capacity_and_does_not_cache_rejected_lookup() {
        use cached::Cached;
        {
            let mut cache = RETRIEVE_LDAP_USER_ROLES.lock().await;
            cache.cache_clear();
            assert_eq!(cache.cache_capacity(), Some(256));
            for n in 0..257 {
                cache.cache_set(
                    (config(), format!("public-{n}")),
                    Return::new(vec!["role".into()]),
                );
            }
            assert_eq!(cache.cache_size(), 256);
            assert!(cache.cache_get(&(config(), "public-0".into())).is_none());
            cache.cache_clear();
        }
        // Fails validation before connecting to LDAP; no live service required.
        assert!(
            retrieve_ldap_user_roles(config(), "u".repeat(257))
                .await
                .is_err()
        );
        assert_eq!(RETRIEVE_LDAP_USER_ROLES.lock().await.cache_size(), 0);
    }

    #[tokio::test]
    async fn ldap_connection_driver_is_aborted_when_lookup_is_dropped() {
        let task = tokio::spawn(std::future::pending::<()>());
        let handle = task.abort_handle();
        drop(ConnectionDriver(task));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn ldap_final_size_limit_or_failure_never_returns_partial_roles_or_diagnostics() {
        for rc in [0, 4, 10, 80] {
            let mut lookup = RoleLookup::default();
            lookup
                .entry(&entry("CN=public-user", vec!["CN=role".into()]), &config())
                .unwrap();
            let result = lookup.finish(ldap3::LdapResult {
                rc,
                matched: "CN=public-user".into(),
                text: "sensitive-diagnostic".into(),
                refs: vec![],
                ctrls: vec![],
            });
            if rc == 0 {
                assert_eq!(result.unwrap(), ["role"]);
            } else {
                assert_eq!(result.unwrap_err(), LDAP_LOOKUP_ERROR);
            }
        }
    }

    #[tokio::test]
    async fn rejected_ldap_augmentation_keeps_existing_roles_without_connecting() {
        let mut settings = config();
        settings.filters = Some(vec!["OU=team".into(); 33]);
        let user = Arc::new(Mutex::new(User::new(
            "test".into(),
            "public-user".into(),
            Some(vec!["existing".into()]),
            None,
            None,
            None,
        )));
        let error = LDAPAugmenter::new(&settings)
            .augment(user.clone())
            .await
            .unwrap_err();
        assert!(error.contains(LDAP_LIMIT_ERROR));
        assert!(!error.contains("public-user"));
        assert!(!error.contains("public-test-password"));
        assert_eq!(user.lock().await.roles, ["existing"]);
    }

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
                "/TeamA/TeamB/SomeRole".to_string(),
                "/TeamB/SomeRole".to_string()
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

        assert_eq!(roles, vec!["/TeamA/TeamB/SomeRole".to_string()]);
    }

    #[test]
    fn test_collect_roles_multiple_filters_multi_attribute_dn_order() {
        let roles = collect_roles_from_dn(
            "CN=SomeRole,OU=TeamB,OU=TeamA,DC=example,DC=com",
            &None,
            &Some(vec!["OU=TeamB,OU=TeamA".to_string()]),
        );

        assert_eq!(roles, vec!["/TeamA/TeamB/SomeRole".to_string()]);
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
