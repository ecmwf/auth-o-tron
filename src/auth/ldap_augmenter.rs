use async_trait::async_trait;
use cached::proc_macro::cached;
use inline_colorization::*;
use ldap3::LdapConnAsync;
use ldap3::Scope;
use ldap3::SearchEntry;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::models::User;

use super::Augmenter;

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

pub struct LDAPAugmenter {
    config: LDAPAugmenterConfig,
}

impl LDAPAugmenter {
    pub fn new(config: &LDAPAugmenterConfig) -> LDAPAugmenter {
        println!("  🏷️  Creating {style_bold}{color_cyan}LDAPAugmenter{style_reset}{color_reset} for realm {}", config.realm);
        LDAPAugmenter {
            config: config.clone(),
        }
    }
}

fn parse_cn(role: &str) -> Option<String> {
    role.split(',').find_map(|part| {
        let mut split = part.splitn(2, '=');
        match (split.next(), split.next()) {
            (Some("CN"), Some(cn)) => Some(cn.to_string()),
            _ => None,
        }
    })
}

#[cached(time = 120, sync_writes = true)]
async fn retrieve_ldap_user_roles(
    config: LDAPAugmenterConfig,
    uid: String,
) -> Result<Vec<String>, String> {
    let (conn, mut ldap) = LdapConnAsync::new(&config.uri)
        .await
        .map_err(|e| e.to_string())?;
    ldap3::drive!(conn);

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
    let (result, _res) = ldap
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
    for entry in result {
        let search_entry = SearchEntry::construct(entry);
        if let Some(member_of) = search_entry.attrs.get("memberOf") {
            for role in member_of {
                if config.filter.as_deref().map_or(true, |f| role.contains(f)) {
                    if let Some(cn) = parse_cn(role) {
                        roles.push(cn);
                    }
                }
            }
        }
    }

    Ok(roles)
}

#[async_trait]
impl Augmenter for LDAPAugmenter {
    fn get_name(&self) -> &str {
        &self.config.name
    }

    fn get_realm(&self) -> &str {
        &self.config.realm
    }

    fn get_type(&self) -> &str {
        "ldap"
    }

    async fn augment(&self, user: &mut User) -> Result<(), String> {
        if user.realm != self.get_realm() {
            panic!(
                "Trying to authorize a user in the wrong realm, expected {}, got {}",
                self.get_realm(),
                user.realm
            );
        }

        match retrieve_ldap_user_roles(self.config.clone(), user.username.clone()).await {
            Ok(roles) => {
                user.roles.extend(roles);
                Ok(())
            }
            Err(err) => Err(format!("Failed to retrieve LDAP user roles: {:?}", err)),
        }
    }
}
