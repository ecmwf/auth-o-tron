# Augmenters

Augmenters enrich authenticated users with additional roles and attributes. They run after a provider successfully authenticates a user but before the final token is generated. Augmenters can be filtered by realm, so different augmenters apply to users from different authentication sources.

All augmenters share these common fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | The augmenter type |
| name | string | yes | A unique identifier for this augmenter |
| realm | string | yes | Only apply to users authenticated through this realm |

## Augmenter Types

### 1. Plain Augmenter

Type: `plain`

The plain augmenter is a simple role mapper that assigns roles based on username. It is deprecated and will be removed in a future version. Use `plain_advanced` instead.

When this augmenter runs, it logs a deprecation warning.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| roles | map | Map of role names to lists of usernames that should receive that role |

**Example:**

```yaml
augmenters:
  - type: plain
    name: basic_roles
    realm: internal
    roles:
      admin: [alice, bob]
      readonly: [guest, anonymous]
```

In this example, users "alice" and "bob" receive the "admin" role, while "guest" and "anonymous" receive the "readonly" role.

### 2. Plain Advanced Augmenter

Type: `plain_advanced`

The plain advanced augmenter provides conditional role and attribute injection based on username or existing roles. It is the recommended replacement for the deprecated `plain` augmenter.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| match | object | Conditions that must be met for augmentation to apply |
| augment | object | Roles and attributes to add when conditions match |

**Match conditions:**

| Field | Type | Description |
|-------|------|-------------|
| username | array | List of usernames that trigger this augmenter |
| role | array | List of existing roles that trigger this augmenter |

A user matches if their username is in the `username` list OR if they have any of the listed `role` entries.

**Augmentation:**

| Field | Type | Description |
|-------|------|-------------|
| roles | array | Roles to add to the user |
| attributes | map | Key-value attributes to add or update on the user |

**Example:**

```yaml
augmenters:
  - type: plain_advanced
    name: admin_boost
    realm: internal
    match:
      username: [admin, root]
      role: [superuser]
    augment:
      roles: [full_access, audit]
      attributes:
        department: engineering
        clearance: top-secret
```

In this example, any user with username "admin" or "root", OR any user who already has the "superuser" role, receives the "full_access" and "audit" roles plus the department and clearance attributes.

### 3. LDAP Augmenter

Type: `ldap`

The LDAP augmenter queries a Lightweight Directory Access Protocol server to extract roles and group memberships for authenticated users. This is useful when user roles are managed in an enterprise directory like Active Directory or OpenLDAP.

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| uri | string | LDAP server URI (e.g., ldap://ldap.example.com:389) |
| search_base | string | Base DN for searches (e.g., ou=users,dc=example,dc=com) |
| filter | string | Single LDAP filter template (optional, uses {username} placeholder) |
| filters | array | Multiple LDAP filter templates (optional, alternative to single filter) |
| bind_dn | string | DN to bind with for searching (service account) |
| ldap_password | string | Password for the bind DN |

**Filter vs Filters:**

- Use `filter` for a single search that returns group CNs directly.
- Use `filters` for multiple searches that return hierarchical paths like `/TeamA/Admin`.

When using `filters`, each filter is executed and the results are combined. The filter template can use `{username}` as a placeholder.

Results are cached for 120 seconds to reduce LDAP server load.

**Example with single filter:**

```yaml
augmenters:
  - type: ldap
    name: ldap_groups
    realm: corporate
    uri: ldap://ldap.company.com:389
    search_base: ou=groups,dc=company,dc=com
    filter: (member=uid={username},ou=users,dc=company,dc=com)
    bind_dn: cn=service,dc=company,dc=com
    ldap_password: service-password
```

**Example with multiple filters:**

```yaml
augmenters:
  - type: ldap
    name: ldap_teams
    realm: corporate
    uri: ldap://ldap.company.com:389
    search_base: ou=teams,dc=company,dc=com
    filters:
      - (member=uid={username},ou=users,dc=company,dc=com)
      - (manager=uid={username},ou=users,dc=company,dc=com)
    bind_dn: cn=service,dc=company,dc=com
    ldap_password: service-password
```

## Multiple Augmenters

You can configure multiple augmenters to build up a user's final set of roles and attributes:

```yaml
augmenters:
  - type: ldap
    name: ldap_roles
    realm: internal
    uri: ldap://ldap.example.com
    search_base: ou=groups,dc=example,dc=com
    filter: (member=uid={username},ou=users,dc=example,dc=com)
    bind_dn: cn=reader,dc=example,dc=com
    ldap_password: secret
```

Non-`plain_advanced` augmenters (such as LDAP) run in parallel. `plain_advanced` augmenters run sequentially after all parallel augmenters complete. This lets advanced augmenters match on roles added by LDAP or other parallel sources.
