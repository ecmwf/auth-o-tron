# Augmenters

Augmenters enrich authenticated users with additional roles and attributes. They run after a provider successfully authenticates a user but before the final token is generated. Augmenters can be filtered by realm, so different augmenters apply to users from different authentication sources.

All augmenters share these common fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | The augmenter type |
| name | string | yes | A unique identifier for this augmenter |
| realm | string | yes | Only apply to users authenticated through this realm |

## Built-in Augmenter Logging

The built-in `plain`, `plain_advanced`, and `ldap` implementations omit user
identities, user-derived realms, and raw role/attribute payloads from their logs
for all calls. They retain configured augmenter names/types/realms, counts,
outcomes, and fixed diagnostics. LDAP logs omit DNs, filters, credentials, and
raw directory diagnostics; lookup identities remain in private cache keys.
Configured names and realms are trusted operator metadata, so avoid sensitive
values there. Third-party augmenters are responsible for their own logging.
This boundary does not cover central authentication logs, other application
logs, or logs emitted by external dependencies such as the LDAP driver.

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

Successful complete results are cached for 120 seconds to reduce LDAP server
load, with a process-wide capacity of 256 lookup identities (LRU eviction).

#### LDAP Result and Cache Limits

The lookup requests `memberOf` using a streaming search with server-side
`SearchOptions.sizelimit(16)`, and independently enforces these inclusive limits
locally before deriving/caching roles:

| Data | Limit |
|------|-------|
| Lookup UID | 256 UTF-8 bytes |
| Search entries | 16 per lookup |
| Returned attributes | 16 per entry, including text and binary maps |
| Attribute name | 128 bytes |
| Attribute values | 512 total across all entries/maps, including ignored attributes |
| Each attribute value / entry DN | 4,096 bytes |
| Derived roles | 256 per lookup, each at most 1,024 UTF-8 bytes |
| Lookup aggregate | 128 KiB: entry DNs, attribute names/values and derived role text combined |
| Role filters | At most 32 `filters`; each filter (including legacy `filter`) at most 4,096 bytes |

The client consumes one entry at a time rather than collecting the full result
set. Every attribute, including unexpected/binary values, is budgeted. Binary
`memberOf`, referrals/intermediate results, size-limit failures, and other
non-success final search results reject the complete lookup. UID is escaped as
an LDAP filter value. Normal CN/path role derivation is unchanged.

Roles remain in a private accumulator until the complete search succeeds. Any
limit/error discards all accumulated LDAP roles, does not mutate the user's
roles, and is not cached. Error messages emitted by this augmenter are static
and do not include LDAP diagnostics, identity data, or credentials; role payloads
are not logged. The shared authentication pipeline retains its existing
augmenter-error behavior: it records the error and may continue with the user's
preexisting roles. Browser projection limits separately reject an oversized
final identity with 401. CLI identities are not subject to browser projection
limits, but their LDAP lookups obey the same limits above.

The transport driver is aborted when the lookup completes, fails, or is
cancelled, including a browser deadline. The size-limited cache holds only
bounded successful role vectors; cache keys also contain operator-controlled
connector configuration, whose size remains trusted.

**Residual transport boundary:** ldap3 decodes an LDAP protocol frame and
constructs an entry before application checks can inspect its contents. Its
transport-to-search channel is internally unbounded. A large frame or a burst
from a nonconforming server can therefore allocate before these checks; a
cooperative server's entry-size limit does not bound individual frame bytes.
Connector configuration and the directory server must remain trusted, with
deployment/transport resource limits as appropriate. This implementation bounds
application accumulation and retained cache/session data; it does not claim an
end-to-end hard memory limit or provide a custom bounded LDAP decoder/channel.

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
