# Token Store

The token store provides optional persistence for opaque tokens. By default, token storage is disabled and all token operations return an error.

## When to Use a Token Store

A token store is needed when you want to:

- Issue and validate opaque tokens (random strings) instead of JWTs
- Revoke tokens before they expire
- Track active token sessions
- Share token state across multiple Auth-O-Tron instances

If you only use JWT-based authentication, you do not need to configure a token store.

## NoStore (Default)

When no store is configured or when the store is explicitly disabled, Auth-O-Tron uses the `NoStore` backend. This backend returns errors for all token storage operations.

To explicitly disable the store:

```yaml
store:
  enabled: false
```

## MongoDB Backend

Type: `mongo`

The MongoDB backend stores tokens in a MongoDB database. This enables persistent, shared token state across multiple server instances.

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Must be "mongo" |
| uri | string | yes | MongoDB connection URI |
| database | string | yes | Database name to use |

**Collections:**

The MongoDB backend creates and uses two collections:

- **tokens**: Stores token documents with a unique index on `token.token_string`
- **users**: Stores user documents with a unique compound index on `username` + `realm`, and a unique index on `user_id`

**Example:**

```yaml
store:
  enabled: true
  type: mongo
  uri: mongodb://localhost:27017
  database: auth_o_tron
```

**Example with authentication:**

```yaml
store:
  enabled: true
  type: mongo
  uri: mongodb://username:password@mongodb.example.com:27017/auth_o_tron?authSource=admin
  database: auth_o_tron
```

**Example with replica set:**

```yaml
store:
  enabled: true
  type: mongo
  uri: mongodb://mongo1.example.com:27017,mongo2.example.com:27017/auth_o_tron?replicaSet=rs0
  database: auth_o_tron
```

## Configuration Examples

**Disabled store (default):**

```yaml
version: "2.0.0"

server:
  port: 8080

store:
  enabled: false
```

**MongoDB store:**

```yaml
version: "2.0.0"

server:
  port: 8080

store:
  enabled: true
  type: mongo
  uri: mongodb://localhost:27017
  database: auth_o_tron
```
