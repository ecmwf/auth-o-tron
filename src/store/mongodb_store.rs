use async_trait::async_trait;
use futures::stream::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::{ClientOptions, IndexOptions};
use mongodb::{Client, Collection, IndexModel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::models::{token::Token, user::User};
use crate::store::Store;

/// The config struct for MongoDB connections.
/// Contains the URI and database name.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct MongoDBConfig {
    pub uri: String,
    pub database: String,
}

/// A concrete `Store` implementation that uses MongoDB.
///
/// This struct holds references to two collections:
/// - `token_collection`: For storing issued tokens
/// - `user_collection`: For storing user data
pub struct MongoDBStore {
    token_collection: Collection<TokenDocument>,
    user_collection: Collection<UserDocument>,
}

/// Document shape for storing tokens in MongoDB.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenDocument {
    _id: ObjectId,
    user_id: String,
    token_version: i32,
    token: Token,
}

/// Document shape for storing users in MongoDB.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserDocument {
    _id: ObjectId,
    user_id: String,
    user_version: i32,
    user: User,
}

impl MongoDBStore {
    /// Creates a new `MongoDBStore` from the given config.
    /// It initializes client connections, sets up indexes, etc.
    pub async fn new(config: &MongoDBConfig) -> Result<Self, String> {
        info!("Connecting to MongoDB at URI: {}", config.uri);

        // Parse the connection string from the config
        let mut client_options = ClientOptions::parse(&config.uri)
            .await
            .map_err(|e| format!("Failed to parse MongoDB URI: {}", e))?;

        // Optionally set the client application name
        client_options.app_name = Some("Auth-O-Tron".to_string());

        // Create a new MongoDB client
        let client = Client::with_options(client_options)
            .map_err(|e| format!("Failed to create MongoDB client: {}", e))?;

        info!("MongoDB connection established successfully.");

        // Retrieve the specified database and relevant collections
        let database = client.database(&config.database);
        let token_collection = database.collection::<TokenDocument>("tokens");
        let user_collection = database.collection::<UserDocument>("users");

        // Setup indexes for uniqueness and performance

        // 1) Unique index on token.token_string
        let mut unique_on_token = IndexModel::default();
        unique_on_token.keys = doc! { "token.token_string": 1 };
        unique_on_token.options = Some(IndexOptions::builder().unique(true).build());

        token_collection
            .create_index(unique_on_token, None)
            .await
            .map_err(|e| format!("Failed to create unique index on token_string: {}", e))?;

        // 2) Unique index on (username, realm) in the user collection
        let mut unique_on_user_realm = IndexModel::default();
        unique_on_user_realm.keys = doc! { "user.username": 1, "user.realm": 1 };
        unique_on_user_realm.options = Some(IndexOptions::builder().unique(true).build());

        user_collection
            .create_index(unique_on_user_realm, None)
            .await
            .map_err(|e| format!("Failed to create unique index on (username, realm): {}", e))?;

        // 3) Unique index on user_id
        let mut unique_on_user_id = IndexModel::default();
        unique_on_user_id.keys = doc! { "user_id": 1 };
        unique_on_user_id.options = Some(IndexOptions::builder().unique(true).build());

        user_collection
            .create_index(unique_on_user_id, None)
            .await
            .map_err(|e| format!("Failed to create unique index on user_id: {}", e))?;

        Ok(Self {
            token_collection,
            user_collection,
        })
    }

    /// Helper function to convert a `User` struct to our `UserDocument`.
    fn user_to_doc(user: &User) -> UserDocument {
        UserDocument {
            _id: ObjectId::new(),
            user_id: ObjectId::new().to_hex(),
            user_version: user.version,
            user: user.clone(),
        }
    }

    /// Convert a `UserDocument` back into a `User` struct.
    fn doc_to_user(doc: &UserDocument) -> User {
        doc.user.clone()
    }

    /// Convert a `Token` to a `TokenDocument`, referencing the user by user_id.
    fn token_to_doc(token: &Token, user_id: String) -> TokenDocument {
        TokenDocument {
            _id: ObjectId::new(),
            user_id,
            token_version: token.version,
            token: token.clone(),
        }
    }

    /// Convert a `TokenDocument` back to a `Token` struct.
    fn doc_to_token(doc: &TokenDocument) -> Token {
        doc.token.clone()
    }
}

#[async_trait]
impl Store for MongoDBStore {
    /// Adds a token to the DB. If the user does not exist yet, create a user record.
    async fn add_token(&self, token: &Token, user: &User, _expiry: i64) -> Result<(), String> {
        // 1) Attempt to find existing user in the DB
        let user_doc = self
            .user_collection
            .find_one(
                doc! { "user.username": &user.username, "user.realm": &user.realm },
                None,
            )
            .await
            .map_err(|e| format!("Failed to query user: {}", e))?;

        // 2) If no user doc, insert a new one
        let user_doc = match user_doc {
            Some(ud) => ud,
            None => {
                debug!("User not found in DB, inserting new user document.");
                let new_user_doc = Self::user_to_doc(user);
                self.user_collection
                    .insert_one(new_user_doc.clone(), None)
                    .await
                    .map_err(|e| format!("Failed to insert new user document: {}", e))?;
                new_user_doc
            }
        };

        // 3) Insert the new token referencing this user
        let token_doc = Self::token_to_doc(token, user_doc.user_id.clone());
        self.token_collection
            .insert_one(token_doc, None)
            .await
            .map_err(|e| format!("Failed to insert token: {}", e))?;

        Ok(())
    }

    /// Lists all tokens for a given user.
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String> {
        // 1) Look up the corresponding user document
        let user_doc = self
            .user_collection
            .find_one(
                doc! { "user.username": &user.username, "user.realm": &user.realm },
                None,
            )
            .await
            .map_err(|e| format!("Failed to query user document: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;

        // 2) Find all token documents that reference this user by user_id
        let mut cursor = self
            .token_collection
            .find(doc! { "user_id": user_doc.user_id }, None)
            .await
            .map_err(|e| format!("Failed to list tokens for user: {}", e))?;

        let mut tokens = Vec::new();
        while let Some(token_doc) = cursor
            .try_next()
            .await
            .map_err(|e| format!("Failed to read token document: {}", e))?
        {
            tokens.push(Self::doc_to_token(&token_doc));
        }

        Ok(tokens)
    }

    /// Given a token string, returns the associated `User`, if any.
    async fn get_user(&self, token: &str) -> Result<Option<User>, String> {
        // 1) Look up the token document by token string
        let token_doc = self
            .token_collection
            .find_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| format!("Failed to query token document: {}", e))?;

        // 2) If token not found, return None
        if let Some(td) = token_doc {
            // 3) Look up the user doc that corresponds to this token’s user_id
            let user_doc = self
                .user_collection
                .find_one(doc! { "user_id": &td.user_id }, None)
                .await
                .map_err(|e| format!("Failed to fetch user by user_id: {}", e))?;

            if let Some(ud) = user_doc {
                debug!("User document found for token. user_id = {}", ud.user_id);
                return Ok(Some(Self::doc_to_user(&ud)));
            }
        }

        // If the token or user doc wasn't found, return None
        Ok(None)
    }

    /// Deletes a token document matching the provided token string.
    async fn delete_token(&self, token: &str) -> Result<(), String> {
        self.token_collection
            .delete_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| format!("Failed to delete token: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{token::Token, user::User};
    use std::collections::HashMap;

    /// Test that converting a User to a MongoDB document and back preserves the original user data.
    #[test]
    fn test_user_doc_conversion() {
        let user = User::new(
            "test".to_string(),
            "user1".to_string(),
            Some(vec!["role1".to_string()]),
            None,
            None,
            Some(1),
        );
        let doc = MongoDBStore::user_to_doc(&user);
        let user_converted = MongoDBStore::doc_to_user(&doc);
        assert_eq!(user.username, user_converted.username);
        assert_eq!(user.realm, user_converted.realm);
    }

    /// Test that converting a Token to a MongoDB document and back preserves the token data.
    #[test]
    fn test_token_doc_conversion() {
        // Create a token with empty scopes.
        let token = Token::new("dummy".to_string(), HashMap::new(), Some(1));
        let user_id = "some_user_id".to_string();

        // Convert the token to a document and then back to a token.
        let doc = MongoDBStore::token_to_doc(&token, user_id);
        let token_converted = MongoDBStore::doc_to_token(&doc);

        // Verify that all fields are preserved.
        assert_eq!(token.version, token_converted.version);
        assert_eq!(token.token_string, token_converted.token_string);
        assert_eq!(token.scopes, token_converted.scopes);
    }

    /// Test a round-trip token conversion with non-empty scopes.
    #[test]
    fn test_round_trip_token_conversion() {
        let mut scopes = HashMap::new();
        scopes.insert(
            "service".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );
        let token = Token::new("another_dummy".to_string(), scopes.clone(), Some(2));
        let user_id = "some_user_id".to_string();

        // Convert to document and back.
        let doc = MongoDBStore::token_to_doc(&token, user_id);
        let token_converted = MongoDBStore::doc_to_token(&doc);

        // Assert that the original token and the converted token are equal.
        assert_eq!(token, token_converted);
    }
}
