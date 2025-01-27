use async_trait::async_trait;
use futures::stream::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::options::{ClientOptions, IndexOptions};
use mongodb::{Client, Collection, IndexModel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::models::{Token, User};
use crate::store::Store;

/// The config struct for MongoDB
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct MongoDBConfig {
    pub uri: String,
    pub database: String,
}

/// A concrete `Store` implementation using MongoDB.
pub struct MongoDBStore {
    token_collection: Collection<TokenDocument>,
    user_collection: Collection<UserDocument>,
}

/// The MongoDB document used to store tokens.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct TokenDocument {
    _id: ObjectId,
    user_id: String,
    token_version: i32,
    token: Token,
}

/// The MongoDB document used to store users.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserDocument {
    _id: ObjectId,
    user_id: String,
    user_version: i32,
    user: User,
}

impl MongoDBStore {
    /// Create a new `MongoDBStore`, returning an error message on failure.
    pub async fn new(config: &MongoDBConfig) -> Result<Self, String> {
        println!("🔌 Connecting to MongoDB: {}...", config.uri);

        // Parse connection string
        let mut client_options = ClientOptions::parse(&config.uri)
            .await
            .map_err(|e| format!("Failed to parse MongoDB URI: {}", e))?;

        // Set an optional app name
        client_options.app_name = Some("Auth-O-Tron".to_string());

        // Create the client
        let client = Client::with_options(client_options)
            .map_err(|e| format!("Failed to create MongoDB client: {}", e))?;

        println!("✅ MongoDB connection established successfully!");

        // Get references to the database and collections
        let database = client.database(&config.database);
        let token_collection = database.collection::<TokenDocument>("tokens");
        let user_collection = database.collection::<UserDocument>("users");

        // 1) Unique on "token.token_string"
        let mut unique_on_token = IndexModel::default();
        unique_on_token.keys = doc! { "token.token_string": 1 };
        unique_on_token.options = Some(IndexOptions::builder().unique(true).build());

        token_collection
            .create_index(unique_on_token, None)
            .await
            .map_err(|e| format!("Failed to create unique index on token_string: {}", e))?;

        // 2) Unique on (username, realm)
        let mut unique_on_user_realm = IndexModel::default();
        unique_on_user_realm.keys = doc! { "user.username": 1, "user.realm": 1 };
        unique_on_user_realm.options = Some(IndexOptions::builder().unique(true).build());

        user_collection
            .create_index(unique_on_user_realm, None)
            .await
            .map_err(|e| format!("Failed to create unique index on (username, realm): {}", e))?;

        // 3) Unique on user_id
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

    /// Helper: Convert a `User` struct into a MongoDB `UserDocument`.
    fn user_to_doc(user: &User) -> UserDocument {
        UserDocument {
            _id: ObjectId::new(),
            user_id: ObjectId::new().to_hex(),
            user_version: user.version,
            user: user.clone(),
        }
    }

    /// Helper: Convert a MongoDB `UserDocument` into a `User` struct.
    fn doc_to_user(doc: &UserDocument) -> User {
        doc.user.clone()
    }

    /// Helper: Convert a `Token` struct into a MongoDB `TokenDocument`.
    fn token_to_doc(token: &Token, user_id: String) -> TokenDocument {
        TokenDocument {
            _id: ObjectId::new(),
            user_id,
            token_version: token.version,
            token: token.clone(),
        }
    }

    /// Helper: Convert a MongoDB `TokenDocument` into a `Token` struct.
    fn doc_to_token(doc: &TokenDocument) -> Token {
        doc.token.clone()
    }
}

#[async_trait]
impl Store for MongoDBStore {
    async fn add_token(&self, token: &Token, user: &User, _expiry: i64) -> Result<(), String> {
        // 1) Attempt to find the user document
        let user_doc = self
            .user_collection
            .find_one(
                doc! { "user.username": &user.username, "user.realm": &user.realm },
                None,
            )
            .await
            .map_err(|e| format!("Failed to query user: {}", e))?;

        // 2) If it doesn't exist, create it
        let user_doc = match user_doc {
            Some(ud) => ud,
            None => {
                println!("User not found, inserting new user document");
                let new_user_doc = Self::user_to_doc(user);
                self.user_collection
                    .insert_one(new_user_doc.clone(), None)
                    .await
                    .map_err(|e| format!("Failed to insert new user document: {}", e))?;
                new_user_doc
            }
        };

        // 3) Insert the token for that user
        let token_doc = Self::token_to_doc(token, user_doc.user_id.clone());
        self.token_collection
            .insert_one(token_doc, None)
            .await
            .map_err(|e| format!("Failed to insert token: {}", e))?;

        Ok(())
    }

    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String> {
        // 1) Find the user document
        let user_doc = self
            .user_collection
            .find_one(
                doc! { "user.username": &user.username, "user.realm": &user.realm },
                None,
            )
            .await
            .map_err(|e| format!("Failed to query user document: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;

        // 2) Find all tokens referencing that user
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

    async fn get_user(&self, token: &str) -> Result<Option<User>, String> {
        // 1) Look up the token document
        let token_doc = self
            .token_collection
            .find_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| format!("Failed to query token document: {}", e))?;

        // 2) If it doesn't exist, return None
        if let Some(td) = token_doc {
            // 3) Then fetch the user that token belongs to
            let user_doc = self
                .user_collection
                .find_one(doc! { "user_id": &td.user_id }, None)
                .await
                .map_err(|e| format!("Failed to fetch user by user_id: {}", e))?;

            if let Some(ud) = user_doc {
                println!("User doc found: {:?}", &ud);
                return Ok(Some(Self::doc_to_user(&ud)));
            }
        }

        // Token or user doc not found
        Ok(None)
    }

    async fn delete_token(&self, token: &str) -> Result<(), String> {
        self.token_collection
            .delete_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| format!("Failed to delete token: {}", e))?;

        Ok(())
    }
}
