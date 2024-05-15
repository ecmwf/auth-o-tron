use std::sync::Arc;

use crate::config::TokenStoreConfig;
use crate::models::Token;
use crate::models::User;
use async_trait::async_trait;
use mongodb::options::IndexOptions;
use mongodb::IndexModel;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::ClientOptions,
    Client, Collection,
    error::Error as MongoError,
};
use futures::stream::TryStreamExt;

#[async_trait]
pub trait Store: Send + Sync {
    async fn add_token(&self, token: &Token, user: &User, expiry: i64) -> Result<(), String>;
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String>;
    async fn get_user(&self, token: &str) -> Result<Option<User>, String>;
    async fn delete_token(&self, token: &str) -> Result<(), String>;
}

pub async fn create_store(config: &TokenStoreConfig) -> Arc<dyn Store> {
    match config {
        TokenStoreConfig::MongoDB(mongo_config) => Arc::new(MongoDBStore::new(mongo_config).await),
    }
}


// --- MongoDB Store

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct MongoDBConfig {
    pub uri: String,
}

pub struct MongoDBStore {
    client: Client,
    token_collection: Collection<TokenDocument>,
    user_collection: Collection<UserDocument>,
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenDocument {
    _id: ObjectId,
    user_id: String,
    token_version: i32,
    token: Token,
}

#[derive(Serialize, Deserialize, Clone)]
struct UserDocument {
    _id: ObjectId,
    user_id: String,
    user_version: i32,
    user: User,
}

impl MongoDBStore {
    pub async fn new(config: &MongoDBConfig) -> Self {
        let mut client_options = ClientOptions::parse(&config.uri).await.unwrap();
        client_options.app_name = Some("AuthApp".to_string());
        let client = Client::with_options(client_options).unwrap();

        let database = client.database("auth_db");
        let token_collection = database.collection::<TokenDocument>("tokens");
        let user_collection = database.collection::<UserDocument>("users");

        // Ensure indexes are created
        token_collection.create_index(
            IndexModel::builder()
                .keys(doc! { "token.token_string": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        ).await.unwrap();

        user_collection.create_index(
            IndexModel::builder()
                .keys(doc! { "user.username": 1, "user.realm": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        ).await.unwrap();

        user_collection.create_index(
            IndexModel::builder()
                .keys(doc! { "user_id": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        ).await.unwrap();

        Self {
            client,
            token_collection,
            user_collection,
        }
    }

    fn user_to_doc(user: &User) -> UserDocument {
        UserDocument {
            _id: ObjectId::new(),
            user_id: ObjectId::new().to_hex(),
            user_version: user.version,
            user: user.clone(),
        }
    }

    fn doc_to_user(doc: &UserDocument) -> User {
        doc.user.clone()
    }

    fn token_to_doc(token: &Token, user_id: String) -> TokenDocument {
        TokenDocument {
            _id: ObjectId::new(),
            user_id,
            token_version: token.version,
            token: token.clone(),
        }
    }

    fn doc_to_token(doc: &TokenDocument) -> Token {
        doc.token.clone()
    }
}

#[async_trait]
impl Store for MongoDBStore {
    
    async fn add_token(&self, token: &Token, user: &User, _expiry: i64) -> Result<(), String> {
        // Try to find the user document
        let user_doc = match self.user_collection.find_one(doc! { "user.username": &user.username, "user.realm": &user.realm }, None).await {
            Ok(Some(user_doc)) => user_doc,
            Ok(None) => {
                // User not found, insert a new user document
                let new_user_doc = MongoDBStore::user_to_doc(user);
                self.user_collection.insert_one(new_user_doc.clone(), None)
                    .await
                    .map_err(|e| e.to_string())?;
                new_user_doc
            },
            Err(e) => return Err(e.to_string()),
        };

        // Use the user document to add the token
        let token_doc = MongoDBStore::token_to_doc(token, user_doc.user_id.clone());

        self.token_collection.insert_one(token_doc, None)
            .await
            .map_err(|e| e.to_string())?;
        
        Ok(())
    }

    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String> {
        let user_doc = self.user_collection.find_one(doc! { "user.username": &user.username, "user.realm": &user.realm }, None)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("User not found")?;

        let mut cursor = self.token_collection.find(doc! { "user_id": user_doc.user_id }, None)
            .await
            .map_err(|e| e.to_string())?;
        
        let mut tokens = Vec::new();
        while let Some(token_doc) = cursor.try_next().await.map_err(|e| e.to_string())? {
            tokens.push(MongoDBStore::doc_to_token(&token_doc));
        }

        Ok(tokens)
    }

    async fn get_user(&self, token: &str) -> Result<Option<User>, String> {
        let token_doc = self.token_collection.find_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| e.to_string())?;

        if let Some(token_doc) = token_doc {
            let user_doc = self.user_collection.find_one(doc! { "user_id": token_doc.user_id }, None)
                .await
                .map_err(|e| e.to_string())?;
            
            if let Some(user_doc) = user_doc {
                return Ok(Some(MongoDBStore::doc_to_user(&user_doc)));
            }
        }

        Ok(None)
    }

    async fn delete_token(&self, token: &str) -> Result<(), String> {
        self.token_collection.delete_one(doc! { "token.token_string": token }, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}