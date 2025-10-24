use crate::{Balance, BalanceError, BalanceStore, Store};
use chrono::Utc;
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;
use crate::assets::{Asset, AssetError, AssetStore};
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub password: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub struct AddPublicKeyRequest {
    pub id: String,
    pub public_key: String,
}


#[derive(Serialize)]
pub struct UserTokenAssetBalance {
    pub balance: i64,
    pub tokenMint: String,
    pub symbol: String,
    pub decimals: i16,
}

pub type UserTokensAssetsBalances = Vec<UserTokenAssetBalance>;

#[derive(Debug)]
pub struct SignInRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub enum UserAssetBalanceError {
    UserError(UserError),
    AssetError(AssetError),
    BalanceError(BalanceError),
    AssetNotFound,
}

#[derive(Debug)]
pub enum UserError {
    UserExists,
    UserNotFound,
    InvalidCredentials,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::UserExists => write!(f, "User already exists"),
            UserError::UserNotFound => write!(f, "User not found"),
            UserError::InvalidCredentials => write!(f, "Invalid credentials"),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for UserError {}

const SOL_PROGRAM_ADDRESS: &str = "So11111111111111111111111111111111111111112";

impl Store {
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, UserError> {
        // Validate email format
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        // Validate password length
        if request.password.len() < 6 {
            return Err(UserError::InvalidInput(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Check if user already exists
        let existing_user = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(&request.email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        if existing_user.is_some() {
            return Err(UserError::UserExists);
        }

        // Hash the password
        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)
            .map_err(|e| UserError::DatabaseError(format!("Password hashing failed: {}", e)))?;

        // Generate user ID and timestamp
        let user_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Insert user into database
        sqlx::query("INSERT INTO users (id, email, password, \"createdAt\") VALUES ($1, $2, $3, $4)")
            .bind(&user_id)
            .bind(&request.email)
            .bind(&password_hash)
            .bind(&created_at)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Return the created user
        let user = User {
            id: user_id,
            email: request.email,
            created_at: Some(created_at.to_rfc3339()),
            updated_at: None,
            password: None,
            public_key: None,
        };

        Ok(user)
    }
    pub async fn signin_user(&self, request: SignInRequest) -> Result<User, UserError> {
        // Validate email format
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        // Get user from database
        let user_record =
            sqlx::query("SELECT id, email, password, \"createdAt\" FROM users WHERE email = $1")
                .bind(&request.email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        // Verify password
        let password_hash: String = user_record.get("password");
        let password_valid = bcrypt::verify(&request.password, &password_hash).map_err(|e| {
            UserError::DatabaseError(format!("Password verification failed: {}", e))
        })?;

        if !password_valid {
            return Err(UserError::InvalidCredentials);
        }

        // Return the user
        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: Some(user_record
                .get::<chrono::DateTime<chrono::Utc>, _>("createdAt")
                .to_rfc3339()),
            updated_at: None,
            password: None,
            public_key: None,
        };

        Ok(user)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User, UserError> {
        let user_record = sqlx::query("SELECT id, email, \"createdAt\" FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: Some(user_record
                .get::<chrono::DateTime<chrono::Utc>, _>("createdAt")
                .to_rfc3339()),
            updated_at: None,
            password: None,
            public_key: None,
        };

        Ok(user)
    }

    pub async fn add_public_key(&self, request: AddPublicKeyRequest) -> Result<User, UserError> {
        sqlx::query("UPDATE users SET \"publicKey\" = $2 WHERE id = $1")
            .bind(&request.id)
            .bind(&request.public_key)
            .execute(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Fetch and return the updated user
        let user_record = sqlx::query("SELECT id, email, \"createdAt\" FROM users WHERE id = $1")
            .bind(&request.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: Some(user_record
                .get::<chrono::DateTime<chrono::Utc>, _>("createdAt")
                .to_rfc3339()),
            updated_at: None,
            password: None,
            public_key: None,
        };

        Ok(user)
    }

    pub async fn has_public_key(&self, user_id: &str) -> Result<bool, UserError> {
        let result = sqlx::query("SELECT \"publicKey\" FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        match result {
            Some(record) => {
                let public_key: Option<String> = record.get("publicKey");
                Ok(public_key.is_some())
            }
            None => Err(UserError::UserNotFound),
        }
    }

    pub async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<User>, UserError> {
        let user = sqlx::query(
            r#"
        SELECT id, email, "publicKey", "createdAt"
        FROM users
        WHERE "publicKey" = $1
        "#,
        )
        .bind(public_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user.map(|u| User {
            id: u.get("id"),
            email: u.get("email"),
            public_key: Some(u.get("publicKey")),
            created_at: Some(u
                .get::<chrono::DateTime<chrono::Utc>, _>("createdAt")
                .to_rfc3339()),
            updated_at: None,
            password: None,
        }))
    }

    pub async fn get_user_asset_balance(
        &self,
        id: &str,
        mint_address: &str,
    ) -> Result<(Asset, Balance), UserAssetBalanceError> {
        // Step 1: Get asset by mint address using AssetStore
        let asset_store = AssetStore::new(self.pool.clone());
        let asset = asset_store
            .get_asset_by_mint_address(mint_address)
            .await
            .map_err(|e| UserAssetBalanceError::AssetError(e))?
            .ok_or(UserAssetBalanceError::AssetNotFound)?;

        // Step 2: Get balance using user ID and asset ID using BalanceStore
        let balance_store = BalanceStore::new(self.pool.clone());
        let balance = balance_store.get_balance(&id, &asset.id).await.map_err(|e| UserAssetBalanceError::BalanceError(e))?;

        Ok((asset, balance))
    }

    pub async fn get_users_token_assets_balances(
        &self,
        id: &str,
    ) -> Result<UserTokensAssetsBalances, UserAssetBalanceError> {
        // Step 1: Get balances using user ID using BalanceStore
        let balance_store = BalanceStore::new(self.pool.clone());
        let balances = balance_store.get_user_balances(&id).await.map_err(|e| UserAssetBalanceError::BalanceError(e))?;

        let asset_ids: Vec<String> = balances.iter().map(|b| b.assetId.clone()).collect();

        // Step 2: Get assets using asset IDs using AssetStore
        let asset_store = AssetStore::new(self.pool.clone());
        let assets = asset_store
            .get_assets_by_ids(&asset_ids)
            .await
            .map_err(|e| UserAssetBalanceError::AssetError(e))?;

        let result: UserTokensAssetsBalances = balances
            .iter()
            .filter_map(|b| {
                let asset = assets.iter().find(|a| a.id == b.assetId)?;
                let mint_address = asset.mintAddress.clone().unwrap_or_default();
                if mint_address == SOL_PROGRAM_ADDRESS {
                    return None;
                }
                Some(UserTokenAssetBalance {
                    balance: b.amount,
                    tokenMint: mint_address,
                    symbol: asset.symbol.clone().unwrap_or_default(),
                    decimals: asset.decimals,
                })
            })
            .collect();

        Ok(result)
    }

    pub async fn get_user_public_key_by_id(&self, id: &str) -> Result<String, UserError> {
        let user = sqlx::query(
            r#"
            SELECT id, email, "publicKey", "createdAt", "updatedAt"
            FROM users
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user.ok_or(UserError::UserNotFound)?.get("publicKey"))
    }
}
