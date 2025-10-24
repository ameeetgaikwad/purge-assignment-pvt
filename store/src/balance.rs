#![allow(non_snake_case)]

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Row};

#[derive(Debug)]
pub enum BalanceError {
    BalanceNotFound,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceError::BalanceNotFound => write!(f, "Balance not found"),
            BalanceError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            BalanceError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for BalanceError {}

#[derive(Debug, Clone, FromRow)]
pub struct Balance {
    pub id: String,
    pub amount: i64,
    pub createdAt: DateTime<Utc>,
    pub updatedAt: DateTime<Utc>,
    pub userId: String,
    pub assetId: String,
}

pub struct BalanceStore {
    pool: PgPool,
}

impl BalanceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn add_balance(
        &self,
        userId: String,
        assetId: String,
        amount: i64,
    ) -> Result<Balance, BalanceError> {
        // Generate a unique ID for the balance
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let record = sqlx::query(
            r#"
            INSERT INTO balances (id, amount, "createdAt", "updatedAt", "userId", "assetId")
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, amount, "createdAt", "updatedAt", "userId", "assetId"
            "#
        )
        .bind(&id)
        .bind(&amount)
        .bind(&now)
        .bind(&now)
        .bind(&userId)
        .bind(&assetId)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| BalanceError::DatabaseError(e.to_string()))?;

        let balance = Balance {
            id: record.get("id"),
            amount: record.get("amount"),
            createdAt: record.get("createdAt"),
            updatedAt: record.get("updatedAt"),
            userId: record.get("userId"),
            assetId: record.get("assetId"),
        };

        Ok(balance)
    }

    pub async fn update_balance(
        &self,
        userId: &str,
        assetId: &str,
        new_amount: i64,
    ) -> Result<Balance, BalanceError> {
        let now = Utc::now();

        let record = sqlx::query(
            r#"
            UPDATE balances
            SET amount = $1, "updatedAt" = $2
            WHERE "userId" = $3 AND "assetId" = $4
            RETURNING id, amount, "createdAt", "updatedAt", "userId", "assetId"
            "#
        )
        .bind(&new_amount)
        .bind(&now)
        .bind(userId)
        .bind(assetId)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => BalanceError::BalanceNotFound,
            _ => BalanceError::DatabaseError(e.to_string()),
        })?;

        let balance = Balance {
            id: record.get("id"),
            amount: record.get("amount"),
            createdAt: record.get("createdAt"),
            updatedAt: record.get("updatedAt"),
            userId: record.get("userId"),
            assetId: record.get("assetId"),
        };

        Ok(balance)
    }

    pub async fn get_balance(&self, userId: &str, assetId: &str) -> Result<Balance, BalanceError> {
        let record = sqlx::query(
            r#"
            SELECT id, amount, "createdAt", "updatedAt", "userId", "assetId"
            FROM balances
            WHERE "userId" = $1 AND "assetId" = $2
            "#
        )
        .bind(userId)
        .bind(assetId)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => BalanceError::BalanceNotFound,
            _ => BalanceError::DatabaseError(e.to_string()),
        })?;

        let balance = Balance {
            id: record.get("id"),
            amount: record.get("amount"),
            createdAt: record.get("createdAt"),
            updatedAt: record.get("updatedAt"),
            userId: record.get("userId"),
            assetId: record.get("assetId"),
        };

        Ok(balance)
    }

    pub async fn get_user_balances(&self, userId: &str) -> Result<Vec<Balance>, BalanceError> {
        let records = sqlx::query(
            r#"
            SELECT id, amount, "createdAt", "updatedAt", "userId", "assetId"
            FROM balances
            WHERE "userId" = $1
            "#
        )
        .bind(userId)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BalanceError::DatabaseError(e.to_string()))?;

        let balances = records.into_iter().map(|r| Balance {
            id: r.get("id"),
            amount: r.get("amount"),
            createdAt: r.get("createdAt"),
            updatedAt: r.get("updatedAt"),
            userId: r.get("userId"),
            assetId: r.get("assetId"),
        }).collect();

        Ok(balances)
    }
}