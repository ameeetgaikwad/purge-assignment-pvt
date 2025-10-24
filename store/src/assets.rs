#![allow(non_snake_case)]

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Row};

#[derive(Debug)]
pub enum AssetError {
    AssetExists,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::AssetExists => write!(f, "Asset already exists"),
            AssetError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            AssetError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for AssetError {}

#[derive(Debug, Clone, FromRow)]
#[allow(non_snake_case)]

pub struct Asset {
    pub id: String,
    pub createdAt: DateTime<Utc>,
    pub updatedAt: DateTime<Utc>,
    pub mintAddress: Option<String>,
    pub decimals: i16,
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub logoUrl: Option<String>,
}

impl Asset {
    pub fn new(
        id: String,
        mintAddress: Option<String>,
        decimals: i16,
        name: Option<String>,
        symbol: Option<String>,
        logoUrl: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id,
            createdAt: now,
            updatedAt: now,
            mintAddress,
            decimals,
            name,
            symbol,
            logoUrl,
        }
    }
}

pub struct AssetStore {
    pool: PgPool,
}

impl AssetStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn add_asset(&self, asset: Asset) -> Result<Asset, AssetError> {
        let record = sqlx::query(
            r#"
            INSERT INTO assets (id, "createdAt", "updatedAt", "mintAddress", decimals, name, symbol, "logoUrl")
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, "createdAt", "updatedAt", "mintAddress", decimals, name, symbol, "logoUrl"
            "#
        )
        .bind(&asset.id)
        .bind(&asset.createdAt)
        .bind(&asset.updatedAt)
        .bind(&asset.mintAddress)
        .bind(&asset.decimals)
        .bind(&asset.name)
        .bind(&asset.symbol)
        .bind(&asset.logoUrl)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AssetError::DatabaseError(e.to_string()))?;

        let result = Asset {
            id: record.get("id"),
            createdAt: record.get("createdAt"),
            updatedAt: record.get("updatedAt"),
            mintAddress: record.get("mintAddress"),
            decimals: record.get("decimals"),
            name: record.get("name"),
            symbol: record.get("symbol"),
            logoUrl: record.get("logoUrl"),
        };

        Ok(result)
    }

    pub async fn get_asset_by_id(&self, id: &str) -> Result<Option<Asset>, AssetError> {
        let record = sqlx::query(
            r#"
            SELECT id, "createdAt", "updatedAt", "mintAddress", decimals, name, symbol, "logoUrl"
            FROM assets
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AssetError::DatabaseError(e.to_string()))?;

        Ok(record.map(|r| Asset {
            id: r.get("id"),
            createdAt: r.get("createdAt"),
            updatedAt: r.get("updatedAt"),
            mintAddress: r.get("mintAddress"),
            decimals: r.get("decimals"),
            name: r.get("name"),
            symbol: r.get("symbol"),
            logoUrl: r.get("logoUrl"),
        }))
    }

    pub async fn get_asset_by_mint_address(
        &self,
        mintAddress: &str,
    ) -> Result<Option<Asset>, AssetError> {
        let record = sqlx::query(
            r#"
            SELECT id, "createdAt", "updatedAt", "mintAddress", decimals, name, symbol, "logoUrl"
            FROM assets
            WHERE "mintAddress" = $1
            "#
        )
        .bind(mintAddress)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AssetError::DatabaseError(e.to_string()))?;

        Ok(record.map(|r| Asset {
            id: r.get("id"),
            createdAt: r.get("createdAt"),
            updatedAt: r.get("updatedAt"),
            mintAddress: r.get("mintAddress"),
            decimals: r.get("decimals"),
            name: r.get("name"),
            symbol: r.get("symbol"),
            logoUrl: r.get("logoUrl"),
        }))
    }

    pub async fn get_assets_by_ids(&self, ids: &[String]) -> Result<Vec<Asset>, AssetError> {
        let records = sqlx::query(
            r#"
            SELECT id, "createdAt", "updatedAt", "mintAddress", decimals, name, symbol, "logoUrl"
            FROM assets
            WHERE id = ANY($1)
            "#
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AssetError::DatabaseError(e.to_string()))?;

        let assets = records.into_iter().map(|r| Asset {
            id: r.get("id"),
            createdAt: r.get("createdAt"),
            updatedAt: r.get("updatedAt"),
            mintAddress: r.get("mintAddress"),
            decimals: r.get("decimals"),
            name: r.get("name"),
            symbol: r.get("symbol"),
            logoUrl: r.get("logoUrl"),
        }).collect();

        Ok(assets)
    }
}