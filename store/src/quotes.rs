#![allow(non_snake_case)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, types::Json, Row};

#[derive(Debug)]
pub enum QuoteError {
    QuoteNotFound,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteError::QuoteNotFound => write!(f, "Quote not found"),
            QuoteError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            QuoteError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for QuoteError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePlan {
    pub routes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Quote {
    pub id: String,
    pub createdAt: DateTime<Utc>,
    pub inputMint: Option<String>,
    pub inAmount: Option<String>,
    pub outputMint: Option<String>,
    pub outAmount: Option<String>,
    pub otherAmount: Option<String>,
    pub swapMode: Option<String>,
    pub slippageBps: Option<i32>,
    pub priceImpactPct: Option<String>,
    #[serde(serialize_with = "serialize_json_option")]
    pub routePlan: Option<Json<serde_json::Value>>,
    pub contextSlot: Option<i64>,
    pub timeTaken: Option<i64>,
}

fn serialize_json_option<S>(
    value: &Option<Json<serde_json::Value>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(json) => json.0.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

pub struct QuoteStore {
    pool: PgPool,
}

impl QuoteStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_quote(
        &self,
        id: String,
        inputMint: Option<String>,
        inAmount: Option<String>,
        outputMint: Option<String>,
        outAmount: Option<String>,
        otherAmount: Option<String>,
        swapMode: Option<String>,
        slippageBps: Option<i32>,
        priceImpactPct: Option<String>,
        routePlan: Option<serde_json::Value>,
        contextSlot: Option<i64>,
        timeTaken: Option<i64>,
    ) -> Result<Quote, QuoteError> {
        // Generate a unique ID for the quote
        let now = Utc::now();

        let route_plan_json = routePlan.map(Json);

        let record = sqlx::query(
            r#"
            INSERT INTO quotes (
                id, "createdAt", "inputMint", "inAmount", "outputMint", 
                "outAmount", "otherAmount", "swapMode", "slippageBps", 
                "priceImpactPct", "routePlan", "contextSlot", "timeTaken"
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING 
                id, 
                "createdAt", 
                "inputMint", 
                "inAmount", 
                "outputMint", 
                "outAmount", 
                "otherAmount", 
                "swapMode", 
                "slippageBps", 
                "priceImpactPct", 
                "routePlan", 
                "contextSlot", 
                "timeTaken"
            "#
        )
        .bind(&id)
        .bind(&now)
        .bind(&inputMint)
        .bind(&inAmount)
        .bind(&outputMint)
        .bind(&outAmount)
        .bind(&otherAmount)
        .bind(&swapMode)
        .bind(&slippageBps)
        .bind(&priceImpactPct)
        .bind(&route_plan_json)
        .bind(&contextSlot)
        .bind(&timeTaken)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| QuoteError::DatabaseError(e.to_string()))?;

        let quote = Quote {
            id: record.get("id"),
            createdAt: record.get("createdAt"),
            inputMint: record.get("inputMint"),
            inAmount: record.get("inAmount"),
            outputMint: record.get("outputMint"),
            outAmount: record.get("outAmount"),
            otherAmount: record.get("otherAmount"),
            swapMode: record.get("swapMode"),
            slippageBps: record.get("slippageBps"),
            priceImpactPct: record.get("priceImpactPct"),
            routePlan: record.get("routePlan"),
            contextSlot: record.get("contextSlot"),
            timeTaken: record.get("timeTaken"),
        };

        Ok(quote)
    }

    pub async fn get_quote_by_id(&self, id: &str) -> Result<Option<Quote>, QuoteError> {
        let record = sqlx::query(
            r#"
            SELECT 
                id, 
                "createdAt", 
                "inputMint", 
                "inAmount", 
                "outputMint", 
                "outAmount", 
                "otherAmount", 
                "swapMode", 
                "slippageBps", 
                "priceImpactPct", 
                "routePlan", 
                "contextSlot", 
                "timeTaken"
            FROM quotes
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| QuoteError::DatabaseError(e.to_string()))?;

        Ok(record.map(|r| Quote {
            id: r.get("id"),
            createdAt: r.get("createdAt"),
            inputMint: r.get("inputMint"),
            inAmount: r.get("inAmount"),
            outputMint: r.get("outputMint"),
            outAmount: r.get("outAmount"),
            otherAmount: r.get("otherAmount"),
            swapMode: r.get("swapMode"),
            slippageBps: r.get("slippageBps"),
            priceImpactPct: r.get("priceImpactPct"),
            routePlan: r.get("routePlan"),
            contextSlot: r.get("contextSlot"),
            timeTaken: r.get("timeTaken"),
        }))
    }
}
