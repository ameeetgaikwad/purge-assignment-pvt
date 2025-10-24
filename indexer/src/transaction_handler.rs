use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use store::{
    Store, assets::Asset, assets::AssetStore, balance::BalanceError, balance::BalanceStore,
};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainEvent {
    pub wallet_pubkey: String,
    pub token_amount: u64,
    pub native_lamports: u64,
    pub token_mint: String,
    pub event_time: i64,
    pub tx_signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetInfo {
    pub token_mint: String,
    pub decimal_places: i16,
    pub token_name: Option<String>,
    pub token_symbol: Option<String>,
    pub image_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalAssetData {
    pub mint: String,
    pub decimals: String,
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub logo: Option<String>,
    pub description: Option<String>,
    pub standard: Option<String>,
}

const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

pub async fn fetch_asset_info(token_mint: &str) -> Result<AssetInfo> {
    dotenv::dotenv().ok();

    Pubkey::from_str(token_mint).map_err(|e| anyhow::anyhow!("Invalid token mint: {}", e))?;

    let api_endpoint = format!(
        "https://solana-gateway.moralis.io/token/mainnet/{}/metadata",
        token_mint
    );
    let api_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjJkZDYxOWNiLTc1N2MtNDk2Ni1iYmRhLTZjMDRiOWU1YWE4NiIsIm9yZ0lkIjoiNDcwNjg1IiwidXNlcklkIjoiNDg0MjAyIiwidHlwZUlkIjoiMTMxNjZlODktZGNjYS00YmE3LWE2OTMtNDY5ZDJkZWFlYjkwIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NTc4NDk0MzYsImV4cCI6NDkxMzYwOTQzNn0.jnyZFoFu0KJpxBQwZBXYlNDmCzF9L6s22zIP2J1rWqk".to_string();

    let http_response = reqwest::Client::new()
        .get(&api_endpoint)
        .header("accept", "application/json")
        .header("X-API-Key", api_secret)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    let external_data: ExternalAssetData = http_response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse external API response: {}", e))?;

    let asset_metadata: AssetInfo = AssetInfo {
        token_mint: token_mint.to_string(),
        token_name: external_data.name,
        token_symbol: external_data.symbol,
        decimal_places: external_data.decimals.parse().unwrap(),
        image_uri: external_data.logo,
    };

    println!("✅ Retrieved asset metadata from external API: {:?}", asset_metadata);

    Ok(asset_metadata)
}

pub async fn handle_blockchain_event(store: &Store, event: BlockchainEvent) -> Result<()> {
    let user_record = match store
        .get_user_by_public_key(&event.wallet_pubkey)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            println!(
                "User record not found for public key: {}",
                event.wallet_pubkey
            );
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to query user: {}", e)),
    };

    let asset_repository = AssetStore::new(store.pool.clone());
    let balance_repository = BalanceStore::new(store.pool.clone());

    let asset_record = match asset_repository
        .get_asset_by_mint_address(&event.token_mint)
        .await
    {
        Ok(Some(asset)) => asset,
        Ok(None) => {
            let asset_metadata = fetch_asset_info(&event.token_mint).await?;

            let created_asset = Asset::new(
                Uuid::new_v4().to_string(),
                Some(asset_metadata.token_mint),
                asset_metadata.decimal_places,
                asset_metadata.token_name,
                asset_metadata.token_symbol,
                asset_metadata.image_uri,
            );

            asset_repository
                .add_asset(created_asset)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create asset record: {}", e))?
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to query asset: {}", e)),
    };

    let updated_balance = if event.token_mint == NATIVE_SOL_MINT.to_string() {
        event.native_lamports as i64
    } else {
        event.token_amount as i64
    };

    match balance_repository.get_balance(&user_record.id, &asset_record.id).await {
        Ok(_) => {
            balance_repository
                .update_balance(&user_record.id, &asset_record.id, updated_balance)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to update balance record: {}", e))?;
        }
        Err(BalanceError::BalanceNotFound) => {
            balance_repository
                .add_balance(user_record.id.clone(), asset_record.id.clone(), updated_balance)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create balance record: {}", e))?;
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to query balance: {}", e)),
    }

    Ok(())
}

