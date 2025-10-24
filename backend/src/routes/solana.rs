#![allow(non_snake_case)]

use crate::AuthenticatedUser;
use actix_web::HttpRequest;
use actix_web::{HttpResponse, Result, web};
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
use solana_sdk::transaction::VersionedTransaction;
use std::env;
use std::str::FromStr;
use store::{QuoteStore, Store};
use uuid::Uuid;

const JUPITER_API_BASE: &str = "https://lite-api.jup.ag/swap/v1";

#[derive(Serialize, Deserialize)]
pub struct SwapTransactionResponse {
    #[serde(rename = "swapTransaction")]
    pub swap_transaction: String, // Base64 encoded transaction
    #[serde(rename = "lastValidBlockHeight")]
    pub last_valid_block_height: u64,
}

#[derive(Deserialize)]
pub struct QuoteRequest {
    pub inputMint: String,
    pub outputMint: String,
    pub inAmount: f64,
}

#[derive(Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount: u64,
    pub mint: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct BroadcastResponse {
    pub tx: Transaction,
}

#[derive(Serialize)]
struct AggSendStep2Request {
    mint: Option<String>,
    amount: u64,
    to: String,
    secret_message: String,
    shared_message_1: String,
    shared_message_2: String,
    public_key_1: String,
    public_key_2: String,
    public_key_3: String,
    recent_blockhash: String,
}

#[derive(Serialize)]
struct AggSendStep2SwapRequest {
    tx_b64: String,
    secret_message: String,
    shared_message_1: String,
    shared_message_2: String,
    public_key_1: String,
    public_key_2: String,
    public_key_3: String,
    recent_blockhash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JupiterQuote {
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    #[serde(rename = "otherAmountThreshold")]
    pub other_amount_threshold: String,
    #[serde(rename = "swapMode")]
    pub swap_mode: String,
    #[serde(rename = "slippageBps")]
    pub slippage_bps: u16,
    #[serde(rename = "priceImpactPct")]
    pub price_impact_pct: String,
    #[serde(rename = "routePlan")]
    pub route_plan: Vec<RoutePlan>,
    #[serde(rename = "contextSlot")]
    pub context_slot: Option<u64>,
    #[serde(rename = "timeTaken")]
    pub time_taken: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuoteResponse {
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    pub id: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoutePlan {
    #[serde(rename = "swapInfo")]
    pub swap_info: SwapInfo,
    pub percent: u8,
}

#[derive(Serialize, Deserialize)]
struct AggregateSignaturesBroadcastRequest {
    mint: Option<String>,
    amount: u64,
    to: String,
    public_key_1: String,
    public_key_2: String,
    public_key_3: String,
    partial_signature_1: String,
    partial_signature_2: String,
    partial_signature_3: String,
    recent_blockhash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapInfo {
    #[serde(rename = "ammKey")]
    pub amm_key: String,
    pub label: String,
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: String,
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    #[serde(rename = "feeAmount")]
    pub fee_amount: String,
    #[serde(rename = "feeMint")]
    pub fee_mint: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrioritizationFeeLamports {
    #[serde(rename = "priorityLevelWithMaxLamports")]
    pub priority_level_with_max_lamports: PriorityLevelWithMaxLamports,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct MoralisTokenDecimalsResponse {
    decimals: String,
}

#[derive(Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PriorityLevelWithMaxLamports {
    #[serde(rename = "maxLamports")]
    pub max_lamports: u64,
    #[serde(rename = "priorityLevel")]
    pub priority_level: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SwapTransactionRequest {
    #[serde(rename = "quoteResponse")]
    pub quote_response: JupiterQuote,
    #[serde(rename = "userPublicKey")]
    pub user_public_key: String,
    #[serde(rename = "wrapAndUnwrapSol")]
    pub wrap_and_unwrap_sol: Option<bool>,
    #[serde(rename = "feeAccount")]
    pub fee_account: Option<String>,
    #[serde(rename = "prioritizationFeeLamports")]
    pub prioritization_fee_lamports: Option<PrioritizationFeeLamports>,
    #[serde(rename = "useSharedAccounts")]
    pub use_shared_accounts: Option<bool>,
    #[serde(rename = "asLegacyTransaction")]
    pub as_legacy_transaction: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct SwapRequest {
    id: String,
}

#[derive(Serialize)]
pub struct SwapResponse {}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub balance: i64,
}

#[derive(Deserialize, Debug)]
pub struct Step1Response {
    pub shared_message: String,
    pub secret_message: String,
    pub public_key: String,
}

#[derive(Deserialize, Debug)]
pub struct Step2Response {
    pub partial_signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JupiterTokenResponse {
    address: String,
    decimals: i64,
    name: String,
    symbol: String,
    #[serde(rename = "logoURI")]
    logo_uri: Option<String>,
}

pub async fn get_quote(request: &QuoteRequest, store: &Store) -> anyhow::Result<QuoteResponse> {
    let client = Client::new();
    let slippage_bps = 50;

    let url = format!(
        "{}/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        JUPITER_API_BASE,
        request.inputMint,
        request.outputMint,
        request.inAmount as u64,
        slippage_bps
    );

    println!("Fetching quote from Jupiter: {}", url);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send request to Jupiter API: {}", e))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(anyhow!(
            "Jupiter quote API error ({}): {}",
            status,
            error_text
        ));
    }

    let quote_response: JupiterQuote = response
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse Jupiter API response: {}", e))?;

    let quote_store = QuoteStore::new(store.pool.clone());

    let route_plan_json = serde_json::to_value(&quote_response.route_plan).ok();
    let id = Uuid::new_v4().to_string();

    match quote_store
        .create_quote(
            id.clone(),
            Some(quote_response.input_mint.clone()),
            Some(quote_response.in_amount.clone()),
            Some(quote_response.output_mint.clone()),
            Some(quote_response.out_amount.clone()),
            Some(quote_response.other_amount_threshold.clone()),
            Some(quote_response.swap_mode.clone()),
            Some(quote_response.slippage_bps as i32),
            Some(quote_response.price_impact_pct.clone()),
            route_plan_json,
            quote_response.context_slot.map(|slot| slot as i64),
            quote_response.time_taken.map(|time| time as i64),
        )
        .await
    {
        Ok(saved_quote) => {
            println!("Quote saved to database with ID: {}", saved_quote.id);

            let response = QuoteResponse {
                out_amount: quote_response.out_amount,
                id: id,
            };
            Ok(response)
        }
        Err(e) => {
            println!("Failed to save quote to database: {}", e);
            let uuid = Uuid::new_v4();
            let response = QuoteResponse {
                out_amount: quote_response.out_amount,
                id: uuid.to_string(),
            };
            Ok(response)
        }
    }
}

pub async fn build_swap_transaction(
    jupiter_quote: JupiterQuote,
    user_public_key: &str,
) -> anyhow::Result<SwapTransactionResponse> {
    let url = format!("{}/swap", JUPITER_API_BASE);

    let swap_request = SwapTransactionRequest {
        quote_response: jupiter_quote.clone(),
        user_public_key: user_public_key.to_string(),
        wrap_and_unwrap_sol: Some(true),
        fee_account: None,
        prioritization_fee_lamports: Some(PrioritizationFeeLamports {
            priority_level_with_max_lamports: PriorityLevelWithMaxLamports {
                max_lamports: 10000000,
                priority_level: "medium".to_string(),
            },
        }),
        use_shared_accounts: Some(true),
        as_legacy_transaction: Some(false),
    };

    println!("Sending request to Jupiter: {}", url);

    let response = Client::new().post(&url).json(&swap_request).send().await?;

    println!("Jupiter response status: {}", response.status());

    if !response.status().is_success() {
        let error_text = response.text().await?;
        println!("Jupiter API error: {}", error_text);
        return Err(anyhow!("Jupiter swap API error: {}", error_text));
    }

    let swap_response: SwapTransactionResponse = response.json().await?;
    println!("Jupiter returned transaction successfully");

    Ok(swap_response)
}

pub async fn execute_swap_transaction(
    id: String,
    user_public_key: String,
    store: web::Data<Store>,
) -> anyhow::Result<String> {
    println!("Starting swap execution for user: {}", user_public_key);

    let quote_store = QuoteStore::new(store.pool.clone());
    let jupiter_quote = match quote_store.get_quote_by_id(&id).await {
        Ok(Some(quote_data)) => JupiterQuote {
            input_mint: quote_data.inputMint.unwrap().clone(),
            in_amount: quote_data.inAmount.unwrap().clone(),
            output_mint: quote_data.outputMint.unwrap().clone(),
            out_amount: quote_data.outAmount.unwrap().clone(),
            other_amount_threshold: quote_data.otherAmount.unwrap().clone(),
            swap_mode: quote_data.swapMode.unwrap().clone(),
            slippage_bps: quote_data.slippageBps.unwrap() as u16,
            price_impact_pct: quote_data.priceImpactPct.unwrap().clone(),
            route_plan: serde_json::from_value(quote_data.routePlan.clone().unwrap().0)
                .map_err(|e| anyhow!("Failed to deserialize route_plan: {}", e))?,
            context_slot: quote_data.contextSlot.clone().map(|slot| slot as u64),
            time_taken: quote_data.timeTaken.clone().map(|time| time as f64),
        },
        Ok(None) => return Err(anyhow!("Quote not found")),
        Err(_e) => return Err(anyhow!("Failed to retrieve quote")),
    };

    println!("Building transaction with Jupiter API...");
    let swap_tx_response = build_swap_transaction(jupiter_quote, &user_public_key).await?;

    println!(
        "Jupiter transaction built successfully: {}",
        swap_tx_response.swap_transaction
    );

    let transaction_bytes = B64
        .decode(&swap_tx_response.swap_transaction)
        .map_err(|e| anyhow!("Failed to decode transaction: {}", e))?;

    println!("decoded transaction: {} bytes", transaction_bytes.len());

    Ok(swap_tx_response.swap_transaction)
}

pub async fn get_token_decimals(mint_address: &str) -> anyhow::Result<i16> {

    Pubkey::from_str(mint_address).map_err(|e| anyhow::anyhow!("Invalid mint address: {}", e))?;

    let url = format!(
        "https://solana-gateway.moralis.io/token/mainnet/{}/metadata",
        mint_address
    );
    let moralis_api_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjJkZDYxOWNiLTc1N2MtNDk2Ni1iYmRhLTZjMDRiOWU1YWE4NiIsIm9yZ0lkIjoiNDcwNjg1IiwidXNlcklkIjoiNDg0MjAyIiwidHlwZUlkIjoiMTMxNjZlODktZGNjYS00YmE3LWE2OTMtNDY5ZDJkZWFlYjkwIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NTc4NDk0MzYsImV4cCI6NDkxMzYwOTQzNn0.jnyZFoFu0KJpxBQwZBXYlNDmCzF9L6s22zIP2J1rWqk".to_string();

    let response = reqwest::Client::new()
        .get(&url)
        .header("accept", "application/json")
        .header("X-API-Key", moralis_api_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    let data: MoralisTokenDecimalsResponse = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse Moralis API response: {}", e))?;

    println!(
        "✅ Found token decimals from Moralis API: {}",
        data.decimals
    );

    Ok(data.decimals.parse().unwrap())
}

#[actix_web::post("/quote")]
pub async fn quote(req: web::Json<QuoteRequest>, store: web::Data<Store>) -> Result<HttpResponse> {
    if req.inputMint.is_empty() || req.outputMint.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "input_mint and output_mint are required"
        })));
    }

    if req.inAmount == 0.0 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "amount must be greater than 0"
        })));
    }

    let in_amount = req.inAmount;

    match get_quote(
        &QuoteRequest {
            inputMint: req.inputMint.clone(),
            outputMint: req.outputMint.clone(),
            inAmount: in_amount,
        },
        &store,
    )
    .await
    {
        Ok(quote_response) => Ok(HttpResponse::Ok().json(quote_response)),
        Err(e) => {
            println!("Quote request failed: {}", e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to get quote: {}", e)
            })))
        }
    }
}

#[actix_web::get("/quote/{id}")]
pub async fn get_quote_by_id(
    path: web::Path<String>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let quote_id = path.into_inner();
    let quote_store = QuoteStore::new(store.pool.clone());

    match quote_store.get_quote_by_id(&quote_id).await {
        Ok(Some(quote_data)) => Ok(HttpResponse::Ok().json(quote_data)),
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Quote not found"
        }))),
        Err(e) => {
            println!("Failed to retrieve quote: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve quote"
            })))
        }
    }
}

#[actix_web::post("/send")]
pub async fn send(req: web::Json<SendRequest>, http_req: HttpRequest) -> Result<HttpResponse> {

    let client = reqwest::Client::new();
    let url = "https://mainnet.helius-rpc.com/?api-key=d203db1c-5156-4efc-89b9-4546b8680ea8".to_string();
    let rpc_client = RpcClient::new(url.to_string());

    let token = match http_req.headers().get("Authorization") {
        Some(auth_header) => match auth_header.to_str() {
            Ok(auth_str) => auth_str.to_string(),
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid Authorization header"
                })));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Missing Authorization header"
            })));
        }
    };
    let mut step1_results = Vec::new();

    let step1_res1 = client
        .post("http://127.0.0.1:8081/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 1): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 1): {}",
                e
            ))
        })?;

    step1_results.push(step1_res1);

    let step1_res2 = client
        .post("http://127.0.0.1:8082/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 2): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 2): {}",
                e
            ))
        })?;
    step1_results.push(step1_res2);

    let step1_res3 = client
        .post("http://127.0.0.1:8083/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 3): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 3): {}",
                e
            ))
        })?;
    step1_results.push(step1_res3);

    let recent_blockhash = tokio::task::spawn_blocking(move || rpc_client.get_latest_blockhash())
        .await
        .unwrap()
        .unwrap();

    let mut partial_signatures = Vec::new();

    for i in 0..3 {
        let port = 8081 + i;
        let url = format!("http://127.0.0.1:{}/agg-send-step2", port);

        let mut other_shared_messages = Vec::new();
        let mut other_public_keys = Vec::new();

        for j in 0..3 {
            if i != j {
                other_shared_messages.push(&step1_results[j].shared_message);
                other_public_keys.push(&step1_results[j].public_key);
            }
        }

        let mut step2_request = AggSendStep2Request {
            mint: None,
            amount: req.amount,
            to: req.to.clone(),
            secret_message: step1_results[i].secret_message.clone(),
            shared_message_1: other_shared_messages[0].clone(),
            shared_message_2: other_shared_messages[1].clone(),
            public_key_1: step1_results[0].public_key.clone(),
            public_key_2: step1_results[1].public_key.clone(),
            public_key_3: step1_results[2].public_key.clone(),
            recent_blockhash: recent_blockhash.to_string(),
        };

        if let Some(mint_value) = &req.mint {
            step2_request.mint = Some(mint_value.clone());
        }

        let step2_response = client
            .post(&url)
            .header("Authorization", &token)
            .json(&step2_request)
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Step 2 network error (server {}): {}",
                    i + 1,
                    e
                ))
            })?
            .json::<Step2Response>()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Step 2 parse error (server {}): {}",
                    i + 1,
                    e
                ))
            })?;

        partial_signatures.push(step2_response.partial_signature);
    }

    let mut broadcast_request = AggregateSignaturesBroadcastRequest {
        mint: None,
        amount: req.amount,
        to: req.to.clone(),
        public_key_1: step1_results[0].public_key.clone(),
        public_key_2: step1_results[1].public_key.clone(),
        public_key_3: step1_results[2].public_key.clone(),
        partial_signature_1: partial_signatures[0].clone(),
        partial_signature_2: partial_signatures[1].clone(),
        partial_signature_3: partial_signatures[2].clone(),
        recent_blockhash: recent_blockhash.to_string(),
    };

    if let Some(mint_value) = &req.mint {
        broadcast_request.mint = Some(mint_value.clone());
    }

    let broadcast_data = client
        .post("http://127.0.0.1:8081/aggregate-signatures-broadcast")
        .header("Authorization", &token)
        .json(&broadcast_request)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Broadcast network error (server 1): {}",
                e
            ))
        })?
        .json::<BroadcastResponse>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Broadcast parse error (server 1): {}",
                e
            ))
        })?;

    let tx_to_send = broadcast_data.tx;

    let sig =
        send_legacy_transaction_helius(url.as_str(), &tx_to_send, false, "processed", Some(3))
            .await
            .unwrap();
    println!("submitted, signature = {sig}");

    Ok(HttpResponse::Ok().finish())
}

#[actix_web::post("/swap")]
pub async fn swap(
    req: web::Json<SwapRequest>,
    user: web::ReqData<AuthenticatedUser>,
    store: web::Data<Store>,
    http_req: HttpRequest,
) -> Result<HttpResponse> {
    println!("starting swap");

    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "id is required"
        })));
    }

    let token = match http_req.headers().get("Authorization") {
        Some(auth_header) => match auth_header.to_str() {
            Ok(auth_str) => auth_str.to_string(),
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid Authorization header"
                })));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Missing Authorization header"
            })));
        }
    };

    let client = reqwest::Client::new();
    let url = "https://mainnet.helius-rpc.com/?api-key=d203db1c-5156-4efc-89b9-4546b8680ea8".to_string();
    let rpc_client = RpcClient::new(url.to_string());

    let user_public_key = match store.get_user_public_key_by_id(&user.user_id).await {
        Ok(key) => key,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to get user public key: {}", e)
            })));
        }
    };

    let tx_b64 = match execute_swap_transaction(req.id.clone(), user_public_key, store).await {
        Ok(signature) => {
            println!("Swap transaction formed successfully");
            signature.to_string()
        }
        Err(e) => {
            println!("Failed to form swap transaction: {}", e);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to form swap transaction: {}", e)
            })));
        }
    };

    let mut step1_results = Vec::new();

    let step1_res1 = client
        .post("http://127.0.0.1:8081/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 1): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 1): {}",
                e
            ))
        })?;

    step1_results.push(step1_res1);

    let step1_res2 = client
        .post("http://127.0.0.1:8082/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 2): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 2): {}",
                e
            ))
        })?;
    step1_results.push(step1_res2);

    let step1_res3 = client
        .post("http://127.0.0.1:8083/agg-send-step1")
        .header("Authorization", &token)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 network error (server 3): {}",
                e
            ))
        })?
        .json::<Step1Response>()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Step 1 parse error (server 3): {}",
                e
            ))
        })?;
    step1_results.push(step1_res3);

    let recent_blockhash = tokio::task::spawn_blocking(move || rpc_client.get_latest_blockhash())
        .await
        .unwrap()
        .unwrap();

    let mut partial_signatures = Vec::new();

    for i in 0..3 {
        let port = 8081 + i;
        let url = format!("http://127.0.0.1:{}/agg-send-step2-swap", port);

        let mut other_shared_messages = Vec::new();
        let mut other_public_keys = Vec::new();

        for j in 0..3 {
            if i != j {
                other_shared_messages.push(&step1_results[j].shared_message);
                other_public_keys.push(&step1_results[j].public_key);
            }
        }

        let step2_request = AggSendStep2SwapRequest {
            tx_b64: tx_b64.clone(),
            secret_message: step1_results[i].secret_message.clone(),
            shared_message_1: other_shared_messages[0].clone(),
            shared_message_2: other_shared_messages[1].clone(),
            public_key_1: step1_results[0].public_key.clone(),
            public_key_2: step1_results[1].public_key.clone(),
            public_key_3: step1_results[2].public_key.clone(),
            recent_blockhash: recent_blockhash.to_string(),
        };

        let step2_response = client
            .post(&url)
            .header("Authorization", &token)
            .json(&step2_request)
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Step 2 network error (server {}): {}",
                    i + 1,
                    e
                ))
            })?
            .json::<Step2Response>()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Step 2 parse error (server {}): {}",
                    i + 1,
                    e
                ))
            })?;

        partial_signatures.push(step2_response.partial_signature);
    }

    let sign_request = serde_json::json!({
        "tx_b64": tx_b64.clone(),
        "public_key_1": step1_results[0].public_key.clone(),
        "public_key_2": step1_results[1].public_key.clone(),
        "public_key_3": step1_results[2].public_key.clone(),
        "partial_signature_1": partial_signatures[0],
        "partial_signature_2": partial_signatures[1],
        "partial_signature_3": partial_signatures[2],
        "recent_blockhash": recent_blockhash.to_string(),
    });

    let sign_response = client
        .post("http://127.0.0.1:8081/sign-swap-transaction")
        .header("Authorization", &token)
        .json(&sign_request)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Sign swap transaction network error: {}",
                e
            ))
        })?;

    let sign_result: serde_json::Value = sign_response.json().await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "Sign swap transaction parse error: {}",
            e
        ))
    })?;

    let signed_tx_b64 = sign_result["signed_transaction"].as_str().ok_or_else(|| {
        actix_web::error::ErrorInternalServerError("Missing signed_transaction in response")
    })?;

    let tx_bytes = B64.decode(signed_tx_b64).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to decode signed transaction: {}",
            e
        ))
    })?;

    let versioned_tx: VersionedTransaction = bincode::deserialize(&tx_bytes).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "Failed to deserialize signed transaction: {}",
            e
        ))
    })?;

    let sig = match versioned_tx.clone().into_legacy_transaction() {
        Some(legacy_tx) => {
            println!("Sending legacy transaction...");
            send_legacy_transaction_helius(url.as_str(), &legacy_tx, false, "processed", Some(3))
                .await
                .unwrap()
        }
        None => {
            let tx_bytes = bincode::serialize(&versioned_tx).unwrap();
            let tx_base64 = B64.encode(&tx_bytes);
            println!("Versioned transaction serialized as base64: {}", tx_base64);
            let sig = send_versioned_transaction_helius(
                url.as_str(),
                &versioned_tx,
                false,
                "processed",
                Some(3),
            )
            .await
            .unwrap();
            println!("submitted, signature = {sig}");
            sig
        }
    };
    println!("submitted, signature = {sig}");

    Ok(HttpResponse::Ok().finish())
}

#[actix_web::get("/balance/sol")]
pub async fn sol_balance(
    user: web::ReqData<AuthenticatedUser>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let user_id = &user.user_id;
    let sol_mint_address = "So11111111111111111111111111111111111111112";

    match store
        .get_user_asset_balance(user_id, sol_mint_address)
        .await
    {
        Ok((_asset, balance)) => {
            let response = BalanceResponse {
                balance: balance.amount, // Returns balance in lamports
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            println!("Failed to get SOL balance for user {}: {:?}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get SOL balance: {:?}", e)
            })))
        }
    }
}

#[actix_web::get("/balance/tokens")]
pub async fn token_balance(
    user: web::ReqData<AuthenticatedUser>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let user_id = &user.user_id;

    match store.get_users_token_assets_balances(user_id).await {
        Ok(balances) => Ok(HttpResponse::Ok().json(balances)),
        Err(e) => {
            println!("Failed to get SOL balance for user {}: {:?}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get SOL balance: {:?}", e)
            })))
        }
    }
}

pub fn legacy_tx_to_base64(tx: &Transaction) -> anyhow::Result<String> {
    if tx.signatures.is_empty() {
        return Err(anyhow!("transaction has no signatures"));
    }
    let bytes = bincode::serialize(tx)?;
    Ok(B64.encode(bytes))
}

pub fn versioned_tx_to_base64(tx: &VersionedTransaction) -> anyhow::Result<String> {
    let bytes = bincode::serialize(tx)?;
    Ok(B64.encode(bytes))
}

pub async fn send_legacy_transaction_helius(
    helius_url: &str,
    tx: &Transaction,
    skip_preflight: bool,
    preflight_commitment: &str,
    max_retries: Option<usize>,
) -> anyhow::Result<String> {
    let tx_b64 = legacy_tx_to_base64(tx)?;

    let mut cfg = json!({
        "encoding": "base64",
        "skipPreflight": skip_preflight,
        "preflightCommitment": preflight_commitment,
    });
    if let Some(n) = max_retries {
        cfg["maxRetries"] = json!(n);
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": "send-tx",
        "method": "sendTransaction",
        "params": [tx_b64, cfg],
    });

    let res: RpcResponse = Client::new()
        .post(helius_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if let Some(sig) = res.result {
        Ok(sig)
    } else if let Some(err) = res.error {
        if let Some(data) = err.data {
            if let Some(logs) = data.get("logs") {
                return Err(anyhow!(
                    "RPC error {}: {}\nlogs: {}",
                    err.code,
                    err.message,
                    logs
                ));
            }
        }
        Err(anyhow!("RPC error {}: {}", err.code, err.message))
    } else {
        Err(anyhow!(
            "send_legacy_transaction_helius returned neither result nor error"
        ))
    }
}

pub async fn send_versioned_transaction_helius(
    helius_url: &str,
    tx: &VersionedTransaction,
    skip_preflight: bool,
    preflight_commitment: &str,
    max_retries: Option<usize>,
) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct RpcError {
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    }
    #[derive(Deserialize)]
    struct RpcResponse {
        result: Option<String>,
        error: Option<RpcError>,
    }

    let tx_b64 = versioned_tx_to_base64(tx)?;
    let mut cfg = json!({
        "encoding": "base64",
        "skipPreflight": skip_preflight,
        "preflightCommitment": preflight_commitment,
    });
    if let Some(n) = max_retries {
        cfg["maxRetries"] = json!(n);
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": "send-v0",
        "method": "sendTransaction",
        "params": [tx_b64, cfg],
    });

    let res: RpcResponse = Client::new()
        .post(helius_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if let Some(sig) = res.result {
        Ok(sig)
    } else if let Some(err) = res.error {
        if let Some(data) = err.data {
            if let Some(logs) = data.get("logs") {
                return Err(anyhow!(
                    "RPC error {}: {}\nlogs: {}",
                    err.code,
                    err.message,
                    logs
                ));
            }
        }
        Err(anyhow!("RPC error {}: {}", err.code, err.message))
    } else {
        Err(anyhow!("sendTransaction returned neither result nor error"))
    }
}
