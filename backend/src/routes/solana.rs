use crate::AuthenticatedUser;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;

#[derive(Deserialize)]
pub struct QuoteRequest {}
#[derive(Serialize)]
struct AggSendStep2Request {
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
struct AggregateSignaturesBroadcastRequest {
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
#[derive(Serialize, Deserialize)]
pub struct QuoteResponse {}

#[derive(Deserialize)]
pub struct SwapRequest {}

#[derive(Serialize)]
pub struct SwapResponse {}

#[derive(Serialize)]
pub struct BalanceResponse {}

#[derive(Serialize)]
pub struct TokenBalanceResponse {}

#[derive(Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount: u64,
    pub mint: Option<String>,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub transaction_signature: String,
}

// MPC Step 1 Response structures
#[derive(Deserialize, Debug)]
pub struct Step1Response {
    pub shared_message: String,
    pub secret_message: String,
    pub public_key: String,
}

// MPC Step 2 Response structures
#[derive(Deserialize, Debug)]
pub struct Step2Response {
    pub partial_signature: String,
}

// MPC Broadcast Response structures
#[derive(Deserialize, Debug)]
pub struct BroadcastResponse {
    pub tx: String,
}

#[actix_web::post("/quote")]
pub async fn quote(_req: web::Json<QuoteRequest>) -> Result<HttpResponse> {
    let response = QuoteResponse {};

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/swap")]
pub async fn swap(_req: web::Json<SwapRequest>) -> Result<HttpResponse> {
    let response = SwapResponse {};

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::get("/sol-balance/{pubkey}")]
pub async fn sol_balance() -> Result<HttpResponse> {
    let response = BalanceResponse {};

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::get("/token-balance/{pubkey}/{mint}")]
pub async fn token_balance() -> Result<HttpResponse> {
    let response = TokenBalanceResponse {};

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/send")]
pub async fn send(req: web::Json<SendRequest>, http_req: HttpRequest) -> Result<HttpResponse> {
    let client = reqwest::Client::new();

    // Get the authorization token from the request headers
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
    println!("yo we are here");
    // Step 1: Call agg-send-step1 on all three MPC servers sequentially
    let mut step1_results = Vec::new();

    // Call server 1
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
    println!("yo we are here 1 {:?}", step1_res1);
    step1_results.push(step1_res1);
    println!("testting");
    // Call server 2
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
    println!("yo we are here 2 {:?}", step1_res2);
    step1_results.push(step1_res2);

    // Call server 3
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
    println!("yo we are here 2 {:?}", step1_res3);
    step1_results.push(step1_res3);

    println!("yo we are here 3");
    
    // Get a single recent block hash to use for all servers
    let rpc_client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let recent_blockhash = tokio::task::spawn_blocking(move || rpc_client.get_latest_blockhash())
        .await
        .unwrap()
        .unwrap();
    
    // Step 2: Call agg-send-step2 on each server with the other servers' data sequentially
    let mut partial_signatures = Vec::new();

    for i in 0..3 {
        let port = 8081 + i;
        let url = format!("http://127.0.0.1:{}/agg-send-step2", port);

        // Get the shared messages from the OTHER two servers (not the current one)
        let mut other_shared_messages = Vec::new();
        let mut other_public_keys = Vec::new();

        for j in 0..3 {
            if i != j {
                other_shared_messages.push(&step1_results[j].shared_message);
                other_public_keys.push(&step1_results[j].public_key);
            }
        }

        let step2_request = AggSendStep2Request {
            amount: req.amount, // Convert lamports to SOL
            to: req.to.clone(),
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
    println!("partial_signatures {:?}", partial_signatures);
    println!("amount {:?}", req.amount);
    
    // Step 3: Call aggregate-signatures-broadcast on one of the servers
    let broadcast_request = AggregateSignaturesBroadcastRequest {
        amount: req.amount, // Convert lamports to SOL
        to: req.to.clone(),
        public_key_1: step1_results[0].public_key.clone(),
        public_key_2: step1_results[1].public_key.clone(),
        public_key_3: step1_results[2].public_key.clone(),
        partial_signature_1: partial_signatures[0].clone(),
        partial_signature_2: partial_signatures[1].clone(),
        partial_signature_3: partial_signatures[2].clone(),
        recent_blockhash: recent_blockhash.to_string(),
    };

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

    let response = SendResponse {
        transaction_signature: broadcast_data.tx,
    };

    Ok(HttpResponse::Ok().json(response))
}
