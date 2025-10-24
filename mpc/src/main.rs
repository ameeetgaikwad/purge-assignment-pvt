pub mod error;
pub mod serialization;
pub mod tss;
use actix_web::{
    App, Error, HttpMessage, HttpResponse, HttpServer,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    middleware::{Next, from_fn},
    web::{self, post},
};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bincode;
use serde::{Deserialize, Serialize as SerdeSerialize};
use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::{hash::Hash, native_token::lamports_to_sol};
use spl_memo::solana_program::pubkey::Pubkey;
use sqlx::postgres::PgPoolOptions;
use std::{env, str::FromStr};
use store::{CreateKeyshareRequest, Store};
mod jwt;
use dotenv::dotenv;

use crate::{
    serialization::{AggMessage1, PartialSignature, SecretAggStepOne, Serialize},
    tss::{
        key_agg, sign_and_broadcast, sign_swap_transaction, step_one,
        step_two_send_sol_transaction, step_two_send_token_transaction, step_two_swap_transaction,
    },
};

#[derive(SerdeSerialize, Deserialize)]
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

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
}

#[derive(Deserialize)]
struct SignInRequest;

#[derive(Deserialize)]
struct AggregateKeysRequest {
    keys: Vec<String>,
}

#[derive(Deserialize)]
pub struct AggSendStep2Request {
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct SignSwapTransactionRequest {
    tx_b64: String,
    public_key_1: String,
    public_key_2: String,
    public_key_3: String,
    partial_signature_1: String,
    partial_signature_2: String,
    partial_signature_3: String,
    recent_blockhash: String,
}

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv().ok();

    let port = env::var("PORT").unwrap_or("8000".to_string());

    let database_url = env::var("DATABASE_URL").unwrap_or(String::from(""));
    println!("{}", port);
    println!("{}", database_url);

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .unwrap();

    let store = Store::new(pool);

    async fn auth_middleware(
        req: ServiceRequest,
        next: Next<impl MessageBody>,
    ) -> Result<ServiceResponse<impl MessageBody>, Error> {
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if jwt::validate_jwt(auth_str).is_ok() {
                    let claims = jwt::validate_jwt(auth_str).unwrap();
                    req.request().extensions_mut().insert(AuthenticatedUser {
                        user_id: claims.sub,
                        email: claims.email,
                    });
                    println!("authenticated");
                    return next.call(req).await;
                } else {
                    return Err(Error::from(ErrorUnauthorized(
                        "Unauthorized (requires authentication)".to_string(),
                    )));
                }
            }
        }
        return Err(Error::from(ErrorUnauthorized(
            "Unauthorized (requires authentication)".to_string(),
        )));
    }

    HttpServer::new(move || {
        App::new()
            .wrap(from_fn(auth_middleware))
            .app_data(web::Data::new(store.clone()))
            .route("/generate", post().to(generate))
            .route("/aggregate-keys", post().to(aggregate_keys))
            .route("/agg-send-step1", post().to(agg_send_step_1))
            .route("/agg-send-step2", post().to(agg_send_step_2))
            .route("/agg-send-step2-swap", post().to(agg_send_step_2_swap))
            .route(
                "/aggregate-signatures-broadcast",
                post().to(aggregate_signatures_broadcast),
            )
            .route(
                "/sign-swap-transaction",
                post().to(sign_swap_transaction_endpoint),
            )
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}

async fn generate(
    store: web::Data<Store>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    println!("generate called");
    let keypair = Keypair::generate(&mut rand07::thread_rng());
    let publickey = keypair.try_pubkey().unwrap().to_string();
    println!("publickey: {:?}", publickey);

    return match store
        .add_keyshare(CreateKeyshareRequest {
            user_id: user.user_id.clone(),
            public_key: publickey,
            private_key: keypair.to_base58_string(),
        })
        .await
    {
        Ok(user) => {
            println!("user: {:?}", user);

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "public_key": user.public_key,
            })))
        }

        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            })));
        }
    };
}

async fn aggregate_keys(req: web::Json<AggregateKeysRequest>) -> Result<HttpResponse, Error> {
    let a = key_agg(
        req.keys
            .clone()
            .iter()
            .map(|k| k.parse::<Pubkey>().unwrap())
            .collect(),
        None,
    );
    match a {
        Ok(val) => {
            let pubkey = Pubkey::new(&*val.agg_public_key.to_bytes(true));
            println!("agg_key: {:?}", pubkey);
            println!("agg_key string: {}", pubkey.to_string());
            return Ok(HttpResponse::Ok().json(serde_json::json!({
              "agg_key": pubkey.to_string()
            })));
        }
        Err(error) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string()
            })));
        }
    }
}

async fn agg_send_step_1(
    store: web::Data<Store>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    println!("yo bro");
    let private_key = store.get_private_key(&user.user_id).await.unwrap();

    let (first_messg1, secret1) = step_one(Keypair::from_base58_string(&private_key));
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "shared_message": first_messg1.serialize_bs58(),
        "secret_message": secret1.serialize_bs58(),
        "public_key":Keypair::from_base58_string(&private_key).try_pubkey().unwrap().to_string(),
    })))
}

async fn agg_send_step_2(
    req: web::Json<AggSendStep2Request>,
    store: web::Data<Store>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    let private_key = store.get_private_key(&user.user_id).await.unwrap();
    let recent_hash = Hash::from_str(&req.recent_blockhash).unwrap();

    println!("req.mint {:?}", req.mint);

    let partial_signature1 = if let Some(mint_str) = &req.mint {
        step_two_send_token_transaction(
            Keypair::from_base58_string(&private_key),
            req.amount as f64,
            Pubkey::from_str(&req.to).unwrap(),
            Pubkey::from_str(mint_str).unwrap(),
            None,
            recent_hash,
            vec![
                Pubkey::from_str(req.public_key_1.as_str()).unwrap(),
                Pubkey::from_str(req.public_key_2.as_str()).unwrap(),
                Pubkey::from_str(req.public_key_3.as_str()).unwrap(),
            ],
            vec![
                AggMessage1::deserialize_bs58(&req.shared_message_1).unwrap(),
                AggMessage1::deserialize_bs58(&req.shared_message_2).unwrap(),
            ],
            SecretAggStepOne::deserialize_bs58(&req.secret_message).unwrap(),
        )
        .await
    } else {
        step_two_send_sol_transaction(
            Keypair::from_base58_string(&private_key),
            lamports_to_sol(req.amount),
            Pubkey::from_str(&req.to).unwrap(),
            None,
            recent_hash,
            vec![
                Pubkey::from_str(req.public_key_1.as_str()).unwrap(),
                Pubkey::from_str(req.public_key_2.as_str()).unwrap(),
                Pubkey::from_str(req.public_key_3.as_str()).unwrap(),
            ],
            vec![
                AggMessage1::deserialize_bs58(&req.shared_message_1).unwrap(),
                AggMessage1::deserialize_bs58(&req.shared_message_2).unwrap(),
            ],
            SecretAggStepOne::deserialize_bs58(&req.secret_message).unwrap(),
        )
    }
    .unwrap();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "partial_signature": partial_signature1.serialize_bs58(),
    })))
}

async fn agg_send_step_2_swap(
    req: web::Json<AggSendStep2SwapRequest>,
    store: web::Data<Store>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    println!("yo bro step2");
    let private_key = store.get_private_key(&user.user_id).await.unwrap();

    // Use the provided recent block hash instead of fetching it independently
    let recent_hash = Hash::from_str(&req.recent_blockhash).unwrap();
    println!("req.tx_b64 {:?}", req.tx_b64);
    println!("req.secret_message {:?}", req.secret_message);
    println!("req.shared_message_1 {:?}", req.shared_message_1);
    println!("req.shared_message_2 {:?}", req.shared_message_2);
    println!("req.public_key_1 {:?}", req.public_key_1);
    println!("req.public_key_2 {:?}", req.public_key_2);
    println!("req.public_key_3 {:?}", req.public_key_3);
    println!("req.recent_blockhash {:?}", req.recent_blockhash);
    let partial_signature1 = step_two_swap_transaction(
        Keypair::from_base58_string(&private_key),
        req.tx_b64.clone(),
        None,
        recent_hash,
        vec![
            Pubkey::from_str(req.public_key_1.as_str()).unwrap(),
            Pubkey::from_str(req.public_key_2.as_str()).unwrap(),
            Pubkey::from_str(req.public_key_3.as_str()).unwrap(),
        ],
        vec![
            AggMessage1::deserialize_bs58(&req.shared_message_1).unwrap(),
            AggMessage1::deserialize_bs58(&req.shared_message_2).unwrap(),
        ],
        SecretAggStepOne::deserialize_bs58(&req.secret_message).unwrap(),
    )
    .unwrap();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "partial_signature": partial_signature1.serialize_bs58(),
    })))
}

async fn aggregate_signatures_broadcast(
    req: web::Json<AggregateSignaturesBroadcastRequest>,
    _store: web::Data<Store>,
    _user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    let recent_hash = Hash::from_str(&req.recent_blockhash).unwrap();

    let mint = if let Some(mint_str) = &req.mint {
        Some(Pubkey::from_str(mint_str).unwrap())
    } else {
        None
    };

    let amount = if let Some(_mint_str) = &req.mint {
        req.amount as f64
    } else {
        lamports_to_sol(req.amount)
    };

    let tx = sign_and_broadcast(
        mint,
        amount,
        Pubkey::from_str(&req.to).unwrap(),
        None,
        recent_hash,
        vec![
            Pubkey::from_str(req.public_key_1.as_str()).unwrap(),
            Pubkey::from_str(req.public_key_2.as_str()).unwrap(),
            Pubkey::from_str(req.public_key_3.as_str()).unwrap(),
        ],
        vec![
            PartialSignature::deserialize_bs58(&req.partial_signature_1).unwrap(),
            PartialSignature::deserialize_bs58(&req.partial_signature_2).unwrap(),
            PartialSignature::deserialize_bs58(&req.partial_signature_3).unwrap(),
        ],
    )
    .await
    .map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "aggregate signatures broadcast error: {}",
            e
        ))
    })?;
    println!("tx {:?}", tx);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tx": tx,
    })))
}

async fn sign_swap_transaction_endpoint(
    req: web::Json<SignSwapTransactionRequest>,
    _store: web::Data<Store>,
    _user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    let recent_hash = Hash::from_str(&req.recent_blockhash).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid recent blockhash: {}", e))
    })?;

    let keys = vec![
        Pubkey::from_str(&req.public_key_1).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid public_key_1: {}", e))
        })?,
        Pubkey::from_str(&req.public_key_2).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid public_key_2: {}", e))
        })?,
        Pubkey::from_str(&req.public_key_3).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid public_key_3: {}", e))
        })?,
    ];

    let signatures = vec![
        PartialSignature::deserialize_bs58(&req.partial_signature_1).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid partial_signature_1: {}", e))
        })?,
        PartialSignature::deserialize_bs58(&req.partial_signature_2).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid partial_signature_2: {}", e))
        })?,
        PartialSignature::deserialize_bs58(&req.partial_signature_3).map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid partial_signature_3: {}", e))
        })?,
    ];

    match sign_swap_transaction(req.tx_b64.clone(), recent_hash, keys, signatures) {
        Ok(versioned_tx) => {
            let tx_bytes = bincode::serialize(&versioned_tx).map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Failed to serialize transaction: {}",
                    e
                ))
            })?;
            let tx_base64 = B64.encode(&tx_bytes);

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "signed_transaction": tx_base64,
                "signature": versioned_tx.signatures[0].to_string()
            })))
        }
        Err(e) => {
            println!("Failed to sign swap transaction: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(format!(
                "Failed to sign swap transaction: {:?}",
                e
            )))
        }
    }
}
