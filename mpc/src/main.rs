use actix_web::{
    App, Error, HttpMessage, HttpResponse, HttpServer,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    middleware::{Next, from_fn},
    web::{self, post},
};
use solana_client::rpc_client::RpcClient;

use std::{env, str::FromStr};
pub mod error;
pub mod serialization;
pub mod tss;

use serde::Deserialize;
use solana_sdk::{
    hash::Hash,
    instruction::Instruction,
    native_token::{lamports_to_sol, sol_to_lamports},
};
use solana_sdk::{message::Message, native_token::LAMPORTS_PER_SOL};

use solana_sdk::signer::Signer;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::transaction::Transaction;
use solana_sdk::{native_token, system_instruction};
use spl_memo::solana_program::pubkey::Pubkey;
use sqlx::postgres::PgPoolOptions;
use store::{CreateKeyshareRequest, Store};
mod jwt;
use dotenv::dotenv;

use crate::{
    serialization::{AggMessage1, PartialSignature, SecretAggStepOne, Serialize},
    tss::{key_agg, sign_and_broadcast, step_one, step_two},
};
use aes_gcm::{
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

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

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv().ok();
    // let ciphertext1 = base64::decode(
    //     "pVOjVyIjkiXKJZYk3t2EWILOG6/cz1HR74RFzVW2LH93ZM/0kbmrrEuz+kyVCxyKEQihG3Jk7CXCvtYflkUmPGoRRSd0fUGr/3exhhz6FJYRs+Qo38cr0WLpfpII8FEvI/UOeak1Dw==",
    // ).unwrap();

    // // println!("ciphertext1 {:?}", ciphertext1);
    // let ciphertext2 = base64::decode(
    //     "5VOLTSJzpHKmQ7wh5dyePrWFIbD10FCa1oFG4XuAAnpuEcL5tvidr0iK40X1CT3NPhGJPUlEjgXz49MA6UoIQA8SZggkSmm34WmS7R7pI6804dwj/7M2gfR7W1Vc+JZMGAIHCARih8A=",
    // ).unwrap();
    // let ciphertext3 = base64::decode(
    //     "5WaLfS8XiiKaV5IW5taPetbnNJ2111Ou1aV76HuAEChie9HNu82UqHe32ULHAgGKcCisZ0wJqSnzra9OqhQmSF8xZBx7XHuE6VKvqhmTBrI7/rQY6sVh+iXz6wwf/6l9wscjkG51uUI=",
    // ).unwrap();

    // let key: &[u8] = &[42; 32];

    // let key = Key::<Aes256Gcm>::from_slice(key);

    // let cipher = Aes256Gcm::new(&key);
    // let nonce_bytes = [222, 241, 176, 58, 74, 195, 102, 67, 153, 72, 159, 66]; // 96-bits; unique per message
    // let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message

    // let plaintext1 = String::from_utf8(cipher.decrypt(&nonce, ciphertext1.as_ref()).unwrap());
    // let plaintext2 = String::from_utf8(cipher.decrypt(&nonce, ciphertext2.as_ref()).unwrap());
    // let plaintext3 = String::from_utf8(cipher.decrypt(&nonce, ciphertext3.as_ref()).unwrap());
    // println!("plain1 {:?}", plaintext1);
    // println!("plain2 {:?}", plaintext2);
    // println!("plain3 {:?}", plaintext3);

    // let ciphertext = cipher
    //     .encrypt(&nonce, request.private_key.as_ref())
    //     .unwrap();
    // let b64 = base64::encode(&ciphertext);
    // let ciphertext2 = base64::decode(&b64).unwrap();
    // println!("cypher {:?}", b64);
    // let plaintext = String::from_utf8(cipher.decrypt(&nonce, ciphertext2.as_ref()).unwrap());
    // println!("plain {:?}", plaintext);

    // let keypair1 = Keypair::generate(&mut rand07::thread_rng());
    // let publickey1 = keypair1.try_pubkey().unwrap();
    // let keypair2 = Keypair::generate(&mut rand07::thread_rng());
    // let publickey2 = keypair2.try_pubkey().unwrap();
    // println!("{:?}", publickey1);
    // println!("{:?}", publickey2);
    // let a = key_agg(vec![publickey1, publickey2], None);
    // match a {
    //     Ok(val) => {
    //         println!("yo bois final public key{}", Pubkey::new(&*val.agg_public_key.to_bytes(true)))
    //     }
    //     Err(_) => {
    //         println!("Error")
    //     }
    // }
    // let (first_messg1, secret1) = step_one(Keypair::from_base58_string(
    //     "3FnSkWv1fFtpAdRr2QXZ3AiMtUUHCsffvSvQYAjVFVwmjHE38mN7K5tMdzN7zgi1bkPwnBxBrhJvW9QENz2RC337",
    // ));
    // println!("step_1 {:?}", first_messg1.serialize_bs58());
    // println!("secret_1 {:?}", secret1.serialize_bs58());
    let rpc_client = RpcClient::new("https://api.mainnet-beta.solana.com".to_string());
    let recent_hash = tokio::task::spawn_blocking(move || rpc_client.get_latest_blockhash())
        .await
        .unwrap()
        .unwrap();

    let partial_signature1=step_two(
        Keypair::from_base58_string(
            "ssFyfcn664pByoYPfxwhZYk2NtkmmEZ1cLhhs5URzRTc8AX3YMCKuX1AUi7fF6iEWKqLacBmdMTZRPCad7bbv1y",
        ),
        f64::from(0.0001),
        Pubkey::from_str("BC4qCkbsGtPRjwXhrJD5415Cxn6swrFB4d5RKn9Vm3XF").unwrap(),
        None,
        Hash::new_from_array(recent_hash.to_bytes()),
        vec![
            Pubkey::from_str("BCVnjtkGjDDUHweVQM6uc9rA2U6tq7HJ5rYe53Ge9JM1").unwrap(),
            Pubkey::from_str("BFt9ubm8BJAAmutLKFXzmkFLYh14JgZSyTWB5CZ5xoCr").unwrap(),
            Pubkey::from_str("GBJZcD5afxJCfGdH1GET4fwvGGXmPNd85gKfqTCfiHJR").unwrap(),
        ],
        vec![AggMessage1::deserialize_bs58("15MnY8hbzDduEntA5gL2x5Hr92T4ZxRKxh5ggxZN4f3FW3TNYNCEvdstQfy9tzwAb5BDkhJ6D896BbxCipQEZF5HC3NZmhxAxnauTN9evPVCbHeNKE1G7T7VXH3gocnRqSiJ").unwrap(),AggMessage1::deserialize_bs58("1ohyeafCXoUg1A9vZYaDa3nQ1MYvNVSMEPrZjVcHcCHnSid8jDLDHs4pjCVYnAqe6ni999VaDAVJQxR49PeHBMtwCJZQDG54uSRBptEbWMb8cPZiu6aDuKP5WzzEenJRM9Yu").unwrap()],
        SecretAggStepOne::deserialize_bs58("2oREvZXgBAuXoRgk2G5b5XPZAta4gHjZFrd54b2NsrdyJtxVMfDuELnjLyGpCKsRTZSyMs4PHS67HNK9cDPQ7pkUz2pfW2GfZtiT7Lp58pJn5pg3Qb1qgVAMfVZsiaJWKLRNxjswvzBV8zvV3RZ8XjAenCggZ698kp1EkRFnMArsQEHR").unwrap(),
    ).unwrap();
    let partial_signature2=step_two(
        Keypair::from_base58_string(
            "3sncf3XaZRZGBnC6Q3MwsFjywqhACst4z9eeTtcQykMjXCytvTkmNxSad42y99G92HRc1TjqzSw1PCtXAeZiVEdL",
        ),
        f64::from(0.0001),
        Pubkey::from_str("BC4qCkbsGtPRjwXhrJD5415Cxn6swrFB4d5RKn9Vm3XF").unwrap(),
        None,
        Hash::new_from_array(recent_hash.to_bytes()),
        vec![
            Pubkey::from_str("BCVnjtkGjDDUHweVQM6uc9rA2U6tq7HJ5rYe53Ge9JM1").unwrap(),
            Pubkey::from_str("BFt9ubm8BJAAmutLKFXzmkFLYh14JgZSyTWB5CZ5xoCr").unwrap(),
            Pubkey::from_str("GBJZcD5afxJCfGdH1GET4fwvGGXmPNd85gKfqTCfiHJR").unwrap(),
        ],
        vec![AggMessage1::deserialize_bs58("12A3HAeGZjpWV6S9xyxMqTwvu822GfCRUh4N11gkBNJSs2mA2fVCvtC65MR6AeQL9y5pnS74NFkeJuNFwSPUwgY3LAGWaJBVnuEDdjhX6cWsacaJo1mQPRN54LZ4oGw2ujQjm").unwrap(),AggMessage1::deserialize_bs58("1ohyeafCXoUg1A9vZYaDa3nQ1MYvNVSMEPrZjVcHcCHnSid8jDLDHs4pjCVYnAqe6ni999VaDAVJQxR49PeHBMtwCJZQDG54uSRBptEbWMb8cPZiu6aDuKP5WzzEenJRM9Yu").unwrap()],
        SecretAggStepOne::deserialize_bs58("2VGqoBmcbksZgrFSNmiMQYKD2hvEZGq72SV14YfdjXuN8Uj35sUj7jbGzXkrpQE3WwWKjeAnW3BPxEgN3BsSMneSPvgA1WNXJPgoUCu2282mNFF5nggG4zD8EKbDhfv1j75zeh6EB452W2utSj8qPdCS7RTD5diRbJVi5SsSHyWtWdtZ").unwrap(),
    ).unwrap();
    let partial_signature3=step_two(
        Keypair::from_base58_string(
            "3FnSkWv1fFtpAdRr2QXZ3AiMtUUHCsffvSvQYAjVFVwmjHE38mN7K5tMdzN7zgi1bkPwnBxBrhJvW9QENz2RC337",
        ),
        f64::from(0.0001),
        Pubkey::from_str("BC4qCkbsGtPRjwXhrJD5415Cxn6swrFB4d5RKn9Vm3XF").unwrap(),
        None,
        Hash::new_from_array(recent_hash.to_bytes()),
        vec![
            Pubkey::from_str("BCVnjtkGjDDUHweVQM6uc9rA2U6tq7HJ5rYe53Ge9JM1").unwrap(),
            Pubkey::from_str("BFt9ubm8BJAAmutLKFXzmkFLYh14JgZSyTWB5CZ5xoCr").unwrap(),
            Pubkey::from_str("GBJZcD5afxJCfGdH1GET4fwvGGXmPNd85gKfqTCfiHJR").unwrap(),
        ],
        vec![AggMessage1::deserialize_bs58("15MnY8hbzDduEntA5gL2x5Hr92T4ZxRKxh5ggxZN4f3FW3TNYNCEvdstQfy9tzwAb5BDkhJ6D896BbxCipQEZF5HC3NZmhxAxnauTN9evPVCbHeNKE1G7T7VXH3gocnRqSiJ").unwrap(),AggMessage1::deserialize_bs58("12A3HAeGZjpWV6S9xyxMqTwvu822GfCRUh4N11gkBNJSs2mA2fVCvtC65MR6AeQL9y5pnS74NFkeJuNFwSPUwgY3LAGWaJBVnuEDdjhX6cWsacaJo1mQPRN54LZ4oGw2ujQjm").unwrap()],
        SecretAggStepOne::deserialize_bs58("2ULUyApiGU9J42yhpc9edWqLUEBxjY6zGwzi5hjywShdULT4VvCEq8W6PakDEKa6Krq2iSHUBx7UgC5vFvX8YCovZujDjTpRQWUqKMpfxPAzRM1BHwxLvyt91VURP97tMnaVsZecfmCdGmeE63ufDtyyYQUm1XrYVRqmXFym2Yji7NNE").unwrap(),
    ).unwrap();

    let tx = sign_and_broadcast(
        f64::from(0.0001),
        Pubkey::from_str("BC4qCkbsGtPRjwXhrJD5415Cxn6swrFB4d5RKn9Vm3XF").unwrap(),
        None,
        Hash::new_from_array(recent_hash.to_bytes()),
        vec![
            Pubkey::from_str("BCVnjtkGjDDUHweVQM6uc9rA2U6tq7HJ5rYe53Ge9JM1").unwrap(),
            Pubkey::from_str("BFt9ubm8BJAAmutLKFXzmkFLYh14JgZSyTWB5CZ5xoCr").unwrap(),
            Pubkey::from_str("GBJZcD5afxJCfGdH1GET4fwvGGXmPNd85gKfqTCfiHJR").unwrap(),
        ],
        vec![PartialSignature::deserialize_bs58("Dd1MVkQBFmnXcrfTbBrvSxFGZck9hBJ5ZrJNnWV1kP5UAtmrcmnWF2x8AKc6cLfaX9te6aSYDZBPNzDJg3UtJWQC").unwrap(), PartialSignature::deserialize_bs58("EyD8PMUcYnxnRDSSbLqWncR38MoTRXBrSqpg3sU5HG1u4GTwppLfXMUkQf15Mq2a4xDT6vSBFJVrkAB9fEo2XePJ").unwrap(), PartialSignature::deserialize_bs58("EDR4cUiDw22cAgdDz8REE8tNfqDKS7BsffyEzWzWTj7k47J3Lr7GhmUuaiRUmehxDrNjf72rxcSHKj1b7C5Grcro").unwrap()],
    )
    .map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "sign and broadcast error: {}",
            e
        ))
    });
    println!("tx {:?}", tx);

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
        println!("auth_middleware");
        // pre-processing
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
            .route("/send-single", post().to(send_single))
            .route("/aggregate-keys", post().to(aggregate_keys))
            .route("/agg-send-step1", post().to(agg_send_step1))
            .route("/agg-send-step2", post().to(agg_send_step2))
            .route(
                "/aggregate-signatures-broadcast",
                post().to(aggregate_signatures_broadcast),
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
    let keypair = Keypair::generate(&mut rand07::thread_rng());
    let publickey = keypair.try_pubkey().unwrap().to_string();

    return match store
        .add_keyshare(CreateKeyshareRequest {
            user_id: user.user_id.clone(),
            public_key: publickey,
            private_key: keypair.to_base58_string(),
        })
        .await
    {
        Ok(user) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "public_key": user.public_key,
        }))),

        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            })));
        }
    };
}

async fn send_single() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("Hello, world!"))
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

async fn agg_send_step1(
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

async fn agg_send_step2(
    req: web::Json<AggSendStep2Request>,
    store: web::Data<Store>,
    user: web::ReqData<AuthenticatedUser>,
) -> Result<HttpResponse, Error> {
    println!("yo bro step2");
    let private_key = store.get_private_key(&user.user_id).await.unwrap();

    // Use the provided recent block hash instead of fetching it independently
    let recent_hash = Hash::from_str(&req.recent_blockhash).unwrap();
    println!("req.amount this from mcp {:?}", req.amount);
    let partial_signature1 = step_two(
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
    println!("yo bro step3");
    // Use the provided recent block hash instead of fetching it independently
    let recent_hash = Hash::from_str(&req.recent_blockhash).unwrap();

    let tx = sign_and_broadcast(
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
            PartialSignature::deserialize_bs58(&req.partial_signature_1).unwrap(),
            PartialSignature::deserialize_bs58(&req.partial_signature_2).unwrap(),
            PartialSignature::deserialize_bs58(&req.partial_signature_3).unwrap(),
        ],
    )
    .map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!(
            "aggregate signatures broadcast error: {}",
            e
        ))
    })?;
    println!("tx {:?}", tx);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tx": tx.signatures[0].to_string(),
    })))
}

pub fn create_unsigned_transaction(
    amount: f64,
    to: &Pubkey,
    memo: Option<String>,
    payer: &Pubkey,
) -> Transaction {
    let amount = native_token::sol_to_lamports(amount);
    let transfer_ins = system_instruction::transfer(payer, to, amount);
    let msg = match memo {
        None => Message::new(&[transfer_ins], Some(payer)),
        Some(memo) => {
            let memo_ins = Instruction {
                program_id: spl_memo::id(),
                accounts: Vec::new(),
                data: memo.into_bytes(),
            };
            Message::new(&[transfer_ins, memo_ins], Some(payer))
        }
    };
    Transaction::new_unsigned(msg)
}
