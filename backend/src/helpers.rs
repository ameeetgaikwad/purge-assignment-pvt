use serde::Deserialize;
use store::user::{AddPublicKeyRequest, User};

#[derive(Deserialize, Debug)]
pub struct McpResponse {
    pub public_key: String,
}

#[derive(Deserialize, Debug)]
pub struct AggKeyResponse {
    pub agg_key: String,
}

#[derive(Debug)]
pub enum MpcError {
    NetworkError(String),
    JsonError(String),
}

// impl std::error::Error for MpcError {}

pub async fn generate_mpc_keys_for_user(
    user_id: &str,
    token: &str,
) -> Result<AddPublicKeyRequest, MpcError> {
    let client = reqwest::Client::new();
    println!("entereddd");

    let res1 = client
        .post("http://127.0.0.1:8081/generate")
        .header("Authorization", token)
        .body("")
        .send()
        .await
        .map_err(|e| MpcError::NetworkError(e.to_string()))?
        .json::<McpResponse>()
        .await
        .map_err(|e| MpcError::JsonError(e.to_string()))?;

    let res2 = client
        .post("http://127.0.0.1:8082/generate")
        .header("Authorization", token)
        .body("")
        .send()
        .await
        .map_err(|e| MpcError::NetworkError(e.to_string()))?
        .json::<McpResponse>()
        .await
        .map_err(|e| MpcError::JsonError(e.to_string()))?;

    let res3 = client
        .post("http://127.0.0.1:8083/generate")
        .header("Authorization", token)
        .body("")
        .send()
        .await
        .map_err(|e| MpcError::NetworkError(e.to_string()))?
        .json::<McpResponse>()
        .await
        .map_err(|e| MpcError::JsonError(e.to_string()))?;
    println!("yo are almost done bois");
    // Agg
    let agg_pubkey = client
        .post("http://127.0.0.1:8081/aggregate-keys")
        .header("Authorization", token)
        .json(&serde_json::json!({
            "keys": vec![(res1.public_key), res2.public_key, res3.public_key]
        }))
        .send()
        .await
        .map_err(|e| MpcError::NetworkError(e.to_string()))?
        .json::<AggKeyResponse>()
        .await
        .map_err(|e| MpcError::JsonError(e.to_string()))?;
    println!("done finlaly {:?}", agg_pubkey);
    Ok(AddPublicKeyRequest {
        id: user_id.to_string(),
        public_key: agg_pubkey.agg_key,
    })
}
