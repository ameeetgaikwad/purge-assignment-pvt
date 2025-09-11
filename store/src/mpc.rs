use crate::Store;
use sqlx::Row;

use aes_gcm::{
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Clone)]
pub struct Keyshare {
    pub user_id: String,
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug)]
pub struct CreateKeyshareRequest {
    pub user_id: String,
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug)]
pub enum KeyshareError {
    InvalidInput(String),
    DatabaseError(String),
    KeyshareNotFound,
    UserExists,
}

impl std::fmt::Display for KeyshareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyshareError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            KeyshareError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            KeyshareError::KeyshareNotFound => write!(f, "Keyshare not found"),
            KeyshareError::UserExists => write!(f, "User already exists"),
        }
    }
}

impl std::error::Error for KeyshareError {}

impl Store {
    pub async fn add_keyshare(
        &self,
        request: CreateKeyshareRequest,
    ) -> Result<Keyshare, KeyshareError> {
        // Validate input
        if request.user_id.is_empty() {
            return Err(KeyshareError::InvalidInput(
                "User ID cannot be empty".to_string(),
            ));
        }

        if request.public_key.is_empty() {
            return Err(KeyshareError::InvalidInput(
                "Public key cannot be empty".to_string(),
            ));
        }

        if request.private_key.is_empty() {
            return Err(KeyshareError::InvalidInput(
                "Private key cannot be empty".to_string(),
            ));
        }

        let key: &[u8] = &[42; 32];

        let key = Key::<Aes256Gcm>::from_slice(key);

        let cipher = Aes256Gcm::new(&key);
        let nonce_bytes = [222, 241, 176, 58, 74, 195, 102, 67, 153, 72, 159, 66]; // 96-bits; unique per message
        let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message
        // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(&nonce, request.private_key.as_ref())
            .unwrap();
        let b64 = general_purpose::STANDARD.encode(&ciphertext);
        // let ciphertext2 = base64::decode(&b64).unwrap();
        // println!("cypher {:?}", b64);
        // let plaintext = String::from_utf8(cipher.decrypt(&nonce, ciphertext2.as_ref()).unwrap());
        // println!("plain {:?}", plaintext);

        let existing_user = sqlx::query("SELECT id FROM keyshares WHERE user_id = $1")
            .bind(&request.user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| KeyshareError::DatabaseError(e.to_string()))?;

        if existing_user.is_some() {
            return Err(KeyshareError::UserExists);
        }

        let row = sqlx::query(
            r#"
            INSERT INTO keyshares (user_id, "publicKey", "privateKey") 
            VALUES ($1, $2, $3) 
            RETURNING user_id, "publicKey", "privateKey"
            "#,
        )
        .bind(&request.user_id)
        .bind(&request.public_key)
        .bind(b64)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| KeyshareError::DatabaseError(e.to_string()))?;

        let keyshare = Keyshare {
            user_id: row.get::<String, _>("user_id"),
            public_key: row.get::<String, _>("publicKey"),
            private_key: request.private_key,
        };

        Ok(keyshare)
    }

    pub async fn get_private_key(&self, user_id: &str) -> Result<String, KeyshareError> {
        // Validate input
        if user_id.is_empty() {
            return Err(KeyshareError::InvalidInput(
                "User ID cannot be empty".to_string(),
            ));
        }

        // Query the database for the keyshare
        let row = sqlx::query(
            r#"
            SELECT "privateKey" FROM keyshares WHERE user_id = $1
            "#,
        )
        .bind(&user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| KeyshareError::DatabaseError(e.to_string()))?;

        let encrypted_private_key = match row {
            Some(record) => record.get::<String, _>("privateKey"),
            None => return Err(KeyshareError::KeyshareNotFound),
        };

        // Decrypt the private key using the same encryption logic
        let key: &[u8] = &[42; 32];
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);
        let nonce_bytes = [222, 241, 176, 58, 74, 195, 102, 67, 153, 72, 159, 66]; // 96-bits; unique per message
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decode from base64 and decrypt
        let ciphertext = general_purpose::STANDARD.decode(&encrypted_private_key)
            .map_err(|e| KeyshareError::DatabaseError(format!("Failed to decode base64: {}", e)))?;
        
        let decrypted_private_key = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|e| KeyshareError::DatabaseError(format!("Failed to decrypt private key: {}", e)))?;

        let private_key = String::from_utf8(decrypted_private_key)
            .map_err(|e| KeyshareError::DatabaseError(format!("Failed to convert to string: {}", e)))?;

        Ok(private_key)
    }
}
