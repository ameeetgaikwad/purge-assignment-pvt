use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use chrono::{Duration, Utc};

const JWT_SECRET: &str = "your-secret-key"; // In production, use environment variable
const JWT_EXPIRATION_HOURS: i64 = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user id)
    pub email: String,
    pub exp: i64, // Expiration time
    pub iat: i64, // Issued at
}

pub fn generate_jwt(user_id: &str, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now + Duration::hours(JWT_EXPIRATION_HOURS);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: expiration.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )
}

pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS256);
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &validation,
    )?;

    Ok(token_data.claims)
}


