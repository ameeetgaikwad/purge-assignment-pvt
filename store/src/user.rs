
use crate::Store;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub struct AddPublicKeyRequest {
    pub id: String,
    pub public_key: String,
}

#[derive(Debug)]
pub struct SignInRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub enum UserError {
    UserExists,
    UserNotFound,
    InvalidCredentials,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::UserExists => write!(f, "User already exists"),
            UserError::UserNotFound => write!(f, "User not found"),
            UserError::InvalidCredentials => write!(f, "Invalid credentials"),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for UserError {}

impl Store {
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, UserError> {
        // Validate email format
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        // Validate password length
        if request.password.len() < 6 {
            return Err(UserError::InvalidInput(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Check if user already exists
        let existing_user = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(&request.email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        if existing_user.is_some() {
            return Err(UserError::UserExists);
        }

        // Hash the password
        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)
            .map_err(|e| UserError::DatabaseError(format!("Password hashing failed: {}", e)))?;

        // Generate user ID and timestamp
        let user_id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Insert user into database
        sqlx::query(
            "INSERT INTO users (id, email, password, created_at) VALUES ($1, $2, $3, $4)"
        )
        .bind(&user_id)
        .bind(&request.email)
        .bind(&password_hash)
        .bind(&created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Return the created user
        let user = User {
            id: user_id,
            email: request.email,
            created_at: created_at.to_rfc3339(),
        };

        Ok(user)
    }
    pub async fn signin_user(&self, request: SignInRequest) -> Result<User, UserError> {
        // Validate email format
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        // Get user from database
        let user_record = sqlx::query(
            "SELECT id, email, password, created_at FROM users WHERE email = $1"
        )
        .bind(&request.email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        // Verify password
        let password_hash: String = user_record.get("password");
        let password_valid = bcrypt::verify(&request.password, &password_hash)
            .map_err(|e| {
                UserError::DatabaseError(format!("Password verification failed: {}", e))
            })?;

        if !password_valid {
            return Err(UserError::InvalidCredentials);
        }

        // Return the user
        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: user_record.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        };

        Ok(user)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User, UserError> {
        let user_record = sqlx::query(
            "SELECT id, email, created_at FROM users WHERE email = $1"
        )
        .bind(&email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: user_record.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        };

        Ok(user)
    }

    pub async fn add_public_key(&self, request: AddPublicKeyRequest) -> Result<User, UserError> {
        sqlx::query(
            "UPDATE users SET \"publicKey\" = $2 WHERE id = $1"
        )
        .bind(&request.id)
        .bind(&request.public_key)
        .execute(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Fetch and return the updated user
        let user_record = sqlx::query(
            "SELECT id, email, created_at FROM users WHERE id = $1"
        )
        .bind(&request.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        let user_record = user_record.ok_or(UserError::UserNotFound)?;

        let user = User {
            id: user_record.get("id"),
            email: user_record.get("email"),
            created_at: user_record.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        };

        Ok(user)
    }

    pub async fn has_public_key(&self, user_id: &str) -> Result<bool, UserError> {
        let result = sqlx::query(
            "SELECT \"publicKey\" FROM users WHERE id = $1"
        )
        .bind(&user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        match result {
            Some(record) => {
                let public_key: Option<String> = record.get("publicKey");
                Ok(public_key.is_some())
            },
            None => Err(UserError::UserNotFound),
        }
    }
}
