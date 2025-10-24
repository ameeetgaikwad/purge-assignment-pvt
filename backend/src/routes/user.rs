use actix_web::{HttpResponse, Result, web};
use serde::{Deserialize, Serialize};
use store::{CreateUserRequest, SignInRequest as StoreSignInRequest, Store, UserError};

use crate::{AuthenticatedUser, helpers, jwt};

#[derive(Deserialize, Clone)]
pub struct SignUpRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SignInRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub email: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    message: String,
}

#[actix_web::post("/signup")]
pub async fn sign_up(
    req: web::Json<SignUpRequest>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    println!("sign_up: ");
    match store
        .create_user(CreateUserRequest {
            email: req.username.clone(),
            password: req.password.clone(),
        })
        .await
    {
        Ok(_) => {
            let response = SignupResponse {
                message: "signed up successfully".to_string(),
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            println!("sign_up error: {:?}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    }
}

#[actix_web::post("/signin")]
pub async fn sign_in(
    req: web::Json<SignInRequest>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    match store
        .signin_user(StoreSignInRequest {
            email: req.username.clone(),
            password: req.password.clone(),
        })
        .await
    {
        Ok(user) => match jwt::generate_jwt(&user.id, &user.email) {
            Ok(token) => {
                // Check if user already has a public key (first-time sign-in check)
                match store.has_public_key(&user.id).await {
                    Ok(has_key) => {
                        if !has_key {
                            // First-time user: generate MPC keys
                            match helpers::generate_mpc_keys_for_user(&user.id, &token).await {
                                Ok(key_request) => match store.add_public_key(key_request).await {
                                    Ok(updated_user) => {
                                        println!(
                                            "Successfully generated and stored MPC keys for user: {}",
                                            updated_user.email
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to store public key: {}", e);
                                        return Ok(HttpResponse::InternalServerError().json(
                                            serde_json::json!({
                                                "error": "Failed to store public key"
                                            }),
                                        ));
                                    }
                                },
                                Err(e) => {
                                    println!("Failed to generate MPC keys: {:?}", e);
                                    return Ok(HttpResponse::InternalServerError().json(
                                        serde_json::json!({
                                            "error": "Failed to generate keys"
                                        }),
                                    ));
                                }
                            }
                        }

                        let response = AuthResponse { token };
                        Ok(HttpResponse::Ok().json(response))
                    }
                    Err(e) => {
                        eprintln!("Failed to check public key status: {:?}", e);
                        Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Internal server error"
                        })))
                    }
                }
            }
            Err(_) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }))),
        },
        Err(UserError::UserNotFound) | Err(UserError::InvalidCredentials) => {
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })))
        }
        Err(_) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }))),
    }
}

#[actix_web::get("/user")]
pub async fn get_user(user: web::ReqData<AuthenticatedUser>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
      "email": user.email
    })))
}
