use actix_web::{
    App, Error, HttpMessage, HttpServer,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    middleware::{Next, from_fn},
    web,
};
use sqlx::postgres::PgPoolOptions;

use store::Store;

mod jwt;
mod routes;
mod helpers;
use routes::*;

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Database connection - in production, use environment variables
    let database_url = String::from(
        "postgresql://postgres:QYJoNSX0XbSzqu10@db.zeiadaunvxihotiuqtxd.supabase.co:5432/postgres",
    );

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
        // pre-processing
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if jwt::validate_jwt(auth_str).is_ok() {
                    let claims = jwt::validate_jwt(auth_str).unwrap();
                    req.request().extensions_mut().insert(AuthenticatedUser {
                        user_id: claims.sub,
                        email: claims.email,
                    });
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
            .app_data(web::Data::new(store.clone()))
            // Public routes (no middleware)
            .service(
                web::scope("/api/v1")
                    .service(sign_up)
                    .service(sign_in)
                    .service(
                        web::scope("")
                            .wrap(from_fn(auth_middleware))
                            .service(get_user)
                            .service(quote)
                            .service(swap)
                            .service(send)
                            .service(sol_balance)
                            .service(token_balance),
                    ),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
