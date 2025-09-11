pub mod user;
pub mod mpc;

pub use user::{UserError, User, CreateUserRequest, SignInRequest};
pub use mpc::{KeyshareError, Keyshare, CreateKeyshareRequest};

use sqlx::PgPool;
#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
