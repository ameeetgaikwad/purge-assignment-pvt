pub mod user;
pub mod mpc;
pub mod assets;
pub mod balance;
pub mod quotes;
pub use user::{UserError, User, CreateUserRequest, SignInRequest};
pub use mpc::{KeyshareError, Keyshare, CreateKeyshareRequest};
pub use assets::{AssetError, Asset, AssetStore};
pub use balance::{BalanceError, Balance, BalanceStore};
pub use quotes::{QuoteError, Quote, QuoteStore};
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
