mod transaction_handler;
use crate::transaction_handler::BlockchainEvent;
use crate::transaction_handler::handle_blockchain_event;
use bs58;
use futures_util::StreamExt;
use solana_pubkey::Pubkey;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcClient};
use yellowstone_grpc_proto::geyser::{
    SubscribeRequest, SubscribeRequestFilterAccounts, SubscribeRequestFilterAccountsFilter,
    SubscribeRequestFilterAccountsFilterMemcmp, subscribe_update::UpdateOneof,
};
use yellowstone_grpc_proto::prelude::subscribe_request_filter_accounts_filter::Filter;
use yellowstone_grpc_proto::prelude::subscribe_request_filter_accounts_filter_memcmp as memcmp_mod;

fn encode_public_key(pubkey_bytes: &[u8]) -> String {
    bs58::encode(pubkey_bytes).into_string()
}

fn fetch_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";
const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let db_connection_string ="postgresql://postgres:GFAuAEStvMvsTQHB@db.zuopvzqlayoueiueechw.supabase.co:5432/postgres".to_string();

    let connection_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_connection_string)
        .await
        .expect("Failed to establish database connection");

    let data_store = Store::new(connection_pool);

    let monitored_wallets = vec![
        "EdkpQKWMZhozxQk5UW6BsQG2zkXanE5fDutdjWK2eKop".to_string()
    ];
    println!("Tracking wallet addresses: {:?}", monitored_wallets);

    let blockchain_listener = tokio::spawn(async move {
        let tls_configuration = ClientTlsConfig::new().with_native_roots();

        if let Ok(mut grpc_client) = GeyserGrpcClient::build_from_shared(
            "https://solana-yellowstone-grpc.publicnode.com:443".to_string(),
        )
        .unwrap()
        .keep_alive_while_idle(true)
        .tls_config(tls_configuration)
        .unwrap()
        .connect()
        .await
        {
            let mut subscription_filters = HashMap::new();
            
            // Native SOL accounts - direct wallet monitoring
            subscription_filters.insert(
                "native_sol_wallets".to_string(),
                SubscribeRequestFilterAccounts {
                    owner: vec![],
                    account: monitored_wallets.clone(),
                    filters: vec![],
                    ..Default::default()
                }
            );
            
            for (idx, wallet_addr) in monitored_wallets.iter().enumerate() {
                // SPL token program v1 - filter by owner field at byte offset 32
                subscription_filters.insert(
                    format!("spl_token_v1_wallet_{}", idx),
                    SubscribeRequestFilterAccounts {
                        owner: vec![SPL_TOKEN_PROGRAM.to_string()],
                        account: vec![],
                        filters: vec![
                            SubscribeRequestFilterAccountsFilter {
                                filter: Some(Filter::Datasize(165)),
                            },
                            SubscribeRequestFilterAccountsFilter {
                                filter: Some(Filter::Memcmp(
                                    SubscribeRequestFilterAccountsFilterMemcmp {
                                        offset: 32,
                                        data: Some(memcmp_mod::Data::Base58(wallet_addr.clone())),
                                    },
                                )),
                            },
                        ],
                        ..Default::default()
                    }
                );
                
                // SPL token 2022 program - filter by owner field at byte offset 32
                subscription_filters.insert(
                    format!("spl_token_2022_wallet_{}", idx),
                    SubscribeRequestFilterAccounts {
                        owner: vec![SPL_TOKEN_2022_PROGRAM.to_string()],
                        account: vec![],
                        filters: vec![
                            SubscribeRequestFilterAccountsFilter {
                                filter: Some(Filter::Memcmp(
                                    SubscribeRequestFilterAccountsFilterMemcmp {
                                        offset: 32,
                                        data: Some(memcmp_mod::Data::Base58(wallet_addr.clone())),
                                    },
                                )),
                            },
                        ],
                        ..Default::default()
                    }
                );
            }

            println!("\nBlockchain indexer is now active");
            println!("Monitoring {} wallet(s): {:?}", monitored_wallets.len(), monitored_wallets);
            println!("Configured {} subscription filter(s):", subscription_filters.len());
            for filter_name in subscription_filters.keys() {
                println!("  - {}", filter_name);
            }

            let subscription_config = SubscribeRequest {
                accounts: subscription_filters,
                ..Default::default()
            };

            let (_sender, mut update_stream) = grpc_client
                .subscribe_with_request(Some(subscription_config))
                .await
                .expect("Failed to subscribe to account updates");

            loop {
                let stream_message = update_stream.next().await.unwrap();
                match stream_message {
                    Ok(msg) => {
                        if let Some(update_data) = msg.update_oneof {
                            match update_data {
                                UpdateOneof::Account(acct_update) => {
                                    println!("Received account update (slot: {})", acct_update.slot);
                                    
                                    let wallet_pubkey;
                                    let token_mint;
                                    let token_amount;
                                    let event_time = fetch_unix_timestamp();
                                    let mut tx_signature: Option<String> = None;
                                    let mut native_lamports = 0;

                                    if let Some(acct_info) = acct_update.account {
                                        println!("🔍 Account data size: {}, program owner: {}", 
                                            acct_info.data.len(), 
                                            encode_public_key(&acct_info.owner));
                                        
                                        if acct_info.data.len() >= 165 {
                                            println!("Parsing SPL token account data");
                                            token_mint =
                                                bs58::encode(&acct_info.data[0..32]).into_string();
                                            let amount_slice = &acct_info.data[64..72]; // Token amount is at byte offset 64
                                            token_amount = u64::from_le_bytes(
                                                amount_slice.try_into().unwrap(),
                                            );
                                            wallet_pubkey = Pubkey::try_from(&acct_info.data[32..64])
                                                .unwrap()
                                                .to_string();
                                        } else {
                                            println!("Parsing native SOL account data");
                                            // let program_owner = encode_public_key(&acct_info.owner);
                                            wallet_pubkey = encode_public_key(&acct_info.pubkey);
                                            token_mint = String::from(NATIVE_SOL_MINT);
                                            token_amount = acct_info.lamports;
                                            native_lamports = acct_info.lamports;

                                            if let Some(txn_sig) = acct_info.txn_signature {
                                                tx_signature = Some(
                                                    bs58::encode(&txn_sig).into_string(),
                                                );
                                            }
                                        }

                                        let blockchain_event = BlockchainEvent {
                                            wallet_pubkey: wallet_pubkey.clone(),
                                            token_amount: token_amount,
                                            native_lamports: native_lamports.clone(),
                                            token_mint: token_mint.clone(),
                                            event_time: event_time.clone(),
                                            tx_signature: tx_signature.clone(),
                                        };
                                        println!(
                                            "\n---------\nParsed Blockchain Event: {:?}\n---------\n",
                                            blockchain_event
                                        );

                                        if let Err(e) =
                                            handle_blockchain_event(&data_store, blockchain_event).await
                                        {
                                            println!("Failed to handle blockchain event: {}", e);
                                        }
                                    }
                                }
                                _other => {}
                            }
                        }
                    }
                    Err(e) => {
                        println!("Unable to parse stream message");
                        println!("Error: {:?}", e);
                    }
                }
            }
        }
    });

    blockchain_listener.await.unwrap();
    Ok(())
}
