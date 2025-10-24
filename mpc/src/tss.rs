#![allow(non_snake_case)]

use crate::error::Error;
use crate::serialization::{
    AggMessage1, Error as DeserializationError, PartialSignature, SecretAggStepOne,
};
use anyhow;
use base64;
use base64::Engine;
use curv::elliptic::curves::{Ed25519, Point, Scalar};
use multi_party_eddsa::protocols::ExpandedKeyPair;
use multi_party_eddsa::protocols::musig2::{self, PrivatePartialNonces, PublicPartialNonces};
use serde::{Deserialize, Serialize};
use serde_json;
use solana_sdk::signature::{Keypair, Signature, Signer, SignerError};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::Message,
    native_token,
    pubkey::Pubkey,
    system_instruction,
    transaction::Transaction,
    transaction::VersionedTransaction,
};
use std::str::FromStr;

const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn derive_associated_token_address(
    owner_wallet: &Pubkey,
    mint_address: &Pubkey,
    program_id: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            &owner_wallet.to_bytes(),
            &program_id.to_bytes(),
            &mint_address.to_bytes(),
        ],
        &spl_associated_token_account::id(),
    )
    .0
}

fn build_create_ata_instruction(
    funder: &Pubkey,
    owner_wallet: &Pubkey,
    mint_address: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let derived_ata = derive_associated_token_address(
        owner_wallet,
        mint_address,
        program_id,
    );

    Instruction {
        program_id: spl_associated_token_account::id(),
        accounts: vec![
            AccountMeta::new(*funder, true),
            AccountMeta::new(derived_ata, false),
            AccountMeta::new_readonly(*owner_wallet, false),
            AccountMeta::new_readonly(*mint_address, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(*program_id, false),
        ],
        data: vec![],
    }
}

async fn build_transfer_instruction(
    program_id: &Pubkey,
    from_account: &Pubkey,
    to_account: &Pubkey,
    authority: &Pubkey,
    additional_signers: &[&Pubkey],
    transfer_amount: u64,
    token_mint: &Pubkey,
) -> Result<Instruction, anyhow::Error> {
    let token_2022 = Pubkey::from_str(SPL_TOKEN_2022_PROGRAM_ID)?;

    if *program_id == token_2022 {
        println!("using transfer_checked for Token Extensions (2022)");

        let decimal_precision = fetch_mint_decimal_places(token_mint).await?;

        let instruction_data = {
            let mut instruction_data = vec![12u8];
            instruction_data.extend_from_slice(&transfer_amount.to_le_bytes());
            instruction_data.push(decimal_precision);
            instruction_data
        };

        let mut account_metas = vec![
            AccountMeta::new(*from_account, false),
            AccountMeta::new_readonly(*token_mint, false),
            AccountMeta::new(*to_account, false),
            AccountMeta::new_readonly(*authority, additional_signers.is_empty()),
        ];

        for signer_key in additional_signers.iter() {
            account_metas.push(AccountMeta::new_readonly(**signer_key, true));
        }

        Ok(Instruction {
            program_id: *program_id,
            accounts: account_metas,
            data: instruction_data,
        })
    } else {
        println!("using regular transfer for Token Program (legacy)");

        let instruction_data = {
            let mut instruction_data = vec![3u8];
            instruction_data.extend_from_slice(&transfer_amount.to_le_bytes());
            instruction_data
        };

        let mut account_metas = vec![
            AccountMeta::new(*from_account, false),
            AccountMeta::new(*to_account, false),
            AccountMeta::new_readonly(*authority, additional_signers.is_empty()),
        ];

        for signer_key in additional_signers.iter() {
            account_metas.push(AccountMeta::new_readonly(**signer_key, true));
        }

        Ok(Instruction {
            program_id: *program_id,
            accounts: account_metas,
            data: instruction_data,
        })
    }
}

struct PartialSigner {
    signer_private_nonce: PrivatePartialNonces,
    signer_public_nonce: PublicPartialNonces,
    other_nonces: Vec<[Point<Ed25519>; 2]>,
    extended_kepair: ExpandedKeyPair,
    aggregated_pubkey: musig2::PublicKeyAgg,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExternalTokenMetadata {
    address: String,
    decimals: i64,
    name: String,
    symbol: String,
    #[serde(rename = "logoURI")]
    logo_uri: Option<String>,
}

pub fn key_agg(keys: Vec<Pubkey>, key: Option<Pubkey>) -> Result<musig2::PublicKeyAgg, Error> {
    let convert_keys = |k: Pubkey| {
        Point::from_bytes(&k.to_bytes()).map_err(|e| Error::DeserializationFailed {
            error: DeserializationError::InvalidPoint(e),
            field_name: "keys",
        })
    };
    let keys: Vec<_> = keys
        .into_iter()
        .map(convert_keys)
        .collect::<Result<_, _>>()?;
    let key = key
        .map(convert_keys)
        .unwrap_or_else(|| Ok(keys[0].clone()))?;
    musig2::PublicKeyAgg::key_aggregation_n(keys, &key).ok_or(Error::KeyPairIsNotInKeys)
}

pub fn step_one(keypair: Keypair) -> (AggMessage1, SecretAggStepOne) {
    let extended_kepair = ExpandedKeyPair::create_from_private_key(keypair.secret().to_bytes());
    let (private_nonces, public_nonces) = musig2::generate_partial_nonces(&extended_kepair, None);

    (
        AggMessage1 {
            sender: keypair.pubkey(),
            public_nonces: public_nonces.clone(),
        },
        SecretAggStepOne {
            private_nonces,
            public_nonces,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn step_two_send_sol_transaction(
    keypair: Keypair,
    amount: f64,
    to: Pubkey,
    memo: Option<String>,
    recent_block_hash: Hash,
    keys: Vec<Pubkey>,
    first_messages: Vec<AggMessage1>,
    secret_state: SecretAggStepOne,
) -> Result<PartialSignature, Error> {
    let other_nonces: Vec<_> = first_messages
        .into_iter()
        .map(|msg1| msg1.public_nonces.R)
        .collect();

    let aggkey = key_agg(keys, Some(keypair.pubkey()))?;
    let aggpubkey = Pubkey::new(&*aggkey.agg_public_key.to_bytes(true));
    let extended_kepair = ExpandedKeyPair::create_from_private_key(keypair.secret().to_bytes());

    let mut tx = create_unsigned_transaction(amount, &to, memo, &aggpubkey);

    let signer = PartialSigner {
        signer_private_nonce: secret_state.private_nonces,
        signer_public_nonce: secret_state.public_nonces,
        other_nonces,
        extended_kepair,
        aggregated_pubkey: aggkey,
    };

    tx.sign(&[&signer], recent_block_hash);
    let sig = tx.signatures[0];
    Ok(PartialSignature(sig))
}

#[allow(clippy::too_many_arguments)]
pub async fn step_two_send_token_transaction(
    keypair: Keypair,
    amount: f64,
    to: Pubkey,
    mint: Pubkey,
    memo: Option<String>,
    recent_block_hash: Hash,
    keys: Vec<Pubkey>,
    first_messages: Vec<AggMessage1>,
    secret_state: SecretAggStepOne,
) -> Result<PartialSignature, Error> {
    let other_nonces: Vec<_> = first_messages
        .into_iter()
        .map(|msg1| msg1.public_nonces.R)
        .collect();

    let aggkey = key_agg(keys, Some(keypair.pubkey()))?;
    let aggpubkey = Pubkey::new(&*aggkey.agg_public_key.to_bytes(true));
    let extended_kepair = ExpandedKeyPair::create_from_private_key(keypair.secret().to_bytes());

    let mut tx = create_unsigned_token_transaction(amount, &to, &mint, memo, &aggpubkey)
        .await
        .map_err(|_| Error::InvalidSignature)?;

    let signer = PartialSigner {
        signer_private_nonce: secret_state.private_nonces,
        signer_public_nonce: secret_state.public_nonces,
        other_nonces,
        extended_kepair,
        aggregated_pubkey: aggkey,
    };

    tx.sign(&[&signer], recent_block_hash);
    let sig = tx.signatures[0];
    Ok(PartialSignature(sig))
}

pub fn step_two_swap_transaction(
    keypair: Keypair,
    swap_transaction: String,
    _memo: Option<String>,
    recent_block_hash: Hash,
    keys: Vec<Pubkey>,
    first_messages: Vec<AggMessage1>,
    secret_state: SecretAggStepOne,
) -> Result<PartialSignature, Error> {
    let other_nonces: Vec<_> = first_messages
        .into_iter()
        .map(|msg1| msg1.public_nonces.R)
        .collect();

    let aggkey = key_agg(keys, Some(keypair.pubkey()))?;
    let aggpubkey = Pubkey::new(&*aggkey.agg_public_key.to_bytes(true));
    println!("Aggregated public key: {}", aggpubkey);
    let extended_kepair = ExpandedKeyPair::create_from_private_key(keypair.secret().to_bytes());

    let decoded_tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(&swap_transaction)
        .map_err(|e| {
            println!("ERROR: Failed to decode base64 transaction: {:?}", e);
            Error::InvalidSignature
        })?;

    let parsed_versioned_tx = match bincode::deserialize::<VersionedTransaction>(&decoded_tx_bytes) {
        Ok(parsed_versioned_tx) => {
            println!("successfully deserialized as versioned transaction");
            parsed_versioned_tx
        }
        Err(_e1) => {
            println!("trying legacy transaction deserialization...");
            match bincode::deserialize::<Transaction>(&decoded_tx_bytes) {
                Ok(mut parsed_legacy_tx) => {
                    println!("successfully deserialized as legacy Transaction");

                    println!(
                        "transaction signer: {:?}",
                        parsed_legacy_tx.message.account_keys.get(0)
                    );
                    if let Some(current_signer) = parsed_legacy_tx.message.account_keys.get(0) {
                        if *current_signer != aggpubkey {
                            parsed_legacy_tx.message.account_keys[0] = aggpubkey;
                        }
                    } else {
                        println!("warning: legacy transaction has no account keys");
                        return Err(Error::InvalidSignature);
                    }

                    let signer = PartialSigner {
                        signer_private_nonce: secret_state.private_nonces,
                        signer_public_nonce: secret_state.public_nonces,
                        other_nonces,
                        extended_kepair,
                        aggregated_pubkey: aggkey,
                    };

                    println!("Signing legacy transaction with PartialSigner...");
                    parsed_legacy_tx.sign(&[&signer], recent_block_hash);
                    let sig = parsed_legacy_tx.signatures[0];
                    println!("partial signature created: {}", sig);
                    return Ok(PartialSignature(sig));
                }
                Err(_e2) => {
                    return Err(Error::InvalidSignature);
                }
            }
        }
    };

    println!("creating partial signer for versioned transaction...");
    let signer = PartialSigner {
        signer_private_nonce: secret_state.private_nonces,
        signer_public_nonce: secret_state.public_nonces,
        other_nonces,
        extended_kepair,
        aggregated_pubkey: aggkey,
    };

    let mut modified_versioned_tx = parsed_versioned_tx.clone();

    let mut tx_message = modified_versioned_tx.message.clone();
    match &mut tx_message {
        solana_sdk::message::VersionedMessage::Legacy(legacy_msg) => {
            legacy_msg.recent_blockhash = recent_block_hash;
        }
        solana_sdk::message::VersionedMessage::V0(v0_msg) => {
            v0_msg.recent_blockhash = recent_block_hash;
        }
    }

    modified_versioned_tx.message = tx_message;

    println!("signing versioned transaction with partial signer...");

    let serialized_message = modified_versioned_tx.message.serialize();
    let partial_sig = signer
        .try_sign_message(&serialized_message)
        .map_err(|_| Error::InvalidSignature)?;

    println!(
        "partial signature created for versioned transaction: {}",
        partial_sig
    );

    println!("step_two_swap done");
    Ok(PartialSignature(partial_sig))
}

pub fn sign_swap_transaction(
    tx_b64: String,
    recent_block_hash: Hash,
    keys: Vec<Pubkey>,
    signatures: Vec<PartialSignature>,
) -> Result<VersionedTransaction, Error> {
    let aggkey = key_agg(keys, None)?;
    let aggpubkey = Pubkey::new(&*aggkey.agg_public_key.to_bytes(true));
    println!("public key: {}", aggpubkey);

    if !signatures[1..]
        .iter()
        .map(|s| &s.0.as_ref()[..32])
        .all(|s| s == &signatures[0].0.as_ref()[..32])
    {
        return Err(Error::MismatchMessages);
    }

    let deserialize_R = |s| {
        Point::from_bytes(s).map_err(|e| Error::DeserializationFailed {
            error: DeserializationError::InvalidPoint(e),
            field_name: "signatures",
        })
    };
    let deserialize_s = |s| {
        Scalar::from_bytes(s).map_err(|e| Error::DeserializationFailed {
            error: DeserializationError::InvalidScalar(e),
            field_name: "signatures",
        })
    };

    let first_sig = musig2::PartialSignature {
        R: deserialize_R(&signatures[0].0.as_ref()[..32])?,
        my_partial_s: deserialize_s(&signatures[0].0.as_ref()[32..])?,
    };

    let partial_sigs: Vec<_> = signatures[1..]
        .iter()
        .map(|s| deserialize_s(&s.0.as_ref()[32..]))
        .collect::<Result<_, _>>()?;

    let aggregated_sig = musig2::aggregate_partial_signatures(&first_sig, &partial_sigs);

    let mut signature_bytes = [0u8; 64];
    let r_component = aggregated_sig.R.to_bytes(true);
    let s_component = aggregated_sig.s.to_bytes();

    signature_bytes[..32].copy_from_slice(&*r_component);
    signature_bytes[32..].copy_from_slice(&s_component);
    let final_sig = Signature::new(&signature_bytes);
    println!("final signature created: {}", final_sig);

    println!("decoding base64 transaction");
    let decoded_tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(&tx_b64)
        .map_err(|e| {
            println!("failed to decode base64 transaction: {:?}", e);
            Error::InvalidSignature
        })?;

    println!("deserializing transaction from bytes");
    let parsed_versioned_tx: VersionedTransaction = match bincode::deserialize::<VersionedTransaction>(
        &decoded_tx_bytes,
    ) {
        Ok(parsed_versioned_tx) => {
            println!("successfully deserialized as versioned transaction");
            parsed_versioned_tx
        }
        Err(_e1) => {
            println!("trying legacy transaction deserialization...");

            match bincode::deserialize::<Transaction>(&decoded_tx_bytes) {
                Ok(parsed_legacy_tx) => {
                    println!(
                        "successfully deserialized as legacy transaction, converting to versioned transaction"
                    );
                    VersionedTransaction::from(parsed_legacy_tx)
                }
                Err(_e2) => {
                    println!("legacy transaction deserialization failed");
                    return Err(Error::InvalidSignature);
                }
            }
        }
    };

    match parsed_versioned_tx.clone().into_legacy_transaction() {
        Some(mut converted_legacy_tx) => {
            println!("converted to Legacy Transaction");
            println!(
                "transaction signer: {:?}",
                converted_legacy_tx.message.account_keys.get(0)
            );

            if let Some(current_signer) = converted_legacy_tx.message.account_keys.get(0) {
                if *current_signer != aggpubkey {
                    converted_legacy_tx.message.account_keys[0] = aggpubkey;
                    println!(
                        "transaction signer updated to: {}",
                        converted_legacy_tx.message.account_keys[0]
                    );
                }
            } else {
                println!("transaction has no account keys");
                return Err(Error::InvalidSignature);
            }

            converted_legacy_tx.message.recent_blockhash = recent_block_hash;
            assert_eq!(converted_legacy_tx.signatures.len(), 1);
            converted_legacy_tx.signatures[0] = final_sig;

            println!("verifying legacy transaction...");
            match converted_legacy_tx.verify() {
                Ok(_) => Ok(VersionedTransaction::from(converted_legacy_tx)),
                Err(e) => {
                    println!("transaction verification failed: {:?}", e);
                    Err(Error::InvalidSignature)
                }
            }
        }
        None => {
            let mut updated_versioned_tx = parsed_versioned_tx.clone();
            updated_versioned_tx.signatures[0] = final_sig;

            let mut tx_message = updated_versioned_tx.message.clone();
            match &mut tx_message {
                solana_sdk::message::VersionedMessage::Legacy(legacy_msg) => {
                    legacy_msg.recent_blockhash = recent_block_hash;
                    if let Some(current_signer) = legacy_msg.account_keys.get_mut(0) {
                        println!("updating signer from {} to {}", current_signer, aggpubkey);
                        *current_signer = aggpubkey;
                    }
                }
                solana_sdk::message::VersionedMessage::V0(v0_msg) => {
                    v0_msg.recent_blockhash = recent_block_hash;
                    if let Some(current_signer) = v0_msg.account_keys.get_mut(0) {
                        println!("original signer: {}", current_signer);
                        println!("updating signer to aggregated pubkey: {}", aggpubkey);
                        *current_signer = aggpubkey;
                    } else {
                        println!("v0 transaction has no account keys to update!");
                        return Err(Error::InvalidSignature);
                    }
                }
            }

            updated_versioned_tx = VersionedTransaction {
                signatures: updated_versioned_tx.signatures,
                message: tx_message,
            };

            Ok(updated_versioned_tx)
        }
    }
}

impl Signer for PartialSigner {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(Pubkey::new(
            &*self.aggregated_pubkey.agg_public_key.to_bytes(true),
        ))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let sig = musig2::partial_sign(
            &self.other_nonces,
            self.signer_private_nonce.clone(),
            self.signer_public_nonce.clone(),
            &self.aggregated_pubkey,
            &self.extended_kepair,
            message,
        );
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&*sig.R.to_bytes(true));
        sig_bytes[32..].copy_from_slice(&sig.my_partial_s.to_bytes());
        Ok(Signature::new(&sig_bytes))
    }

    fn is_interactive(&self) -> bool {
        false
    }
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

pub async fn resolve_token_program_for_mint(mint_address: &Pubkey) -> Result<Pubkey, anyhow::Error> {
    let rpc_endpoint = "https://mainnet.helius-rpc.com/?api-key=d203db1c-5156-4efc-89b9-4546b8680ea8".to_string();

    let http_client = reqwest::Client::new();

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint_address.to_string(),
            {
                "encoding": "base64"
            }
        ]
    });

    let http_response = http_client
        .post(&rpc_endpoint)
        .header("Content-Type", "application/json")
        .json(&rpc_payload)
        .send()
        .await?;

    if !http_response.status().is_success() {
        return Err(anyhow::anyhow!("RPC request failed: {}", http_response.status()));
    }

    let response_json = http_response.json::<serde_json::Value>().await?;

    if let Some(rpc_result) = response_json.get("result") {
        if let Some(account_value) = rpc_result.get("value") {
            if account_value.is_null() {
                return Err(anyhow::anyhow!("Mint address not found"));
            }

            if let Some(program_owner) = account_value.get("owner") {
                if let Some(owner_string) = program_owner.as_str() {
                    let resolved_program = Pubkey::from_str(owner_string)?;

                    let legacy_program = Pubkey::from_str(SPL_TOKEN_PROGRAM_ID)?;
                    let token_2022_program = Pubkey::from_str(SPL_TOKEN_2022_PROGRAM_ID)?;

                    if resolved_program == legacy_program {
                        println!("token program legacy: {}", SPL_TOKEN_PROGRAM_ID);
                        return Ok(legacy_program);
                    } else if resolved_program == token_2022_program {
                        println!("token extensions 2022: {}", SPL_TOKEN_2022_PROGRAM_ID);
                        return Ok(token_2022_program);
                    } else {
                        return Err(anyhow::anyhow!("Unknown token program: {}", owner_string));
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!("Failed to parse RPC response"))
}

async fn fetch_mint_decimal_places(mint_address: &Pubkey) -> Result<u8, anyhow::Error> {
    let rpc_endpoint = "https://mainnet.helius-rpc.com/?api-key=d203db1c-5156-4efc-89b9-4546b8680ea8".to_string();

    println!("Getting mint decimals for: {}", mint_address);

    let http_client = reqwest::Client::new();

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            mint_address.to_string(),
            {
                "encoding": "base64"
            }
        ]
    });

    let http_response = http_client
        .post(&rpc_endpoint)
        .header("Content-Type", "application/json")
        .json(&rpc_payload)
        .send()
        .await?;

    if !http_response.status().is_success() {
        return Err(anyhow::anyhow!("RPC request failed: {}", http_response.status()));
    }

    let response_json = http_response.json::<serde_json::Value>().await?;

    if let Some(rpc_result) = response_json.get("result") {
        if let Some(account_value) = rpc_result.get("value") {
            if account_value.is_null() {
                return Err(anyhow::anyhow!("Mint address not found"));
            }

            if let Some(account_data) = account_value.get("data") {
                if let Some(data_array) = account_data.as_array() {
                    if let Some(encoded_base64) = data_array.get(0).and_then(|v| v.as_str()) {
                        let decoded_bytes = base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            encoded_base64,
                        )?;

                        if decoded_bytes.len() > 44 {
                            let decimal_count = decoded_bytes[44];
                            println!("  Mint decimals: {}", decimal_count);
                            return Ok(decimal_count);
                        }
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to parse mint decimals from RPC response"
    ))
}

pub async fn create_unsigned_token_transaction(
    amount: f64,
    to: &Pubkey,
    mint: &Pubkey,
    memo: Option<String>,
    payer: &Pubkey,
) -> Result<Transaction, anyhow::Error> {
    let resolved_program = resolve_token_program_for_mint(mint).await?;
    println!("  token_program: {}", resolved_program);

    let source_ata = derive_associated_token_address(payer, mint, &resolved_program);
    let destination_ata = derive_associated_token_address(to, mint, &resolved_program);

    println!("  sender_ata: {}", source_ata);
    println!("  receiver_ata: {}", destination_ata);

    let mut transaction_instructions = Vec::new();

    let destination_exists = verify_ata_exists(&destination_ata, &resolved_program).await;
    println!("  Receiver ATA exists: {}", destination_exists);

    if !destination_exists && payer != to {
        let create_destination_ata_ins =
            build_create_ata_instruction(payer, to, mint, &resolved_program);
        transaction_instructions.push(create_destination_ata_ins);
    } else {
        println!("skipping creation");
    }

    let transfer_instruction = match build_transfer_instruction(
        &resolved_program,
        &source_ata,
        &destination_ata,
        payer,
        &[],
        amount as u64,
        mint, // for transfer_checked
    )
    .await
    {
        Ok(built_instruction) => {
            println!("transfer instruction created successfully");
            built_instruction
        }
        Err(e) => {
            println!("error creating transfer instruction: {:?}", e);
            return Err(anyhow::anyhow!(
                "Failed to create transfer instruction: {:?}",
                e
            ));
        }
    };
    transaction_instructions.push(transfer_instruction);

    if let Some(memo) = memo {
        let memo_ins = Instruction {
            program_id: spl_memo::id(),
            accounts: Vec::new(),
            data: memo.into_bytes(),
        };
        transaction_instructions.push(memo_ins);
    }

    let transaction_message = Message::new(&transaction_instructions, Some(payer));
    Ok(Transaction::new_unsigned(transaction_message))
}

pub async fn sign_and_broadcast(
    mint: Option<Pubkey>,
    amount: f64,
    to: Pubkey,
    memo: Option<String>,
    recent_block_hash: Hash,
    keys: Vec<Pubkey>,
    signatures: Vec<PartialSignature>,
) -> Result<Transaction, Error> {
    let aggkey = key_agg(keys, None)?;
    let aggpubkey = Pubkey::new(&*aggkey.agg_public_key.to_bytes(true));

    if !signatures[1..]
        .iter()
        .map(|s| &s.0.as_ref()[..32])
        .all(|s| s == &signatures[0].0.as_ref()[..32])
    {
        return Err(Error::MismatchMessages);
    }
    let deserialize_R = |s| {
        Point::from_bytes(s).map_err(|e| Error::DeserializationFailed {
            error: DeserializationError::InvalidPoint(e),
            field_name: "signatures",
        })
    };
    let deserialize_s = |s| {
        Scalar::from_bytes(s).map_err(|e| Error::DeserializationFailed {
            error: DeserializationError::InvalidScalar(e),
            field_name: "signatures",
        })
    };

    let first_sig = musig2::PartialSignature {
        R: deserialize_R(&signatures[0].0.as_ref()[..32])?,
        my_partial_s: deserialize_s(&signatures[0].0.as_ref()[32..])?,
    };

    let partial_sigs: Vec<_> = signatures[1..]
        .iter()
        .map(|s| deserialize_s(&s.0.as_ref()[32..]))
        .collect::<Result<_, _>>()?;

    let aggregated_sig = musig2::aggregate_partial_signatures(&first_sig, &partial_sigs);

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&*aggregated_sig.R.to_bytes(true));
    signature_bytes[32..].copy_from_slice(&aggregated_sig.s.to_bytes());
    let final_sig = Signature::new(&signature_bytes);

    let mut tx = if let Some(mint) = mint {
        create_unsigned_token_transaction(amount, &to, &mint, memo, &aggpubkey)
            .await
            .map_err(|_| Error::InvalidSignature)?
    } else {
        create_unsigned_transaction(amount, &to, memo, &aggpubkey)
    };

    tx.message.recent_blockhash = recent_block_hash;
    assert_eq!(tx.signatures.len(), 1);
    tx.signatures[0] = final_sig;

    if tx.verify().is_err() {
        return Err(Error::InvalidSignature);
    }
    Ok(tx)
}

async fn verify_ata_exists(ata_pubkey: &Pubkey, expected_program: &Pubkey) -> bool {
    let rpc_endpoint = "https://mainnet.helius-rpc.com/?api-key=d203db1c-5156-4efc-89b9-4546b8680ea8".to_string();

    println!("checking ATA existence");

    let http_client = reqwest::Client::new();

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            ata_pubkey.to_string(),
            {
                "encoding": "base64"
            }
        ]
    });

    match http_client
        .post(&rpc_endpoint)
        .header("Content-Type", "application/json")
        .json(&rpc_payload)
        .send()
        .await
    {
        Ok(http_response) => {
            if let Ok(response_json) = http_response.json::<serde_json::Value>().await {
                if let Some(rpc_result) = response_json.get("result") {
                    if let Some(account_value) = rpc_result.get("value") {
                        if account_value.is_null() {
                            return false;
                        }

                        if let Some(program_owner) = account_value.get("owner") {
                            if let Some(owner_string) = program_owner.as_str() {
                                let matches_expected =
                                    owner_string == expected_program.to_string();
                                return matches_expected;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("Error checking ATA: {}", e);
        }
    }

    false
}
