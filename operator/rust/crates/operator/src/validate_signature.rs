#![allow(missing_docs)]
use alloy::dyn_abi::DynSolValue;
use alloy::{
    primitives::{eip191_hash_message, keccak256, U256},
    providers::Provider,
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::SolValue,
};
use dotenv::dotenv;

use eigen_logging::{get_logger, init_logger, log_level::LogLevel};
use eigen_utils::{get_provider, get_signer};
use eyre::Result;
use hello_world_utils::ecdsastakeregistry::ECDSAStakeRegistry;
use hello_world_utils::parse_stake_registry_address;
use once_cell::sync::Lazy;
use std::{env, str::FromStr};

pub const ANVIL_RPC_URL: &str = "http://ethereum:8545";

static KEY: Lazy<String> =
    Lazy::new(|| env::var("PRIVATE_KEY").expect("failed to retrieve private key"));

async fn validate_signature(
    message: String,
) -> Result<()> {
    let pr = get_signer(&KEY.clone(), ANVIL_RPC_URL);
    let signer = PrivateKeySigner::from_str(&KEY.clone())?;
    let m_hash = eip191_hash_message(keccak256(message.abi_encode_packed()));
    let operators: Vec<DynSolValue> = vec![DynSolValue::Address(signer.address())];
    let signature: Vec<DynSolValue> =
        vec![DynSolValue::Bytes(signer.sign_hash_sync(&m_hash)?.into())];
    let current_block = U256::from(get_provider(ANVIL_RPC_URL).get_block_number().await?);
    let signature_data = DynSolValue::Tuple(vec![
        DynSolValue::Array(operators.clone()),
        DynSolValue::Array(signature.clone()),
        DynSolValue::Uint(current_block, 32),
    ])
    .abi_encode_params();
    let stake_registry_address = parse_stake_registry_address("contracts/deployments/hello-world/17000.json")?;
    let ecdsa_registry = ECDSAStakeRegistry::new(stake_registry_address, &pr);
    let tx = ecdsa_registry.isValidSignature(m_hash, signature_data.into()).gas(500000).send().await?.get_receipt().await?.transaction_hash;
    get_logger().info(&format!("Signature verification completed with tx hash {}", tx), "");
    Ok(())
}


#[tokio::main]
pub async fn main() {
    dotenv().ok();
    init_logger(LogLevel::Info);
    if let Err(e) = validate_signature("Hello, World!".to_string()).await {
        eprintln!("Failed to validate signature: {:?}", e);
        return;
    }
}
