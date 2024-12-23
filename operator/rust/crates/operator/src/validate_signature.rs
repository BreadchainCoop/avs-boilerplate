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

fn read_private_keys() -> Result<Vec<String>> {
    let home = env::var("HOME").expect("HOME environment variable not set");
    let mut keys = Vec::new();
    
    for i in 1..=3 {
        let key_path = format!("{}/.nodes/operator{}", home, i);
        let key = std::fs::read_to_string(key_path)?;
        keys.push(key.trim().to_string());
    }
    
    Ok(keys)
}
static KEYS: Lazy<Vec<String>> = Lazy::new(|| read_private_keys().expect("failed to read private keys"));

async fn validate_signature(
    message: String,
) -> Result<()> {
    let pr = get_signer(&KEYS[0], ANVIL_RPC_URL);
    
    let mut operators: Vec<DynSolValue> = Vec::new();
    let mut signatures: Vec<DynSolValue> = Vec::new();
    
    let m_hash = eip191_hash_message(keccak256(message.abi_encode_packed()));
    
    for key in KEYS.iter() {
        let signer = PrivateKeySigner::from_str(key)?;
        operators.push(DynSolValue::Address(signer.address()));
        signatures.push(DynSolValue::Bytes(signer.sign_hash_sync(&m_hash)?.into()));
    }
    
    let current_block = U256::from(get_provider(ANVIL_RPC_URL).get_block_number().await?);
    let signature_data = DynSolValue::Tuple(vec![
        DynSolValue::Array(operators),
        DynSolValue::Array(signatures),
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
