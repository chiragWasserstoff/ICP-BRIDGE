use crate::helper::get_network_config;
use candid::CandidType;
use candid::Principal;
use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};

use ic_cdk::id;

use bs58;
use k256::PublicKey;
use sha3::Digest;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::sync::Mutex;

type CanisterId = Principal;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct PublicKeyReply {
    pub public_key_hex: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "bip340secp256k1")]
    Bip340Secp256k1,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
struct ManagementCanisterSchnorrPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ManagementCanisterSchnorrPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

pub struct PublicKeyStore {
    pub public_key_hex: String,
}
// Create a static instance of PublicKeyStore using lazy_static
lazy_static! {
    static ref PUBLIC_KEY_STORE: Mutex<Option<PublicKeyStore>> = Mutex::new(None);
}

impl PublicKeyStore {
    // Function to store the public key
    pub fn store(public_key_hex: String) {
        let mut store = PUBLIC_KEY_STORE.lock().unwrap();
        *store = Some(PublicKeyStore { public_key_hex });
    }

    // Function to retrieve the stored public key (returns an Option)
    pub fn get() -> Option<String> {
        let store = PUBLIC_KEY_STORE.lock().unwrap();
        store.as_ref().map(|s| s.public_key_hex.clone())
    }
}

#[ic_cdk::update]
pub async fn generate_key_pair() -> Result<String, String> {
    let (_, ecdsa_key) = get_network_config();

    let canister_principal = id();
    let canister_id_blob = ic_cdk::id().as_slice().to_vec();

    let request = EcdsaPublicKeyArgument {
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: ecdsa_key.to_string(),
        },
        ..Default::default()
    };

    let (response,) = ecdsa_public_key(request)
        .await
        .map_err(|e| format!("ecdsa_public_key failed {:?}", e))?;

    ic_cdk::println!("response , {:?}", response);

    // Convert the public key bytes to an Ethereum address
    let public_key_hex = hex::encode(&response.public_key);
    ic_cdk::println!("stored public_key_hex: {:?}", public_key_hex);

    PublicKeyStore::store(public_key_hex.clone()); // Store the public key

    let ethereum_address = pubkey_bytes_to_address(&response.public_key);
    ic_cdk::println!("Public key: {}", public_key_hex);
    ic_cdk::println!(
        "Ethereum address: {} ,canister_principal {}",
        ethereum_address,
        canister_principal
    );

    // Return the Ethereum address
    Ok(ethereum_address)
}

fn pubkey_bytes_to_address(pubkey_bytes: &[u8]) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let key =
        PublicKey::from_sec1_bytes(pubkey_bytes).expect("failed to parse the public key as SEC1");
    let point = key.to_encoded_point(false);
    let point_bytes = point.as_bytes();
    assert_eq!(point_bytes[0], 0x04);

    let hash = Keccak256::digest(&point_bytes[1..]);

    let address = Address::from_slice(&hash[12..32]);
    ethers_core::utils::to_checksum(&address.into(), None)
}

#[ic_cdk::update]
async fn generate_keypair_solana() -> Result<String, String> {
    let request = ManagementCanisterSchnorrPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: String::from("dfx_test_key"),
        },
    };

    let (res,): (ManagementCanisterSchnorrPublicKeyReply,) = ic_cdk::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (request,),
    )
    .await // Add the await keyword
    .map_err(|e| format!("schnorr_public_key failed {}", e.1))?;

    // Generate or obtain the private key

    ic_cdk::println!("res {:?}", res);
    let public_key_bytes = res.public_key.to_vec();

    if public_key_bytes.len() != 32 {
        return Err("Invalid public key length; expected 32 bytes".to_string());
    }

    // Convert the public key to a Solana address (Base58 encoding)
    // let solana_address = encode_base58(&public_key_bytes);
    let solana_address = bs58::encode(public_key_bytes).into_string();
    // let pubkey = Pubkey::new(&public_key_bytes);
    ic_cdk::println!("Solana Address: {}", solana_address);

    Ok(solana_address)
}
