use candid::CandidType;
use candid::{Nat, Principal};

use evm_rpc_canister_types::{EvmRpcCanister, RpcApi};

use evm_rpc_canister_types::MultiGetTransactionReceiptResult;

use ic_cdk::export_candid;

use serde::{Deserialize, Serialize};

use std::time::Duration;

mod chain_service;
mod helper;
mod key_pair;
mod send_eth;
mod verify_txn;

use crate::chain_service::ChainService;
pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

pub struct PublicKeyReply {
    pub canister_principal: String,
    pub public_key_hex: String,
    pub ethereum_address: String,
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct PriceResponse {
    ethereum: Currency,
    arbitrum: Currency,
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct Currency {
    usd: f64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LogDetails {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub src_chain_id: u64,
    pub txn_hash: String,
    pub dest_chain_id: u64,
}

#[ic_cdk::update]
pub async fn get_logs() -> String {
    let chain_service = ChainService::new("7hfb6-caaaa-aaaar-qadga-cai".to_string());
    chain_service.start_monitoring(Duration::from_secs(10));

    "Monitoring started".to_string()
}
