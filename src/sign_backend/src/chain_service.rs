
use candid::{CandidType, Deserialize, Nat};
use ic_cdk::api::call::{call, call_with_payment128};
use candid::Principal; // Import for Principal
use std::cell::RefCell;
use std::io::{self, Write};
use candid::Encode;
use ic_cdk::api::time;
use ic_cdk_timers::TimerId;
use std::time::Duration;
use std::rc::Rc;

use evm_rpc_canister_types::{
    BlockTag, EvmRpcCanister, GetLogsArgs, GetLogsResult, HttpOutcallError, MultiGetBlockByNumberResult, MultiGetLogsResult, RejectionCode, RpcApi, RpcError, RpcServices, EVM_RPC
};

pub struct ChainService {
    canister_id: String,
    evm_rpc: EvmRpcCanister,
    last_checked_time: RefCell<u64>,
    timer_id: RefCell<Option<TimerId>>,
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


impl ChainService {
    pub fn new(canister_id: String) -> Self {
        let principal = Principal::from_text("7hfb6-caaaa-aaaar-qadga-cai").unwrap();
        let evm_rpc = EvmRpcCanister(principal);
        let last_checked_time = RefCell::new(time() / 1_000_000);
        let timer_id = RefCell::new(None);

        ChainService {
            canister_id,
            evm_rpc,
            last_checked_time,
            timer_id,
        }
    }

    pub async fn fetch_logs(&self, from_block: u64, to_block: u64, address: Option<String>) -> Result<Vec<String>, String> {
        let rpc_providers = RpcServices::Custom {
            chainId: 97,
            services: vec![RpcApi {
                url: "https://bsc-testnet-rpc.publicnode.com".to_string(),
                headers: None,
            }],
        };

        let get_logs_args = GetLogsArgs {
            fromBlock: Some(BlockTag::Number(Nat::from(from_block))),
            toBlock: Some(BlockTag::Number(Nat::from(to_block))),
            addresses: address
                .into_iter()
                .collect(),
            topics: None,
        };

        let cycles = 10_000_000_000;
        let (result,) = self.evm_rpc
            .eth_get_logs(rpc_providers, None, get_logs_args, cycles)
            .await
            .expect("Call failed");

        match result {
            MultiGetLogsResult::Consistent(r) => match r {
                GetLogsResult::Ok(block) => {
                    let log_strings: Vec<String> = block.into_iter().map(|log_entry| {
                        // Extracting from and to addresses from topics
                        let from_address = log_entry.topics.get(1)
                        .map(|topic| Self::convert_address(&format!("{:?}", topic).trim_matches('"')))
                        .unwrap_or_else(|| "N/A".to_string());
                    
                    let to_address = log_entry.topics.get(2)
                        .map(|topic| Self::convert_address(&format!("{:?}", topic).trim_matches('"')))
                        .unwrap_or_else(|| "N/A".to_string());
                    

                        let transaction_hash = log_entry.transactionHash.map_or("N/A".to_string(), |hash| format!("{:?}", hash));
                        let block_number = log_entry.blockNumber.map_or("N/A".to_string(), |block| format!("{:?}", block));
                        let data = log_entry.data;

                        // Parsing the amount, src_chain_id, and dest_chain_id from data
                        let amount = Self::extract_amount(&data);
                        let src_chain_id = Self::extract_src_chain_id(&data);
                        let dest_chain_id = Self::extract_dest_chain_id(&data);

                        format!(
                            "From: {}, To: {}, TxHash: {}, Block: {}, Amount: {}, Src Chain ID: {}, Dest Chain ID: {}, Data: {}",
                            from_address, to_address, transaction_hash, block_number, amount, src_chain_id, dest_chain_id, data
                        )

                        


                    }).collect();
                    Ok(log_strings)
                },
                GetLogsResult::Err(err) => Err(format!("{:?}", err)),
            },
            MultiGetLogsResult::Inconsistent(_) => {
                Err("RPC providers gave inconsistent results".to_string())
            }
        }
   
    }

    fn convert_address(address: &str) -> String {
        // Remove the "0x" prefix and leading zeros
        let stripped_address = address.trim_start_matches("0x")
                                       .strip_prefix("000000000000000000000000")
                                       .unwrap_or(address.trim_start_matches("0x"));
    
        // Ensure it is 40 characters long (20 bytes)
        let padded_address = format!("{:0>40}", stripped_address);
    
        // Convert to mixed-case for Ethereum address format
        let mixed_case_address = format!("0x{}", padded_address);
    
        mixed_case_address
    }
    
    fn extract_amount(data: &str) -> u64 {
        // Logic to extract amount from the data
        // Assuming data is a hex string that contains the amount at a specific position
        // For example, if amount is at positions 66-130
        if data.len() >= 132 {
            let hex_amount = &data[66..130]; // Extracting amount
            return u64::from_str_radix(hex_amount, 16).unwrap_or(0); // Convert hex to decimal
        }
        0 // Return 0 if data length is insufficient
    }
    
    fn extract_src_chain_id(data: &str) -> u64 {
        // Logic to extract src_chain_id from the data
        // Assuming src_chain_id is at positions 130-194
        if data.len() >= 198 {
            let hex_src_chain_id = &data[130..194]; // Extracting src_chain_id
            return u64::from_str_radix(hex_src_chain_id, 16).unwrap_or(0); // Convert hex to decimal
        }
        0 // Return 0 if data length is insufficient
    }
    
    fn extract_dest_chain_id(data: &str) -> u64 {
        // Logic to extract dest_chain_id from the data
        // Assuming dest_chain_id is at positions 194-258
        if data.len() >= 258 {
            let hex_dest_chain_id = &data[194..258]; // Extracting dest_chain_id
            return u64::from_str_radix(hex_dest_chain_id, 16).unwrap_or(0); // Convert hex to decimal
        }
        0 // Return 0 if data length is insufficient
    }

    

    pub fn start_monitoring(&self, interval: Duration) {
        let self_clone = Rc::new(self.clone());

        let timer_id = ic_cdk_timers::set_timer_interval(interval, move || {
            let self_clone = Rc::clone(&self_clone);
            let current_time = time() / 1_000_000;
            if *self_clone.last_checked_time.borrow() < current_time {
                ic_cdk::spawn(async move {
                    self_clone.fetch_logs_and_update_time().await;
                });
            }
        });

        *self.timer_id.borrow_mut() = Some(timer_id);
    }

    async fn fetch_logs_and_update_time(&self) {
        match self.fetch_logs(44438645, 44438945, Some("0xD21eEBE7DB21c37eD6A86DA311ec8EA1E9d6985b".to_string())).await {
            Ok(logs) => {
                if !logs.is_empty() {
                    *self.last_checked_time.borrow_mut() = time() / 1_000_000;
                    for log in logs {
                        ic_cdk::println!("Log: {}", log);
                    }
                }
            },
            Err(e) => {
                ic_cdk::println!("Error during logs extraction: {}", e);
            }
        }
    }

    fn clone(&self) -> Self {
        ChainService {
            canister_id: self.canister_id.clone(),
            evm_rpc: self.evm_rpc.clone(),
            last_checked_time: RefCell::new(*self.last_checked_time.borrow()),
            timer_id: RefCell::new(*self.timer_id.borrow()),
        }
    }
}

