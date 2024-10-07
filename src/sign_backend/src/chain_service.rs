use candid::Principal; // Import for Principal
use candid::{CandidType, Nat};
use ic_cdk::api::time;
use ic_cdk::post_upgrade;
use ic_cdk::pre_upgrade;
use ic_cdk_timers::TimerId;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::rc::Rc;
use std::time::Duration;

use crate::helper::nat_to_u64;
use crate::verify_txn::verify_trans;
use evm_rpc_canister_types::Block;
use evm_rpc_canister_types::MultiGetBlockByNumberResult::Consistent;


use evm_rpc_canister_types::{
    BlockTag, EvmRpcCanister, GetBlockByNumberResult, GetLogsArgs, GetLogsResult, MultiGetBlockByNumberResult, MultiGetLogsResult, RejectionCode, RpcApi, RpcError, RpcServices, SendRawTransactionResult, EVM_RPC
};

#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct TransactionDetails {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub src_chain_id: u64,
    pub dest_chain_id: u64,
    pub block_number: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug, Serialize)]
pub struct TransactionReleaseDetails {
    pub status: bool,
    pub releasetxn: Option<String>,
}
// 86628868
thread_local! {
    static TRANSACTION_MAP: RefCell<HashMap<String, TransactionDetails>> = RefCell::new(HashMap::new());
}

thread_local! {
    static TRANSACTION_MAP_RELEASE: RefCell<HashMap<String, TransactionReleaseDetails>> = RefCell::new(HashMap::new());
}

thread_local! {
    static BLOCK_NUMBER: RefCell<u64> = RefCell::new(86629822);
}

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
    pub async fn fetch_logs(
        &self,
        from_block: u64,
        to_block: u64,
        address: Option<String>,
    ) -> Result<Vec<String>, String> {
        ic_cdk::println!("fetch_logs.");
        let rpc_providers = RpcServices::Custom {
            chainId: 97,
            services: vec![RpcApi {
                url: "https://sepolia-rollup.arbitrum.io/rpc".to_string(),
                headers: None,
            }],
        };

        let get_logs_args = GetLogsArgs {
            fromBlock: Some(BlockTag::Number(Nat::from(from_block))),
            toBlock: Some(BlockTag::Number(Nat::from(to_block))),
            addresses: address.into_iter().collect(),
            topics: None,
        };

        let cycles = 10_000_000_000;
        let (result,) = self
            .evm_rpc
            .eth_get_logs(rpc_providers, None, get_logs_args, cycles)
            .await
            .expect("Call failed");

        ic_cdk::println!("result ,{:?}", result);

        match result {
            MultiGetLogsResult::Consistent(r) => match r {
                GetLogsResult::Ok(block) => {
                    let mut log_strings: Vec<String> = vec![];

                    let mut userfrom_address = String::new();

                    for log_entry in block {
                        // Extracting from and to addresses from topics
                        let from_address = log_entry
                            .topics
                            .get(1)
                            .map(|topic| {
                                Self::convert_address(&format!("{:?}", topic).trim_matches('"'))
                            })
                            .unwrap_or_else(|| "N/A".to_string());

                        userfrom_address = from_address.clone();

                        let to_address = log_entry
                            .topics
                            .get(2)
                            .map(|topic| {
                                Self::convert_address(&format!("{:?}", topic).trim_matches('"'))
                            })
                            .unwrap_or_else(|| "N/A".to_string());

                        let transaction_hash = log_entry
                            .transactionHash
                            .map_or("N/A".to_string(), |hash| format!("{:?}", hash));
                        let block_number = log_entry
                            .blockNumber
                            .map_or("N/A".to_string(), |block| format!("{:?}", block));
                        let data = log_entry.data;

                        // Parsing the amount, src_chain_id, and dest_chain_id from data
                        let amount = Self::extract_amount(&data);
                        let src_chain_id = Self::extract_src_chain_id(&data);
                        let dest_chain_id = Self::extract_dest_chain_id(&data);

                        // Format log entry string
                        log_strings.push(format!(
                            "From: {}, To: {}, TxHash: {}, Block: {}, Amount: {}, Src Chain ID: {}, Dest Chain ID: {}, Data: {}",
                            from_address.clone(), to_address, transaction_hash, block_number, amount, src_chain_id, dest_chain_id, data
                        ));
                    }

                    ic_cdk::println!("logs loop log_strings {:?}.", log_strings);

                    // Verify transactions for each log
                    for log in &log_strings {
                        let parts: Vec<&str> = log.split(',').collect();
                        if parts.len() >= 7 {
                            ic_cdk::println!("parts length   {:?}.", parts);
                            // Ensure we have enough parts to access all necessary indices
                            let transaction_hash =
                                parts[2].split(": ").nth(1).unwrap_or("N/A").to_string();

                            let block_number_str = parts[3].split(": ").nth(1).unwrap_or("N/A");
                            let block_number = block_number_str
                                .replace("Nat(", "")
                                .replace(")", "")
                                .to_string();

                            let to_address =
                                parts[1].split(": ").nth(1).unwrap_or("N/A").to_string();
                            let amount = parts[4].split(": ").nth(1).unwrap_or("0").to_string();
                            let dest_chain_id =
                                parts[6].split(": ").nth(1).unwrap_or("0").to_string();
                            let src_chain_id =
                                parts[5].split(": ").nth(1).unwrap_or("0").to_string(); // Correctly referencing the src_chain_id

                            // Check if the transaction_hash is present in the TRANSACTION_MAP
                            let already_processed = TRANSACTION_MAP
                                .with_borrow(|map| map.contains_key(&transaction_hash));

                            ic_cdk::println!(
                                "already_processed_working {:?}, transaction_hash {:?} block_number {:?}",
                                already_processed,
                                transaction_hash,
                                block_number
                            );

                            if already_processed {
                                ic_cdk::println!(
                                    "Transaction {} already processed, skipping.",
                                    transaction_hash
                                );
                            } else {
                                // Call verify_trans to check the transaction validity asynchronously
                                let release_status = verify_trans(
                                    transaction_hash.clone(),
                                    to_address.clone(),
                                    amount.clone(),
                                    dest_chain_id.clone(),
                                )
                                .await;

                                ic_cdk::println!("release_stauts {:?}", release_status);

                                match release_status {
                                    Ok(SendRawTransactionResult::Ok(hash)) => {
                                        // Print the transaction hash
                                        ic_cdk::println!("Transaction hash: {:?}", hash);
                                        let transaction_hash_string = format!("{:?}", hash); // or hash.to_string() if applicable

                                        TRANSACTION_MAP_RELEASE.with(|map| {
                                            let mut map = map.borrow_mut();
                                            let transaction_details = TransactionReleaseDetails {
                                                status: true,
                                                releasetxn: Some(transaction_hash_string.clone()), // or Some(hash.clone().to_string()) if you want to store the hash as well
                                            };
                                            map.insert(
                                                transaction_hash.clone(),
                                                transaction_details,
                                            );
                                        });
                                    }
                                    Ok(SendRawTransactionResult::Err(message)) => {
                                        ic_cdk::println!("Transaction failed: {:?}", message);
                                        TRANSACTION_MAP_RELEASE.with(|map| {
                                            let mut map = map.borrow_mut();
                                            let transaction_details = TransactionReleaseDetails {
                                                status: false,
                                                releasetxn: None, // or Some(hash.clone().to_string()) if you want to store the hash as well
                                            };
                                            map.insert(
                                                transaction_hash.clone(),
                                                transaction_details,
                                            );
                                        });
                                    }
                                    Err(e) => {
                                        ic_cdk::println!("Error encountered: {:?}", e);
                                    }
                                }
                                // Insert transaction details into TRANSACTION_MAP
                                TRANSACTION_MAP.with(|map| {
                                    map.borrow_mut().insert(
                                        transaction_hash.clone(),
                                        TransactionDetails {
                                            from: userfrom_address.clone().to_owned(),
                                            to: to_address.clone(),
                                            amount: amount.parse::<u64>().unwrap_or(0),
                                            src_chain_id: src_chain_id.parse::<u64>().unwrap_or(0),
                                            dest_chain_id: dest_chain_id
                                                .parse::<u64>()
                                                .unwrap_or(0),
                                            block_number: block_number.parse::<u64>().unwrap_or(0),
                                        },
                                    );
                                });

                                // Proceed if the transaction is valid
                                let already_processed = TRANSACTION_MAP
                                    .with_borrow(|map| map.contains_key(&transaction_hash));

                                ic_cdk::println!("already_processed {:?}", already_processed);

                                if already_processed {
                                    ic_cdk::println!(
                                        "Transaction {} already processed, skipping.",
                                        transaction_hash
                                    );
                                } else {
                                    // Call verify_trans to check the transaction validity asynchronously
                                    match verify_trans(
                                        transaction_hash.clone(),
                                        to_address.clone(),
                                        amount.clone(),
                                        dest_chain_id.clone(),
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            // Insert the transaction details if verification is successful
                                            TRANSACTION_MAP.with_borrow_mut(|map| {
                                                let log_details = TransactionDetails {
                                                    from: parts
                                                        .get(0)
                                                        .and_then(|p| p.split(": ").nth(1))
                                                        .unwrap_or("N/A")
                                                        .to_string(),
                                                    to: to_address.clone(),
                                                    amount: amount.parse::<u64>().unwrap_or(0),
                                                    src_chain_id: src_chain_id
                                                        .parse::<u64>()
                                                        .unwrap_or(0),
                                                    dest_chain_id: dest_chain_id
                                                        .parse::<u64>()
                                                        .unwrap_or(0),
                                                    block_number: block_number
                                                        .parse::<u64>()
                                                        .unwrap_or(0),
                                                };
                                                map.insert(transaction_hash.clone(), log_details);
                                            });
                                            ic_cdk::println!(
                                                "Transaction {} processed successfully.",
                                                transaction_hash
                                            );
                                        }
                                        Err(e) => {
                                            // Handle the error case
                                            ic_cdk::println!(
                                                "Transaction {} failed verification: {}",
                                                transaction_hash,
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok(log_strings)
                }
                GetLogsResult::Err(err) => Err(format!("{:?}", err)),
            },
            MultiGetLogsResult::Inconsistent(_) => {
                Err("RPC providers gave inconsistent results".to_string())
            }
        }
    }

    fn convert_address(address: &str) -> String {
        // Remove the "0x" prefix and leading zeros
        let stripped_address = address
            .trim_start_matches("0x")
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
        if data.len() >= 132 {
            let hex_amount = &data[66..130]; // Extracting amount
            return u64::from_str_radix(hex_amount, 16).unwrap_or(0); // Convert hex to decimal
        }
        0 // Return 0 if data length is insufficient
    }

    fn extract_src_chain_id(data: &str) -> u64 {
        // Logic to extract src_chain_id from the data
        if data.len() >= 198 {
            let hex_src_chain_id = &data[130..194]; // Extracting src_chain_id
            return u64::from_str_radix(hex_src_chain_id, 16).unwrap_or(0); // Convert hex to decimal
        }
        0 // Return 0 if data length is insufficient
    }

    fn extract_dest_chain_id(data: &str) -> u64 {
        // Logic to extract dest_chain_id from the data
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
        ic_cdk::println!("start_monitoring.");

        let latest_block_number = BLOCK_NUMBER.with(|block_num| *block_num.borrow());

        ic_cdk::println!(
            "Latest block number: {}, {} ",
            latest_block_number,
            latest_block_number + 499
        );
        // let to_block = latest_block_number + 499;
        // Call eth_get_block_by_number and unpack the tuple to get the block result
        let (block_result,) = match EVM_RPC
            .eth_get_block_by_number(
                RpcServices::Custom {
                    chainId: 421614,
                    services: vec![RpcApi {
                        url: "https://arbitrum-sepolia.gateway.tenderly.co".to_string(),
                        headers: None,
                    }],
                },
                None,
                BlockTag::Latest,
                2_000_000_000_u128,
            )
            .await
        {
            Ok(res) => res, // Unpack the tuple (containing `MultiGetBlockByNumberResult`)
            Err(e) => {
                ic_cdk::println!("Failed to get latest block, error: {:?}", e);
                return; // Or handle the error accordingly
            }
        };

        // Now extract the block number from `block_result`
        // let to_block = match block_result.block {
        //     Some(block) => block.number, // Replace 'number' with the correct field name for the block number
        //     None => {
        //         ic_cdk::println!("No block number found in the result.");
        //         return; // Or handle the case where there's no block number
        //     }
        // };
        // Use `to_block` in `fetch_logs`

        ic_cdk::println!("block_result ,{:?}", block_result);

        let to_block = match block_result {
            Consistent(GetBlockByNumberResult::Ok(block)) => block.number,
            Consistent(GetBlockByNumberResult::Err(e)) => {
                ic_cdk::println!("Error retrieving block data: {:?}", e);
                return; // Or handle the error case appropriately
            }
            _ => {
                ic_cdk::println!("Unexpected result type.");
                return; // Handle any other unexpected cases
            }
        };

        let _ = self
            .fetch_logs(
                latest_block_number,
                nat_to_u64(to_block.clone()),
                Some("0xffA175050d2B508Cf7Ac3F78C201d69cDE30Ca03".to_string()),
            )
            .await;

        // let to_block = match EVM_RPC
        //     .eth_get_block_by_number(
        //         RpcServices::Custom {
        //             chainId: 421614,
        //             services: vec![RpcApi {
        //                 url: "https://arbitrum-sepolia.gateway.tenderly.co".to_string(),
        //                 headers: None,
        //             }],
        //         },
        //         None,
        //         BlockTag::Latest,
        //         2_000_000_000_u128,
        //     )
        //     .await
        // {
        //     Ok(block_result) => {
        //         // Extract the block number from the result
        //         if let Some(block) = block_result {
        //             block.number // Replace 'number' with the correct field name that contains the block number
        //         } else {
        //             ic_cdk::println!("No block number found in the result.");
        //             return; // or handle the case accordingly
        //         }
        //     }
        //     Err(e) => {
        //         ic_cdk::println!("Failed to get latest block, error: {:?}", e);
        //         return; // or handle the error accordingly
        //     }
        // };

        let _ = self
            .fetch_logs(
                latest_block_number,
                nat_to_u64(to_block.clone()),
                Some("0xffA175050d2B508Cf7Ac3F78C201d69cDE30Ca03".to_string()),
            )
            .await;

        BLOCK_NUMBER.with(|block_num| {
            *block_num.borrow_mut() = 0; // Resetting to 0 or another default value
        });

        BLOCK_NUMBER.with(|block_num| {
            *block_num.borrow_mut() = nat_to_u64(to_block.clone())
        });

        TRANSACTION_MAP.with(|map| {
                let map = map.borrow();
                for (txn_hash, txn_details) in map.iter() {
                    ic_cdk::println!(
                        "Transaction Hash: {}, From: {}, To: {}, Amount: {}, Src Chain ID: {}, Dest Chain ID: {}, Block Number: {}",
                        txn_hash,
                        txn_details.from,
                        txn_details.to,
                        txn_details.amount,
                        txn_details.src_chain_id,
                        txn_details.dest_chain_id,
                        txn_details.block_number
                    );
                }
            });
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

#[derive(CandidType, Deserialize, Serialize)]
struct StableState {
    transaction_map: HashMap<String, TransactionDetails>,
    transaction_map_release: HashMap<String, TransactionReleaseDetails>,
    block_number: u64,
}

#[pre_upgrade]
fn pre_upgrade() {
    // Save the current state to stable memory
    let transaction_map = TRANSACTION_MAP.with(|data| data.borrow().clone());
    let transaction_map_release = TRANSACTION_MAP_RELEASE.with(|data| data.borrow().clone());
    let block_number = BLOCK_NUMBER.with(|num| *num.borrow());

    let state = StableState {
        transaction_map,
        transaction_map_release,
        block_number,
    };

    ic_cdk::storage::stable_save((state,)).expect("Failed to save stable state");
}

#[post_upgrade]
fn post_upgrade() {
    // Restore the state from stable memory
    match ic_cdk::storage::stable_restore::<(StableState,)>() {
        Ok((state,)) => {
            // Restore the transaction map data
            TRANSACTION_MAP.with(|data| *data.borrow_mut() = state.transaction_map);

            // Restore the transaction map release data
            TRANSACTION_MAP_RELEASE.with(|data| *data.borrow_mut() = state.transaction_map_release);

            BLOCK_NUMBER.with(|num| *num.borrow_mut() = state.block_number);
        }
        Err(e) => {
            ic_cdk::println!("Failed to restore stable state: {:?}", e);
        }
    }
}
