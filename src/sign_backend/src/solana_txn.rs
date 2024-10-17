use candid::CandidType;
use serde::{Deserialize, Serialize};
use ic_cdk::api::management_canister::http_request::CanisterHttpRequestArgument;
use ic_cdk::api::management_canister::http_request::{self, HttpHeader, HttpMethod};
use serde_json::{json, Value};
use base64;
use ic_cdk::api::management_canister::http_request::http_request;

#[derive(CandidType, Deserialize, Debug)]
pub struct SignatureResponse {
    pub jsonrpc: String,
    pub result: Vec<SignatureInfo>,
    pub id: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<String>,    // Optional error if the transaction failed
    pub memo: Option<String>,   // Optional memo
    pub blockTime: Option<i64>, // Optional block time
    pub confirmationStatus: Option<String>, // Optional confirmation status
}

#[ic_cdk::update]
async fn get_signatures_for_address(address: String) -> Result<Vec<SignatureInfo>, String> {
    // Define the Solana Devnet URL (use mainnet URL for production)
    let url = "https://api.devnet.solana.com";

    // Prepare the JSON body for the request
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            address,
            {} // Empty options; modify if needed
        ],
    });
    let request_body_bytes = request_body.to_string().into_bytes();

    // Define headers
    let headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];

    // Create the request
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: None,
        method: HttpMethod::POST,
        headers,
        body: Some(request_body_bytes),
        transform: None,
    };


    match http_request(request, 5_000_000_000).await {
        Ok((response,)) => {
            // Decode the response body
            let response_body = String::from_utf8(response.body)
                .map_err(|_| "Failed to decode response body as UTF-8".to_string())?;
            ic_cdk::println!("result response_body {:?}", response_body);

            // Parse the response JSON
            let signature_response: SignatureResponse = serde_json::from_str(&response_body)
                .map_err(|_| "Failed to parse response JSON".to_string())?;

            Ok(signature_response.result)
        }
        Err((rejection_code, msg)) => Err(format!(
            "Error during signature request: RejectionCode: {:?}, Error: {}",
            rejection_code, msg
        )),
    }
}

#[ic_cdk::update]
async fn get_program_data(signature: String) -> Result<(), String> {
    let url = "https://api.devnet.solana.com";

    // Prepare the JSON-RPC payload
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "json",
                "commitment": "finalized"
            }
        ]
    });
    let payload_bytes = payload.to_string().into_bytes();

    // Define headers
    let headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];

    // Create the HTTP request
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: None,
        method: HttpMethod::POST,
        headers,
        body: Some(payload_bytes),
        transform: None,
    };

    // Send the HTTP request
    let response = http_request(request, 5_000_000_000)
        .await
        .map_err(|(r, m)| format!("HTTP request failed: RejectionCode: {:?}, Error: {}", r, m))?;

    // Parse the response and extract the log messages
    let response_body = String::from_utf8(response.0.body)
        .map_err(|_| "Failed to decode response body as UTF-8".to_string())?;

    let json_response: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|_| "Failed to parse JSON response".to_string())?;



    
    if let Some(logs) = json_response["result"]["meta"]["logMessages"].as_array() {
        for log in logs.iter().filter_map(|log| log.as_str()) {
            if log.contains("Program data: ") {
                if let Some(encoded_data) = log.split("Program data: ").nth(1) {
                    // Trim any extra whitespace and print the result
                    let encoded_data = encoded_data.trim();
                    ic_cdk::println!("Program data: {}", encoded_data);
                    return Ok(());  // Return after printing to stop further processing
                }
            }
        }
    } else {
        ic_cdk::println!("No log messages found in transaction data.");
    }
  

    Ok(())
}


async fn decode_base64_to_lossy_string(encoded: String) -> Result<String, String> {
    let decoded_bytes = base64::decode(&encoded).map_err(|e| format!("Failed to decode Base64 string: {}", e))?;
    Ok(String::from_utf8_lossy(&decoded_bytes).to_string())
}

#[ic_cdk::update]
async fn process_decoding(encoded_data: String) -> Result<(), String> {
    match decode_base64_to_lossy_string(encoded_data.clone()).await {
        Ok(decoded_str) => {
            ic_cdk::println!("Decoded (lossy) string: {}", decoded_str);
            Ok(())
        }
        Err(err) => {
            ic_cdk::println!("Error: {}", err);
            Err(err)
        }
    }
}
