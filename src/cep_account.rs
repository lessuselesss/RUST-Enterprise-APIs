// FILE: src/cep_account.rs

use crate::error::{Error, Result};
use crate::helper;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use k256::SecretKey;

#[derive(Debug)]
pub struct CEPAccount {
    address: Option<String>,
    nag_url: String,
    network_node: String,
    blockchain: String,
    latest_tx_id: Option<String>,
    nonce: u64,
    client: Arc<Client>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct GetNonceRequest<'a> {
    blockchain: &'a str,
    address: &'a str,
    version: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetNonceResponse {
    result: i32,
    response: GetNonceResponsePayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GetNonceResponsePayload {
    nonce: u64,
}

#[derive(Deserialize)]
struct SetNetworkResponse {
    url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct TransactionData<'a> {
    id: &'a str,
    from: &'a str,
    to: &'a str,
    timestamp: String,
    payload: String,
    nonce: String,
    signature: String,
    blockchain: &'a str,
    #[serde(rename = "Type")]
    tx_type: &'static str,
    version: &'static str,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct TransactionOutcome {
    pub result: i32,
    pub response: Value,
}

// New struct for GetTransactionbyID API request
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetTransactionRequest<'a> {
    pub id: &'a str,
    pub start: &'a str,
    pub end: &'a str,
    pub blockchain: &'a str,
    pub version: &'static str,
}

impl CEPAccount {
    pub fn new_prod() -> Self {
        CEPAccount {
            address: None,
            nag_url: helper::DEFAULT_NAG.to_string(),
            network_node: String::new(),
            blockchain: helper::DEFAULT_CHAIN.to_string(),
            latest_tx_id: None,
            nonce: 0,
            client: Arc::new(Client::builder()
                .timeout(Duration::from_secs(30))
                .no_proxy()
                .build()
                .expect("Failed to build production HTTP client")),
        }
    }

    pub fn new() -> Self {
        CEPAccount::new_prod()
    }

    pub fn new_with_client(client: Arc<Client>) -> Self {
        CEPAccount {
            address: None,
            nag_url: helper::DEFAULT_NAG.to_string(),
            network_node: String::new(),
            blockchain: helper::DEFAULT_CHAIN.to_string(),
            latest_tx_id: None,
            nonce: 0,
            client,
        }
    }

    pub fn open(&mut self, address: &str) -> Result<()> {
        if address.is_empty() {
            return Err(Error::InvalidInput("Address cannot be empty".to_string()));
        }
        self.address = Some(address.to_string());
        Ok(())
    }

    pub fn update_account(&mut self) -> Result<()> {
        let address = self.address.as_ref().ok_or(Error::AccountNotOpen)?;
        let request_body = GetNonceRequest {
            blockchain: &helper::hex_fix(&self.blockchain),
            address: &helper::hex_fix(address),
            version: helper::LIB_VERSION,
        };
        let url = format!("{}Circular_GetWalletNonce_", self.nag_url);
        let resp: GetNonceResponse = self.client.post(&url).json(&request_body).send()?.json()?;
        if resp.result == 200 {
            self.nonce = resp.response.nonce + 1;
            Ok(())
        } else {
            Err(Error::ApiError(format!(
                "Failed to update account, API result: {}",
                resp.result
            )))
        }
    }

    pub fn set_network(&mut self, network: &str) -> Result<String> {
        let url = format!("{}{}", helper::NETWORK_URL, network);
        let resp: SetNetworkResponse = self.client.get(&url).send()?.json()?;
        self.nag_url = resp.url.clone();
        Ok(resp.url)
    }

    pub fn submit_certificate(&mut self, pdata: &str, private_key_hex: &str) -> Result<()> {
        let address = self.address.as_ref().ok_or(Error::AccountNotOpen)?;
        let fixed_address = helper::hex_fix(address);

        let mut payload_object = HashMap::new();
        payload_object.insert("Action", "CP_CERTIFICATE");
        
        let hex_encoded_data = helper::string_to_hex(pdata);
        payload_object.insert("Data", &hex_encoded_data);

        let json_str = serde_json::to_string(&payload_object)?;
        let payload = helper::string_to_hex(&json_str);

        let timestamp = helper::get_formatted_timestamp();
        let str_to_hash = format!(
            "{}{}{}{}{}{}",
            helper::hex_fix(&self.blockchain),
            fixed_address,
            fixed_address,
            payload,
            self.nonce,
            timestamp
        );

        let mut hasher = Sha256::new();
        hasher.update(str_to_hash.as_bytes());
        let id_hash = hasher.finalize();
        let id = hex::encode(id_hash);

        let signature = self.sign_data(&id, private_key_hex)?;

        let transaction_data = TransactionData {
            id: &id,
            from: &fixed_address,
            to: &fixed_address,
            timestamp,
            payload,
            nonce: self.nonce.to_string(),
            signature,
            blockchain: &helper::hex_fix(&self.blockchain),
            tx_type: "C_TYPE_CERTIFICATE",
            version: helper::LIB_VERSION,
        };

        let url = format!("{}Circular_AddTransaction_{}", self.nag_url, self.network_node);
        let resp = self.client
            .post(&url)
            .json(&transaction_data)
            .send()?
            .json::<Value>()?;

        if resp["Result"] == 200 {
            self.latest_tx_id = Some(id);
            self.nonce += 1;
            Ok(())
        } else {
            Err(Error::ApiError(resp["Response"].to_string()))
        }
    }

    fn sign_data(&self, message: &str, private_key_hex: &str) -> Result<String> {
        let clean_pk = helper::hex_fix(private_key_hex);
        if clean_pk.len() != 64 {
            return Err(Error::InvalidInput(
                "Invalid private key length. Expected 64 hex characters.".to_string(),
            ));
        }
        let secret_key = SecretKey::from_slice(&hex::decode(clean_pk)?)?;
        let signing_key: SigningKey = SigningKey::from(secret_key);

        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash = hasher.finalize();
        
        let signature: Signature = PrehashSigner::<Signature>::sign_prehash(&signing_key, &message_hash)?
            .normalize_s()
            .ok_or_else(|| Error::Crypto("Failed to normalize signature (s-value was zero)".to_string()))?;
        
        let der_signature = signature.to_der();
        Ok(hex::encode(der_signature.as_bytes()))
    }

    pub fn get_transaction_outcome(
        &self,
        tx_id: &str,
        timeout_sec: u64,
        interval_sec: u64,
    ) -> Result<TransactionOutcome> {
        let start_time = Instant::now();
        loop {
            if start_time.elapsed().as_secs() > timeout_sec {
                return Err(Error::Timeout);
            }
            match self.get_transaction("0", tx_id) {
                Ok(data) => {
                    if data.result == 200 {
                        if let Some(response_map) = data.response.as_object() {
                            if let Some(status) = response_map.get("Status").and_then(|s| s.as_str())
                            {
                                if status != "Pending" {
                                    return Ok(data);
                                }
                            } else {
                                return Ok(data);
                            }
                        }
                    }
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_secs(interval_sec));
        }
    }

    pub fn get_transaction(&self, block_id: &str, tx_id: &str) -> Result<TransactionOutcome> {
        let url = format!("{}Circular_GetTransactionbyID_", self.nag_url);
        let request_body = GetTransactionRequest {
            id: &helper::hex_fix(tx_id),
            start: block_id,
            end: block_id,
            blockchain: &helper::hex_fix(&self.blockchain),
            version: helper::LIB_VERSION,
        };

        let resp: TransactionOutcome = self.client.post(&url).json(&request_body).send()?.json()?;
        Ok(resp)
    }

    pub fn close(&mut self) {
        self.address = None;
        self.nag_url = helper::DEFAULT_NAG.to_string();
        self.network_node = String::new();
        self.blockchain = helper::DEFAULT_CHAIN.to_string();
        self.latest_tx_id = None;
        self.nonce = 0;
    }

    pub fn set_nag_url(&mut self, nag_url: String) {
        self.nag_url = nag_url;
    }

    pub fn set_network_node(&mut self, network_node: String) {
        self.network_node = network_node;
    }

    pub fn set_blockchain(&mut self, blockchain: String) {
        self.blockchain = blockchain;
    }

    pub fn get_latest_tx_id(&self) -> Option<&str> {
        self.latest_tx_id.as_deref()
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    pub fn get_transaction_by_id(
        &self,
        tx_id: &str,
        start_block: &str,
        end_block: &str,
    ) -> Result<TransactionOutcome> {
        let url = format!("{}Circular_GetTransactionbyID_", self.nag_url);
        let request_body = GetTransactionRequest {
            id: &helper::hex_fix(tx_id),
            start: start_block,
            end: end_block,
            blockchain: &helper::hex_fix(&self.blockchain),
            version: helper::LIB_VERSION,
        };

        let resp: TransactionOutcome = self.client.post(&url).json(&request_body).send()?.json()?;
        Ok(resp)
    }
}