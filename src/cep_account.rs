use crate::c_certificate::CCertificate;
use crate::error::{CEPError, Result};
use crate::models::*;
use secp256k1::{Message, Secp256k1};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

const LIB_VERSION: &str = "1.0.0-rust";
const DEFAULT_NAG: &str = "https://nag.testnet.circular";
const DEFAULT_CHAIN: &str = "Circular-Main-Public-Chain";

/// Represents a client account for interacting with the Circular ESM Enterprise API.
#[derive(Debug)]
pub struct CEPAccount {
    pub address: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub info: Option<serde_json::Value>,
    pub code_version: String,
    pub nag_url: String,
    pub network_node: String,
    pub blockchain: String,
    pub latest_tx_id: String,
    pub nonce: u64,
    pub interval_sec: u64,
    pub is_open: bool,
    client: reqwest::Client,
}

impl Default for CEPAccount {
    /// #### 1.2.1 - Test: should initialize with default values
    fn default() -> Self {
        Self {
            address: None,
            public_key: None,
            private_key: None,
            info: None,
            code_version: LIB_VERSION.to_string(),
            nag_url: DEFAULT_NAG.to_string(),
            network_node: String::new(),
            blockchain: DEFAULT_CHAIN.to_string(),
            latest_tx_id: String::new(),
            nonce: 0,
            interval_sec: 2,
            is_open: false,
            client: reqwest::Client::new(),
        }
    }
}

impl CEPAccount {
    /// Creates a new `CEPAccount` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_address(&self) -> String {
        self.address.clone().unwrap_or_default()
    }

    pub fn set_address(&mut self, address: &str) {
        self.address = Some(address.to_string());
    }

    pub fn get_public_key(&self) -> String {
        self.public_key.clone().unwrap_or_default()
    }

    pub fn set_public_key(&mut self, public_key: &str) {
        self.public_key = Some(public_key.to_string());
    }

    pub fn get_private_key(&self) -> String {
        self.private_key.clone().unwrap_or_default()
    }

    pub fn set_private_key(&mut self, private_key: &str) {
        self.private_key = Some(private_key.to_string());
    }

    pub fn get_network(&self) -> String {
        self.network_node.clone() // Assuming network_node stores the current network
    }

    pub fn get_blockchain(&self) -> String {
        self.blockchain.clone()
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    pub fn is_open(&self) -> bool {
        self.is_open
    }

    pub fn set_open(&mut self, open: bool) {
        self.is_open = open;
    }

    /// #### 1.3 The open method
    pub async fn open(&mut self, address: &str, private_key_hex: &str) -> Result<()> {
        if address.is_empty() {
            return Err(CEPError::InvalidArgument("Invalid address format".to_string()));
        }
        self.address = Some(address.to_string());
        
        // Remove "0x" prefix if present
        let clean_private_key_hex = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
        self.private_key = Some(clean_private_key_hex.to_string());
        self.is_open = true;

        // Derive public key from private key if needed
        let private_key_bytes = hex::decode(clean_private_key_hex)?;
        let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes)?;
        let secp = secp256k1::Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        self.public_key = Some(hex::encode(public_key.serialize().as_ref()));
        
        Ok(())
    }

    /// #### 1.4 The close method
    pub fn close(&mut self) {
        *self = Self::default();
    }

    /// #### 1.5 The setBlockchain method
    pub fn set_blockchain(&mut self, chain: &str) {
        self.blockchain = chain.to_string();
    }

    /// #### 1.6 The setNetwork method
    pub async fn set_network(&mut self, network: &str) -> Result<()> {
        let url = format!("{}/network/getNAG?network={}", self.nag_url, network);
        let res = self.client.get(&url).send().await?.error_for_status()?;
        let body: NagResponse = res.json().await?;

        if body.status == "error" {
            let message = body.message.unwrap_or_else(|| "Unknown API error".to_string());
            return Err(CEPError::ApiError { message });
        }

        self.nag_url = body.nag.ok_or_else(|| CEPError::ApiError {
            message: "NAG URL missing from successful response".to_string(),
        })?;

        Ok(())
    }
    
    /// #### 1.7 The updateAccount method
    pub async fn update_account(&mut self) -> Result<bool> {
        let address = self.address.as_ref().ok_or_else(|| CEPError::Logic("Account is not open".to_string()))?;
        
        let req_body = GetNonceRequest {
            address,
            blockchain: &self.blockchain,
            version: &self.code_version,
        };

        let res = self.client
            .post(format!("{}/API/Circular_GetWalletNonce_", self.nag_url))
            .json(&req_body)
            .send()
            .await;

        let res = match res {
            Ok(r) => r,
            Err(_) => return Ok(false), // Network error
        };

        if !res.status().is_success() {
            return Ok(false);
        }

        let body: GetNonceResponse = match res.json().await {
            Ok(b) => b,
            Err(_) => return Ok(false), // Malformed response
        };
        
        if body.result != 200 {
            return Ok(false);
        }

        if let Some(nonce) = body.nonce {
            self.nonce = nonce + 1;
            Ok(true)
        } else {
            Ok(false) // Nonce missing from response
        }
    }
    
    /// #### 1.8 The signData method
    pub fn sign_data(&self, data: &str, private_key_hex: &str) -> Result<String> {
        self.address.as_ref().ok_or_else(|| CEPError::Logic("Account is not open".to_string()))?;
        
        // Remove "0x" prefix if present
        let clean_private_key_hex = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
        let private_key_bytes = hex::decode(clean_private_key_hex)?;
        let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes)?;

        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();

        let secp = Secp256k1::new();
        let message = Message::from_slice(&hash)?;
        let signature = secp.sign_ecdsa(&message, &secret_key);

        Ok(hex::encode(signature.serialize_der()))
    }
    
    /// #### 1.10 The submitCertificate method
    pub async fn submit_certificate(&self, cert_data: &str, private_key_hex: &str) -> Result<SubmitTxResponse> {
        let from_address = self.address.as_ref().ok_or_else(|| CEPError::Logic("Account is not open".to_string()))?;

        let mut cert = CCertificate::new();
        cert.set_data(cert_data);
        let cert_json = cert.to_json_string()?;

        let signature = self.sign_data(&cert_json, private_key_hex)?;

        let req_body = SubmitTxRequest {
            from: from_address,
            to: from_address, // Self-transaction
            nonce: self.nonce,
            r#type: 6, // Assuming type 6 for certificate
            blockchain: &self.blockchain,
            payload: SubmitTxPayload {
                data: &cert.data,
                previous_tx_id: cert.previous_tx_id.as_deref(),
                previous_block: cert.previous_block.as_deref(),
                code_version: &cert.code_version,
            },
            signature: &signature,
            version: &self.code_version,
        };

        let res = self.client
            .post(format!("{}/API/Circular_AddTransaction_", self.nag_url))
            .json(&req_body)
            .send()
            .await?;
        
        if !res.status().is_success() {
             return Ok(SubmitTxResponse::Error {
                result: res.status().as_u16() as i32,
                response: "Server unreachable or request failed".to_string(),
            });
        }
        
        let parsed_res = res.json().await?;
        Ok(parsed_res)
    }

    /// #### 1.9 getTransactionbyID
    pub async fn get_transaction_by_id(&self, tx_id: &str, start_block: u64, end_block: u64) -> Result<GetTxResponse> {
        let req_body = GetTxRequest {
            id: tx_id,
            start_block,
            end_block,
            blockchain: &self.blockchain,
            version: &self.code_version,
        };

        let res = self.client
            .post(format!("{}/API/Circular_GetTransactionbyID_", self.nag_url))
            .json(&req_body)
            .send()
            .await?;
        
        Ok(res.json().await?)
    }

    /// #### 1.11 getTransactionOutcome
    pub async fn get_transaction_outcome(&self, tx_id: &str, timeout_sec: u64) -> Result<TransactionData> {
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_sec);
        
        loop {
            if start_time.elapsed() > timeout {
                return Err(CEPError::TimeoutExceeded);
            }

            match self.get_transaction_by_id(tx_id, 0, 0).await {
                Ok(GetTxResponse::Found { response, .. }) => {
                    if response.status == "Confirmed" || response.status == "Executed" {
                        return Ok(response);
                    }
                    // Otherwise, it's "Pending", so we continue polling.
                }
                Ok(GetTxResponse::NotFound { .. }) => {
                    // "Transaction Not Found", continue polling as it might not have propagated yet.
                }
                Err(e) => {
                    // A network or parsing error occurred during polling.
                    return Err(e);
                }
            }

            tokio::time::sleep(Duration::from_secs(self.interval_sec)).await;
        }
    }
}