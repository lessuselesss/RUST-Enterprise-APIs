use crate::{
    LIB_VERSION, hex_fix, string_to_hex, get_formatted_timestamp,
    NetworkConfig, Certificate
};
use reqwest::Client;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use secp256k1::{SecretKey, PublicKey, Message, Secp256k1};
use rand::rngs::OsRng;
use crate::error::AccountError;

#[derive(Debug, Clone)]
pub struct Account {
    address: Option<String>,
    public_key: Option<String>,
    info: Option<String>,
    version: String,
    last_error: String,
    network: NetworkConfig,
    latest_tx_id: String,
    nonce: u64,
    data: serde_json::Value,
    interval_sec: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionResponse {
    result: u32,
    response: Option<serde_json::Value>,
}

impl Account {
    pub fn new() -> Self {
        Self {
            address: None,
            public_key: None,
            info: None,
            version: LIB_VERSION.to_string(),
            last_error: String::new(),
            network: NetworkConfig::new(),
            latest_tx_id: String::new(),
            nonce: 0,
            data: serde_json::json!({}),
            interval_sec: 2,
        }
    }

    pub fn open(&mut self, address: &str) -> Result<(), AccountError> {
        if address.is_empty() {
            return Err(AccountError::InvalidAddress("Address cannot be empty".into()));
        }
        self.address = Some(address.to_string());
        Ok(())
    }

    pub async fn update_account(&mut self) -> Result<bool, AccountError> {
        let address = self.address.as_ref()
            .ok_or(AccountError::AccountNotOpen)?;
        
        let data = serde_json::json!({
            "Blockchain": hex_fix(&self.network.get_blockchain()),
            "Address": hex_fix(address),
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_GetWalletNonce_{}", 
            self.network.get_nag_url(),
            self.network.get_network_node()
        );

        let response = client.post(&url)
            .json(&data)
            .send()
            .await?;

        let tx_response: TransactionResponse = response.json()
            .await?;

        if tx_response.result == 200 {
            if let Some(resp) = tx_response.response {
                if let Some(nonce) = resp.get("Nonce").and_then(|n| n.as_u64()) {
                    self.nonce = nonce + 1;
                    return Ok(true);
                }
            }
        }
        Err(AccountError::InvalidResponseFormat("Missing or invalid Nonce field".into()))
    }

    pub fn sign_data(&self, data: &str, private_key: &str) -> Result<String, AccountError> {
        let address = self.address.as_ref()
            .ok_or(AccountError::AccountNotOpen)?;
        
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&hex::decode(hex_fix(private_key))?)?;
        
        let message = Message::from_slice(&Sha256::digest(data.as_bytes()))
            .map_err(|_| AccountError::InvalidPrivateKey("Invalid message format".into()))?;
        
        let signature = secp.sign_ecdsa(&message, &secret_key);
        Ok(hex::encode(signature.serialize_der()))
    }

    pub async fn submit_certificate(&mut self, data: &str, private_key: &str) -> Result<serde_json::Value, AccountError> {
        let address = self.address.as_ref()
            .ok_or(AccountError::AccountNotOpen)?;
        
        let payload_obj = serde_json::json!({
            "Action": "CP_CERTIFICATE",
            "Data": string_to_hex(data)
        });

        let payload = string_to_hex(&payload_obj.to_string());
        let timestamp = get_formatted_timestamp();
        
        let str = format!("{}{}{}{}{}{}",
            hex_fix(&self.network.get_blockchain()),
            hex_fix(address),
            hex_fix(address),
            payload,
            self.nonce,
            timestamp
        );

        let id = hex::encode(Sha256::digest(str.as_bytes()));
        let signature = self.sign_data(&id, private_key)?;

        let tx_data = serde_json::json!({
            "ID": id,
            "From": hex_fix(address),
            "To": hex_fix(address),
            "Timestamp": timestamp,
            "Payload": payload,
            "Nonce": self.nonce.to_string(),
            "Signature": signature,
            "Blockchain": hex_fix(&self.network.get_blockchain()),
            "Type": "C_TYPE_CERTIFICATE",
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_AddTransaction_{}",
            self.network.get_nag_url(),
            self.network.get_network_node()
        );

        let response = client.post(&url)
            .json(&tx_data)
            .send()
            .await?;

        response.json()
            .await
            .map_err(AccountError::from)
    }

    pub fn close(&mut self) {
        *self = Self::new();
    }

    pub fn set_interval_sec(&mut self, seconds: u64) {
        self.interval_sec = seconds;
    }
} 