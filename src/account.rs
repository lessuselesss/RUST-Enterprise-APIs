use crate::{
    LIB_VERSION, hex_fix, string_to_hex, get_formatted_timestamp,
    DEFAULT_NAG, DEFAULT_CHAIN, NETWORK_URL, Certificate
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
    nag_url: String,
    network_node: String,
    blockchain: String,
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
            nag_url: DEFAULT_NAG.to_string(),
            network_node: String::new(),
            blockchain: DEFAULT_CHAIN.to_string(),
            latest_tx_id: String::new(),
            nonce: 0,
            data: serde_json::json!({}),
            interval_sec: 2,
        }
    }

    /// Opens an account with the specified address
    pub fn open(&mut self, address: &str) -> Result<(), AccountError> {
        if address.is_empty() {
            return Err(AccountError::InvalidAddress("Address cannot be empty".into()));
        }
        self.address = Some(address.to_string());
        Ok(())
    }

    /// Sets the network configuration
    pub async fn set_network(&mut self, network: &str) -> Result<(), AccountError> {
        let client = Client::new();
        let url = format!("{}{}", NETWORK_URL, urlencoding::encode(network));

        let response = client.get(&url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AccountError::NetworkError(format!(
                "HTTP error! status: {}", 
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct NetworkResponse {
            status: String,
            url: Option<String>,
            message: Option<String>,
        }

        let data: NetworkResponse = response.json().await?;

        if data.status == "success" {
            if let Some(url) = data.url {
                self.nag_url = url;
                Ok(())
            } else {
                Err(AccountError::NetworkError("No URL in successful response".into()))
            }
        } else {
            Err(AccountError::NetworkError(
                data.message.unwrap_or_else(|| "Failed to get URL".into())
            ))
        }
    }

    /// Sets the blockchain
    pub fn set_blockchain(&mut self, chain: &str) {
        self.blockchain = chain.to_string();
    }

    /// Sets the network node
    /// This matches the API specification across all language implementations
    pub fn set_network_node(&mut self, node: &str) {
        self.network_node = node.to_string();
    }

    /// Sets the polling interval
    /// This matches the API specification across all language implementations
    pub fn set_interval(&mut self, seconds: u64) {
        self.interval_sec = seconds;
    }

    /// Updates the account parameters such as Nonce
    pub async fn update_account(&mut self) -> Result<bool, AccountError> {
        let address = self.address.as_ref()
            .ok_or(AccountError::AccountNotOpen)?;
        
        let data = serde_json::json!({
            "Blockchain": hex_fix(&self.blockchain),
            "Address": hex_fix(address),
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_GetWalletNonce_{}", 
            self.nag_url,
            self.network_node
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

    /// Submits a certificate to the blockchain
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
            hex_fix(&self.blockchain),
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
            "Blockchain": hex_fix(&self.blockchain),
            "Type": "C_TYPE_CERTIFICATE",
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_AddTransaction_{}",
            self.nag_url,
            self.network_node
        );

        let response = client.post(&url)
            .json(&tx_data)
            .send()
            .await?;

        response.json()
            .await
            .map_err(AccountError::from)
    }

    /// Gets a transaction by its ID
    pub async fn get_transaction(&self, block_num: u64, tx_id: &str) -> Result<serde_json::Value, AccountError> {
        let data = serde_json::json!({
            "Blockchain": hex_fix(&self.blockchain),
            "ID": hex_fix(tx_id),
            "Start": block_num.to_string(),
            "End": block_num.to_string(),
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_GetTransactionbyID_{}", 
            self.nag_url,
            self.network_node
        );

        let response = client.post(&url)
            .json(&data)
            .send()
            .await?;

        response.json()
            .await
            .map_err(AccountError::from)
    }

    /// Gets a transaction by its ID within a block range
    /// This matches the API specification across all language implementations
    pub async fn get_transaction_by_id(&self, tx_id: &str, start: u64, end: u64) -> Result<serde_json::Value, AccountError> {
        let data = serde_json::json!({
            "Blockchain": hex_fix(&self.blockchain),
            "ID": hex_fix(tx_id),
            "Start": start.to_string(),
            "End": end.to_string(),
            "Version": self.version
        });

        let client = Client::new();
        let url = format!("{}Circular_GetTransactionbyID_{}", 
            self.nag_url,
            self.network_node
        );

        let response = client.post(&url)
            .json(&data)
            .send()
            .await?;

        response.json()
            .await
            .map_err(AccountError::from)
    }

    /// Polls for transaction outcome with timeout
    pub async fn get_transaction_outcome(&self, tx_id: &str, timeout_sec: u64) -> Result<serde_json::Value, AccountError> {
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_sec);
        let interval = std::time::Duration::from_secs(self.interval_sec);

        loop {
            if start_time.elapsed() > timeout {
                return Err(AccountError::TimeoutError("Transaction polling timeout exceeded".into()));
            }

            match self.get_transaction_by_id(tx_id, 0, 10).await {
                Ok(response) => {
                    if let Some(resp) = response.get("Response") {
                        if resp != "Transaction Not Found" {
                            if let Some(status) = resp.get("Status") {
                                if status != "Pending" {
                                    return Ok(response);
                                }
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// Closes the account
    pub fn close(&mut self) {
        *self = Self::new();
    }

    // Private helper methods
    fn sign_data(&self, data: &str, private_key: &str) -> Result<String, AccountError> {
        let address = self.address.as_ref()
            .ok_or(AccountError::AccountNotOpen)?;
        
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&hex::decode(hex_fix(private_key))?)?;
        
        let message = Message::from_slice(&Sha256::digest(data.as_bytes()))
            .map_err(|_| AccountError::InvalidPrivateKey("Invalid message format".into()))?;
        
        let signature = secp.sign_ecdsa(&message, &secret_key);
        Ok(hex::encode(signature.serialize_der()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_methods_existence() {
        // Create an instance of Account
        let mut account = Account::new();
        
        // Test constructor
        assert_eq!(account.version, LIB_VERSION);
        
        // Test open method
        assert!(account.open("test_address").is_ok());
        
        // Test set_blockchain
        account.set_blockchain("test_chain");
        assert_eq!(account.blockchain, "test_chain");
        
        // Test set_network_node
        account.set_network_node("test_node");
        assert_eq!(account.network_node, "test_node");
        
        // Test set_interval
        account.set_interval(5);
        assert_eq!(account.interval_sec, 5);
        
        // Test close
        account.close();
        assert!(account.address.is_none());
    }

    #[tokio::test]
    async fn test_async_methods_existence() {
        let mut account = Account::new();
        
        // Test set_network (async)
        // Note: This might fail if network is unreachable, but we're just testing method existence
        let _ = account.set_network("test_network").await;
        
        // Test update_account (async)
        let _ = account.update_account().await;
        
        // Test submit_certificate (async)
        let _ = account.submit_certificate("test_data", "test_key").await;
        
        // Test get_transaction (async)
        let _ = account.get_transaction(0, "test_id").await;
        
        // Test get_transaction_by_id (async)
        let _ = account.get_transaction_by_id("test_id", 0, 10).await;
        
        // Test get_transaction_outcome (async)
        let _ = account.get_transaction_outcome("test_id", 5).await;
    }
} 