use serde::{Deserialize, Serialize};
use hex;
use sha2::{Sha256, Digest};
use crate::error::{CEPError, Result};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CCertificate {
    pub data: String, // Stored as hex
    #[serde(rename = "type")]
    cert_type: String,
    issuer: String,
    uri: String,
    hash: String,
    signature: String,
    pub previous_tx_id: Option<String>,
    pub previous_block: Option<String>,
    pub code_version: String,
}

impl CCertificate {
    pub fn new() -> Self {
        CCertificate {
            code_version: "1.0.0-rust".to_string(), // Assuming a default version
            previous_tx_id: Some(String::new()), // Initialize as Some empty string
            previous_block: Some(String::new()), // Initialize as Some empty string
            ..Default::default()
        }
    }

    pub fn set_data(&mut self, data: &str) {
        self.data = hex::encode(data.as_bytes());
        self.update_hash();
    }

    pub fn get_data(&self) -> String {
        if self.data.is_empty() || self.data == "0x" {
            return String::new();
        }
        // Attempt to decode hex data. If it fails, return the original hex string.
        hex::decode(&self.data).map_or_else(|_| self.data.clone(), |bytes| String::from_utf8_lossy(&bytes).to_string())
    }

    pub fn set_type(&mut self, cert_type: &str) {
        self.cert_type = cert_type.to_string();
        self.update_hash();
    }

    pub fn get_type(&self) -> String {
        self.cert_type.clone()
    }

    pub fn set_issuer(&mut self, issuer: &str) {
        self.issuer = issuer.to_string();
        self.update_hash();
    }

    pub fn get_issuer(&self) -> String {
        self.issuer.clone()
    }

    pub fn set_uri(&mut self, uri: &str) {
        self.uri = uri.to_string();
        self.update_hash();
    }

    pub fn get_uri(&self) -> String {
        self.uri.clone()
    }

    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }

    pub fn set_signature(&mut self, signature: &str) {
        self.signature = signature.to_string();
    }

    pub fn get_signature(&self) -> String {
        self.signature.clone()
    }

    pub fn get_json_certificate(&self) -> String {
        serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn get_certificate_size(&self) -> usize {
        self.get_json_certificate().as_bytes().len()
    }

    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(&self).map_err(CEPError::DeserializationError)
    }

    // Private helper to update hash whenever relevant fields change
    fn update_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.data.as_bytes());
        hasher.update(self.cert_type.as_bytes());
        hasher.update(self.issuer.as_bytes());
        hasher.update(self.uri.as_bytes());
        if let Some(prev_tx_id) = &self.previous_tx_id {
            hasher.update(prev_tx_id.as_bytes());
        }
        if let Some(prev_block) = &self.previous_block {
            hasher.update(prev_block.as_bytes());
        }
        hasher.update(self.code_version.as_bytes());
        self.hash = hex::encode(hasher.finalize());
    }
}
