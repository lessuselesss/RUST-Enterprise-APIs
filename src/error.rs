use thiserror::Error;
use secp256k1::Error as Secp256k1Error;
use serde_json::Error as SerdeError;
use reqwest::Error as ReqwestError;

#[derive(Error, Debug)]
pub(crate) enum AccountError {
    #[error("Account is not open")]
    AccountNotOpen,
    
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
    
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Cryptography error: {0}")]
    CryptoError(#[from] Secp256k1Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerdeError),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] ReqwestError),
    
    #[error("Transaction error: {0}")]
    TransactionError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Invalid response format: {0}")]
    InvalidResponseFormat(String),
    
    #[error("Certificate error: {0}")]
    CertificateError(String),
}

impl From<hex::FromHexError> for AccountError {
    fn from(err: hex::FromHexError) -> Self {
        AccountError::InvalidPrivateKey(format!("Invalid hex format: {}", err))
    }
} 