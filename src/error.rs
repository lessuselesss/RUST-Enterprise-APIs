use thiserror::Error;

#[derive(Error, Debug)]
pub enum CEPError {
    #[error("Logic Error: {0}")]
    Logic(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Network request failed: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("Failed to parse JSON response: {0}")]
    DeserializationError(#[from] serde_json::Error),

    #[error("API returned an error: {message}")]
    ApiError { message: String },

    #[error("Cryptography error: {0}")]
    Crypto(#[from] secp256k1::Error),

    #[error("Hex decoding/encoding error: {0}")]
    Hex(#[from] hex::FromHexError),
    
    #[error("Polling for transaction outcome timed out")]
    TimeoutExceeded,

    #[error("Transaction not found")]
    TransactionNotFound,

    #[error("Unknown error")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, CEPError>;