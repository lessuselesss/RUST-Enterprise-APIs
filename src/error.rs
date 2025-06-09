// FILE: src/error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Account is not open")]
    AccountNotOpen,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Network request failed")]
    Network(#[from] reqwest::Error),

    #[error("JSON serialization or deserialization failed")]
    Json(#[from] serde_json::Error),
    
    #[error("Hex decoding failed")]
    Hex(#[from] hex::FromHexError),
    
    #[error("UTF-8 conversion failed")]
    Utf8(#[from] std::string::FromUtf8Error),
    
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("API call returned an error: {0}")]
    ApiError(String),

    #[error("Timeout exceeded while waiting for transaction outcome")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;

// This is where ALL error conversions should live.
impl From<k256::ecdsa::Error> for Error {
    fn from(e: k256::ecdsa::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

// FIX #1: This is the correct, single location for this implementation.
impl From<k256::elliptic_curve::Error> for Error {
    fn from(e: k256::elliptic_curve::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}