//! # CEP SDK
//!
//! A Rust SDK for interacting with the Circular ESM Enterprise APIs.
//! This library provides functionality for managing accounts, creating
//! and submitting certificates, and querying transaction status on the
//! Circular network.

// Expose the public components of the library.
pub mod cep_account;
pub mod c_certificate;
pub mod error;
pub mod models;

pub use cep_account::CEPAccount;
pub use c_certificate::CCertificate;
pub use error::{CEPError, Result};