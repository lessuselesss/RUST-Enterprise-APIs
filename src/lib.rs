pub mod certificate;
pub mod account;
mod utils;
mod error;

pub use certificate::Certificate;
pub use account::Account;

// Library version constant
pub const LIB_VERSION: &str = "1.0.13";
pub const DEFAULT_CHAIN: &str = "0x8a20baa40c45dc5055aeb26197c203e576ef389d9acb171bd62da11dc5ad72b2";
pub const DEFAULT_NAG: &str = "https://nag.circularlabs.io/NAG.php?cep=";
pub const NETWORK_URL: &str = "https://circularlabs.io/network/getNAG?network="; 