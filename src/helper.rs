// FILE: src/helper.rs

use chrono::Utc;

// All of these constants and functions must be public to be used by other modules.
pub const LIB_VERSION: &str = "1.0.13";
pub const NETWORK_URL: &str = "https://circularlabs.io/network/getNAG?network=";
pub const DEFAULT_CHAIN: &str = "0x8a20baa40c45dc5055aeb26197c203e576ef389d9acb171bd62da11dc5ad72b2";
pub const DEFAULT_NAG: &str = "https://nag.circularlabs.io/NAG.php?cep=";

pub fn get_formatted_timestamp() -> String {
    let now_utc = Utc::now();
    now_utc.format("%Y:%m:%d-%H:%M:%S").to_string()
}

pub fn hex_fix(hex_str: &str) -> String {
    hex_str.strip_prefix("0x").unwrap_or(hex_str).to_string()
}

pub fn string_to_hex(s: &str) -> String {
    hex::encode(s.as_bytes())
}

pub fn hex_to_string(hex_str: &str) -> String {
    if hex_str.is_empty() {
        return String::new();
    }
    match hex::decode(hex_str) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => String::new(),
    }
}