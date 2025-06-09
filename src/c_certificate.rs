// FILE: src/c_certificate.rs

use crate::helper;
use crate::error::{Result, Error};
use serde::Serialize;

// This struct must be public to be used by lib.rs and tests
#[derive(Debug, Default)]
pub struct CCertificate {
    data: Option<String>,
    previous_tx_id: Option<String>,
    previous_block: Option<String>,
}

// This struct is only used inside this module, so it can remain private
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateJson<'a> {
    data: String,
    previous_tx_id: Option<&'a str>,
    previous_block: Option<&'a str>,
    version: &'static str,
}

// The implementation block for the public struct
impl CCertificate {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_data(&mut self, data: &str) {
        self.data = Some(helper::string_to_hex(data));
    }

    pub fn get_data(&self) -> String {
        self.data.as_ref().map_or_else(|| "".to_string(), |d| helper::hex_to_string(d))
    }

    pub fn get_json_certificate(&self) -> Result<String> {
        let cert_json = CertificateJson {
            data: self.get_data(),
            previous_tx_id: self.previous_tx_id.as_deref(),
            previous_block: self.previous_block.as_deref(),
            version: helper::LIB_VERSION,
        };
        serde_json::to_string(&cert_json).map_err(Error::Json)
    }

    pub fn get_certificate_size(&self) -> usize {
        self.get_json_certificate().map_or(0, |s| s.len())
    }

    pub fn get_previous_tx_id(&self) -> Option<&str> {
        self.previous_tx_id.as_deref()
    }

    pub fn set_previous_tx_id(&mut self, previous_tx_id: String) {
        self.previous_tx_id = Some(previous_tx_id);
    }

    pub fn get_previous_block(&self) -> Option<&str> {
        self.previous_block.as_deref()
    }

    pub fn set_previous_block(&mut self, previous_block: String) {
        self.previous_block = Some(previous_block);
    }
}