use crate::{LIB_VERSION, string_to_hex, hex_to_string};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CCertificate {
    data: Option<String>,
    previous_tx_id: Option<String>,
    previous_block: Option<String>,
    version: String,
}

impl CCertificate {
    pub(crate) fn new() -> Self {
        Self {
            data: None,
            previous_tx_id: None,
            previous_block: None,
            version: LIB_VERSION.to_string(),
        }
    }

    /// Sets the certificate data
    pub(crate) fn set_data(&mut self, data: &str) {
        self.data = Some(string_to_hex(data));
    }

    /// Gets the certificate data
    pub(crate) fn get_data(&self) -> Option<String> {
        self.data.as_ref().and_then(|hex| hex_to_string(hex).ok())
    }

    /// Returns the certificate in JSON format
    pub(crate) fn get_json_certificate(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Returns the certificate size in bytes
    pub(crate) fn get_certificate_size(&self) -> usize {
        self.get_json_certificate().as_bytes().len()
    }
} 