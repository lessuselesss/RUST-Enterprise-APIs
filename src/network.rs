use serde::{Serialize, Deserialize};
use crate::{DEFAULT_NAG, DEFAULT_CHAIN, NETWORK_URL};

#[derive(Debug, Clone)]
pub(crate) struct NetworkConfig {
    nag_url: String,
    network_node: String,
    blockchain: String,
    interval_sec: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            nag_url: DEFAULT_NAG.to_string(),
            network_node: String::new(),
            blockchain: DEFAULT_CHAIN.to_string(),
            interval_sec: 2,
        }
    }
}

impl NetworkConfig {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_network_node(&mut self, node: &str) {
        self.network_node = node.to_string();
    }

    pub(crate) fn set_blockchain(&mut self, chain: &str) {
        self.blockchain = chain.to_string();
    }

    pub(crate) fn set_interval(&mut self, seconds: u64) {
        self.interval_sec = seconds;
    }

    pub(crate) fn get_nag_url(&self) -> &str {
        &self.nag_url
    }

    pub(crate) fn get_network_node(&self) -> &str {
        &self.network_node
    }

    pub(crate) fn get_blockchain(&self) -> &str {
        &self.blockchain
    }

    pub(crate) fn get_interval(&self) -> u64 {
        self.interval_sec
    }
} 