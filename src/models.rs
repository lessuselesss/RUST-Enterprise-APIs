use serde::{Deserialize, Serialize};

// For 1.6 setNetwork
#[derive(Deserialize, Debug)]
pub struct NagResponse {
    pub status: String,
    pub nag: Option<String>,
    pub message: Option<String>,
}

// For 1.7 updateAccount
#[derive(Serialize, Debug)]
pub struct GetNonceRequest<'a> {
    #[serde(rename = "Address")]
    pub address: &'a str,
    #[serde(rename = "Blockchain")]
    pub blockchain: &'a str,
    #[serde(rename = "Version")]
    pub version: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct GetNonceResponse {
    #[serde(rename = "Result")]
    pub result: i32,
    #[serde(rename = "Nonce")]
    pub nonce: Option<u64>,
}

// For 1.10 submitCertificate
#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitTxPayload<'a> {
    pub data: &'a str,
    pub previous_tx_id: Option<&'a str>,
    pub previous_block: Option<&'a str>,
    pub code_version: &'a str,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitTxRequest<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub nonce: u64,
    pub r#type: i32,
    pub blockchain: &'a str,
    pub payload: SubmitTxPayload<'a>,
    pub signature: &'a str,
    pub version: &'a str,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SubmitTxSuccessResponse {
    #[serde(rename = "TxID")]
    pub tx_id: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SubmitTxResponse {
    Success {
        #[serde(rename = "Result")]
        result: i32,
        #[serde(rename = "Response")]
        response: SubmitTxSuccessResponse,
    },
    Error {
        #[serde(rename = "Result")]
        result: i32,
        #[serde(rename = "Response")]
        response: String,
    },
}


// For 1.9 & 1.11 getTransaction / getTransactionOutcome
#[derive(Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GetTxRequest<'a> {
    #[serde(rename = "ID")]
    pub id: &'a str,
    pub start_block: u64,
    pub end_block: u64,
    pub blockchain: &'a str,
    pub version: &'a str,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TransactionData {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "BlockID")]
    pub block_id: String,
    #[serde(rename = "BroadcastFee")]
    pub broadcast_fee: f64,
    #[serde(rename = "DeveloperFee")]
    pub developer_fee: f64,
    #[serde(rename = "From")]
    pub from: String,
    #[serde(rename = "GasLimit")]
    pub gas_limit: f64,
    #[serde(rename = "Instructions")]
    pub instructions: i32,
    #[serde(rename = "NagFee")]
    pub nag_fee: f64,
    #[serde(rename = "NodeID")]
    pub node_id: String,
    #[serde(rename = "Nonce")]
    pub nonce: String,
    #[serde(rename = "OSignature")]
    pub o_signature: String,
    #[serde(rename = "Payload")]
    pub payload: String,
    #[serde(rename = "ProcessingFee")]
    pub processing_fee: f64,
    #[serde(rename = "ProtocolFee")]
    pub protocol_fee: f64,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
    #[serde(rename = "To")]
    pub to: String,
    #[serde(rename = "Type")]
    pub r#type: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum GetTxResponse {
    Found {
        #[serde(rename = "Result")]
        result: i32,
        #[serde(rename = "Response")]
        response: TransactionData,
        #[serde(rename = "Node")]
        node: String,
    },
    NotFound {
        #[serde(rename = "Result")]
        result: i32,
        #[serde(rename = "Response")]
        response: String, // e.g., "Transaction Not Found"
        #[serde(rename = "Node")]
        node: String,
    },
}