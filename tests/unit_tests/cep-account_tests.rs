use circular_enterprise_apis::account::Account;
use circular_enterprise_apis::NetworkConfig;
use circular_enterprise_apis::error::AccountError;
use std::env;
use mockito::{Server, Mock};
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

#[test]
fn test_account_initialization() {
    let account = Account::new();
    assert!(account.address.is_none());
    assert!(account.public_key.is_none());
    assert!(account.info.is_none());
    assert!(!account.version.is_empty());
    assert!(account.last_error.is_empty());
    assert_eq!(account.nonce, 0);
    assert!(account.latest_tx_id.is_empty());
}

#[test]
fn test_account_open() {
    let mut account = Account::new();
    
    // Test valid address
    let valid_address = "0x1234567890abcdef";
    assert!(account.open(valid_address).is_ok());
    assert_eq!(account.address, Some(valid_address.to_string()));
    
    // Test invalid address
    let mut account = Account::new();
    let result = account.open("");
    assert!(matches!(result, Err(AccountError::InvalidAddress(_))));
}

#[test]
fn test_account_close() {
    let mut account = Account::new();
    account.open("0x1234567890abcdef").unwrap();
    account.close();
    
    assert!(account.address.is_none());
    assert!(account.public_key.is_none());
    assert!(account.info.is_none());
    assert_eq!(account.nonce, 0);
    assert!(account.latest_tx_id.is_empty());
}

#[test]
fn test_sign_data() {
    let mut account = Account::new();
    account.open("0x1234567890abcdef").unwrap();
    
    let test_data = "test data";
    let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    // Test successful signing
    let signature = account.sign_data(test_data, private_key);
    assert!(signature.is_ok());
    
    // Test signing with different data produces different signatures
    let signature1 = account.sign_data("data1", private_key).unwrap();
    let signature2 = account.sign_data("data2", private_key).unwrap();
    assert_ne!(signature1, signature2);
    
    // Test signing with different private keys produces different signatures
    let private_key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let signature3 = account.sign_data(test_data, private_key2).unwrap();
    assert_ne!(signature1, signature3);
    
    // Test signing without opening account
    let mut closed_account = Account::new();
    let result = closed_account.sign_data(test_data, private_key);
    assert!(matches!(result, Err(AccountError::AccountNotOpen)));
}

#[test]
fn test_invalid_private_key() {
    let mut account = Account::new();
    account.open("0x1234567890abcdef").unwrap();
    
    let invalid_private_key = "invalid_key";
    let result = account.sign_data("test data", invalid_private_key);
    assert!(matches!(result, Err(AccountError::InvalidPrivateKey(_))));
}

// Helper function to generate test certificates of specific sizes
fn generate_certificate_with_size(size_bytes: usize) -> String {
    "A".repeat(size_bytes)
}

// Helper function to setup mock server and configure account
async fn setup_mock_account() -> (Server, Account) {
    let mut server = Server::new();
    let mut account = Account::new();
    account.open("0x1234567890abcdef").unwrap();
    
    // Configure account to use mock server
    account.network.set_nag_url(&server.url());
    account.network.set_network_node("test");
    
    (server, account)
}

#[tokio::test]
async fn test_update_account() {
    let (mut server, mut account) = setup_mock_account().await;
    
    // Mock successful response
    let mock_response = json!({
        "result": 200,
        "response": {
            "Nonce": 42
        }
    });
    
    let _m = server.mock("POST", "/Circular_GetWalletNonce_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.update_account().await;
    assert!(result.is_ok());
    assert_eq!(account.nonce, 43); // Nonce should be incremented by 1
}

#[tokio::test]
async fn test_update_account_error() {
    let (mut server, mut account) = setup_mock_account().await;
    
    // Mock error response
    let mock_response = json!({
        "result": 400,
        "response": null
    });
    
    let _m = server.mock("POST", "/Circular_GetWalletNonce_test")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.update_account().await;
    assert!(matches!(result, Err(AccountError::InvalidResponseFormat(_))));
}

#[tokio::test]
async fn test_update_account_not_open() {
    let mut account = Account::new();
    let result = account.update_account().await;
    assert!(matches!(result, Err(AccountError::AccountNotOpen)));
}

#[tokio::test]
async fn test_submit_certificate() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let test_data = "test certificate data";
    let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    // Mock successful response
    let mock_response = json!({
        "result": 200,
        "response": {
            "certificateId": "test-cert-id-123"
        }
    });
    
    let _m = server.mock("POST", "/Circular_AddTransaction_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.submit_certificate(test_data, private_key).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response["result"], 200);
    assert!(response["response"]["certificateId"].is_string());
}

#[tokio::test]
async fn test_submit_certificate_error() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let test_data = "test certificate data";
    let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    // Mock error response
    let mock_response = json!({
        "result": 400,
        "response": null
    });
    
    let _m = server.mock("POST", "/Circular_AddTransaction_test")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.submit_certificate(test_data, private_key).await;
    assert!(result.is_ok()); // The function returns Ok even for error responses
    let response = result.unwrap();
    assert_eq!(response["result"], 400);
}

#[tokio::test]
async fn test_submit_certificates_of_various_sizes() {
    let (mut server, mut account) = setup_mock_account().await;
    let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    
    let sizes = [1024, 2048, 5120]; // 1KB, 2KB, 5KB
    
    for size in sizes {
        let cert_data = generate_certificate_with_size(size);
        
        // Mock successful response for each size
        let mock_response = json!({
            "result": 200,
            "response": {
                "certificateId": format!("test-cert-id-{}", size)
            }
        });
        
        let _m = server.mock("POST", "/Circular_AddTransaction_test")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response.to_string())
            .create();
        
        let result = account.submit_certificate(&cert_data, private_key).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response["result"], 200);
        assert!(response["response"]["certificateId"].is_string());
    }
}

#[tokio::test]
async fn test_get_transaction() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let block_num = 123;
    let tx_id = "0xabcdef1234567890";
    
    // Mock successful response
    let mock_response = json!({
        "Result": 200,
        "Response": {
            "Status": "Confirmed",
            "BlockID": block_num,
            "TxID": tx_id
        }
    });
    
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.get_transaction(block_num, tx_id).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response["Result"], 200);
    assert_eq!(response["Response"]["Status"], "Confirmed");
    assert_eq!(response["Response"]["BlockID"], block_num);
    assert_eq!(response["Response"]["TxID"], tx_id);
}

#[tokio::test]
async fn test_get_transaction_error() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let block_num = 123;
    let tx_id = "0xabcdef1234567890";
    
    // Mock error response
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(500)
        .with_header("content-type", "application/json")
        .create();
    
    let result = account.get_transaction(block_num, tx_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_transaction_by_id() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let tx_id = "0xabcdef1234567890";
    let start_block = 100;
    let end_block = 200;
    
    // Mock successful response
    let mock_response = json!({
        "Result": 200,
        "Response": {
            "Status": "Confirmed",
            "BlockID": 150,
            "TxID": tx_id
        }
    });
    
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.get_transaction_by_id(tx_id, start_block, end_block).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response["Result"], 200);
    assert_eq!(response["Response"]["Status"], "Confirmed");
}

#[tokio::test]
async fn test_get_transaction_by_id_not_found() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let tx_id = "0xabcdef1234567890";
    let start_block = 100;
    let end_block = 200;
    
    // Mock "Transaction Not Found" response
    let mock_response = json!({
        "Result": 200,
        "Response": "Transaction Not Found"
    });
    
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();
    
    let result = account.get_transaction_by_id(tx_id, start_block, end_block).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response["Result"], 200);
    assert_eq!(response["Response"], "Transaction Not Found");
}

#[tokio::test]
async fn test_get_transaction_outcome_success() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let tx_id = "0xabcdef1234567890";
    
    // First mock: Transaction Not Found
    let mock_not_found = json!({
        "Result": 200,
        "Response": "Transaction Not Found"
    });
    
    // Second mock: Transaction Found and Confirmed
    let mock_confirmed = json!({
        "Result": 200,
        "Response": {
            "Status": "Confirmed",
            "BlockID": 150,
            "TxID": tx_id
        }
    });
    
    let _m1 = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_not_found.to_string())
        .create();
    
    let _m2 = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_confirmed.to_string())
        .create();
    
    // Set a short interval for testing
    account.set_interval_sec(1);
    
    let result = account.get_transaction_outcome(tx_id, 5).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response["Status"], "Confirmed");
    assert_eq!(response["TxID"], tx_id);
}

#[tokio::test]
async fn test_get_transaction_outcome_timeout() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let tx_id = "0xabcdef1234567890";
    
    // Mock: Always return Transaction Not Found
    let mock_not_found = json!({
        "Result": 200,
        "Response": "Transaction Not Found"
    });
    
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_not_found.to_string())
        .create();
    
    // Set a short interval and timeout for testing
    account.set_interval_sec(1);
    
    let result = account.get_transaction_outcome(tx_id, 2).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Timeout exceeded");
}

#[tokio::test]
async fn test_get_transaction_outcome_error() {
    let (mut server, mut account) = setup_mock_account().await;
    
    let tx_id = "0xabcdef1234567890";
    
    // Mock: Network error
    let _m = server.mock("POST", "/Circular_GetTransactionbyID_test")
        .with_status(500)
        .with_header("content-type", "application/json")
        .create();
    
    // Set a short interval for testing
    account.set_interval_sec(1);
    
    let result = account.get_transaction_outcome(tx_id, 5).await;
    assert!(result.is_err());
} 