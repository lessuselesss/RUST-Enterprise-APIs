use circular_enterprise_apis::{self, CEPAccount, CCertificate};
use std::env;
use once_cell::sync::Lazy;
use mockito::ServerGuard;
use serde_json::Value;
use reqwest::blocking::Client;
use std::sync::Arc;

mod test_setup {
    use once_cell::sync::Lazy;
    use mockito::ServerGuard;
    use std::env;
    use reqwest::blocking::Client;
    use std::time::Duration;

    pub static MOCKITO_SERVER: Lazy<ServerGuard> = Lazy::new(|| {
        let server = mockito::start();
        println!("mockito server started at: {}", server.address());
        server
    });

    pub fn get_mockito_client() -> Arc<Client> {
        let server = Lazy::force(&MOCKITO_SERVER);
        let mockito_url = format!("http://{}", server.address());

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .proxy(reqwest::Proxy::http(&mockito_url).expect("Failed to create HTTP proxy"))
            .proxy(reqwest::Proxy::https(&mockito_url).expect("Failed to create HTTPS proxy"))
            .build()
            .expect("Failed to build reqwest client with mockito proxy");
        
        Arc::new(client)
    }

    pub fn get_live_client() -> Arc<Client> {
        env::remove_var("http_proxy");
        env::remove_var("https_proxy");
        env::remove_var("all_proxy");
        env::remove_var("no_proxy");
        env::remove_var("HTTP_PROXY");
        env::remove_var("HTTPS_PROXY");
        env::remove_var("ALL_PROXY");
        env::remove_var("NO_PROXY");

        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .no_system_proxy()
            .build()
            .expect("Failed to build live HTTP client");
        Arc::new(client)
    }
}

// Constants for testing signatures/IDs
const MOCK_PRIVATE_KEY: &str = "0x8a20baa40c45dc5055aeb26197c203e576ef389d9acb171bd62da11dc5ad72b2";
const MOCK_ADDRESS: &str = "0x1234567890abcdef1234567890abcdef12345678";

#[test]
fn test_c_certificate_initialization() {
    let certificate = circular_enterprise_apis::CCertificate::new();
    assert_eq!(certificate.get_data(), "".to_string());
    assert!(certificate.get_previous_tx_id().is_none());
    assert!(certificate.get_previous_block().is_none());
}

#[test]
fn test_c_certificate_set_get_data_simple_string() {
    let mut certificate = circular_enterprise_apis::CCertificate::new();
    let original_data = "another test";
    certificate.set_data(original_data);
    assert_eq!(certificate.get_data(), original_data.to_string());
}

#[test]
fn test_c_certificate_get_data_empty_or_null() {
    let mut certificate = circular_enterprise_apis::CCertificate::new();
    assert_eq!(certificate.get_data(), "".to_string());

    certificate.set_data("");
    assert_eq!(certificate.get_data(), "".to_string());
}

#[test]
fn test_helper_hex_to_string_0x_prefix() {
    assert_eq!(circular_enterprise_apis::helper::hex_to_string("0x"), "".to_string());
}

#[test]
fn test_c_certificate_set_get_data_unicode() {
    let mut certificate = circular_enterprise_apis::CCertificate::new();
    let unicode_data = "你好世界 😊";
    certificate.set_data(unicode_data);
    assert_eq!(certificate.get_data(), unicode_data.to_string());
}

#[test]
fn test_c_certificate_get_json_certificate() -> circular_enterprise_apis::error::Result<()> {
    let mut certificate = circular_enterprise_apis::CCertificate::new();
    let test_data = "json test";
    certificate.set_data(test_data);
    certificate.set_previous_tx_id("tx123".to_string());
    certificate.set_previous_block("block456".to_string());

    let json_cert = certificate.get_json_certificate()?;
    let parsed_cert: serde_json::Value = serde_json::from_str(&json_cert)?;

    let expected_hex_data = circular_enterprise_apis::helper::string_to_hex(test_data);

    let mut expected_map = serde_json::Map::new();
    expected_map.insert("data".to_string(), serde_json::Value::String(expected_hex_data));
    expected_map.insert("previousTxID".to_string(), serde_json::Value::String("tx123".to_string()));
    expected_map.insert("previousBlock".to_string(), serde_json::Value::String("block456".to_string()));
    expected_map.insert("version".to_string(), serde_json::Value::String(circular_enterprise_apis::helper::LIB_VERSION.to_string()));

    assert_eq!(parsed_cert, serde_json::Value::Object(expected_map));
    Ok(())
}

#[test]
fn test_c_certificate_get_certificate_size() -> circular_enterprise_apis::error::Result<()> {
    let mut certificate = circular_enterprise_apis::CCertificate::new();
    let test_data = "size test";
    certificate.set_data(test_data);
    certificate.set_previous_tx_id("txIDForSize".to_string());
    certificate.set_previous_block("blockIDForSize".to_string());

    let json_string = certificate.get_json_certificate()?;
    let expected_size = json_string.len(); // Rust string len is in bytes for UTF-8

    assert_eq!(certificate.get_certificate_size(), expected_size);
    Ok(())
}

#[test]
fn test_cep_account_initialization() {
    let account = circular_enterprise_apis::CEPAccount::new();
    assert!(account.get_address().is_none());
    assert_eq!(account.get_nag_url(), circular_enterprise_apis::helper::DEFAULT_NAG.to_string());
    assert_eq!(account.get_network_node(), "".to_string());
    assert_eq!(account.get_blockchain(), circular_enterprise_apis::helper::DEFAULT_CHAIN.to_string());
    assert!(account.get_latest_tx_id().is_none());
    assert_eq!(account.get_nonce(), 0);
}

#[test]
fn test_cep_account_open() -> circular_enterprise_apis::error::Result<()> {
    let mut account = circular_enterprise_apis::CEPAccount::new();
    let mock_address = "0x1234567890abcdef1234567890abcdef12345678";
    account.open(mock_address)?;
    assert_eq!(account.get_address(), Some(mock_address.to_string()));
    Ok(())
}

#[test]
fn test_cep_account_open_invalid_address_format() {
    let mut account = circular_enterprise_apis::CEPAccount::new();
    let result = account.open(""); // Node.js throws for null/invalid types; Rust `open` checks for empty string
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        circular_enterprise_apis::error::Error::InvalidInput("Address cannot be empty".to_string()).to_string()
    );
    assert!(account.get_address().is_none());
}

#[test]
fn test_cep_account_close() {
    let mut account = circular_enterprise_apis::CEPAccount::new();
    // Open the account and set some properties to non-default values
    account.open("0x1234567890abcdef1234567890abcdef12345678").expect("Failed to open account");
    account.set_blockchain("0xnewchain".to_string());
    account.set_network_node("testnode".to_string());
    account.set_nag_url("http://custom.nag".to_string());

    // Close the account
    account.close();

    // Verify properties are reset to defaults
    assert!(account.get_address().is_none());
    assert_eq!(account.get_nag_url(), circular_enterprise_apis::helper::DEFAULT_NAG.to_string());
    assert_eq!(account.get_network_node(), "".to_string());
    assert_eq!(account.get_blockchain(), circular_enterprise_apis::helper::DEFAULT_CHAIN.to_string());
    assert!(account.get_latest_tx_id().is_none());
    assert_eq!(account.get_nonce(), 0);
}

#[test]
fn test_cep_account_set_blockchain() {
    let mut account = circular_enterprise_apis::CEPAccount::new();
    let new_chain = "0xmynewchain";
    account.set_blockchain(new_chain.to_string());
    assert_eq!(account.get_blockchain(), new_chain.to_string());
}

#[test]
fn test_cep_account_set_network_success() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();
    
    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());

    let expected_mainnet_url = "https://mainnet-nag.circularlabs.io/API/";
    let _m1 = mockito::mock("GET", "/network/getNAG")
        .match_query(mockito::Matcher::UrlEncoded("network".into(), "mainnet".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"status":"success","url":"{}"}}"#, expected_mainnet_url))
        .create();

    let network_url = account.set_network("mainnet")?;
    assert_eq!(account.get_nag_url(), expected_mainnet_url.to_string());
    assert_eq!(network_url, expected_mainnet_url.to_string());
    _m1.assert();

    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());

    let expected_testnet_url = "https://testnet-nag.circularlabs.io/API/";
    let _m2 = mockito::mock("GET", "/network/getNAG")
        .match_query(mockito::Matcher::UrlEncoded("network".into(), "testnet".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(r#"{{"status":"success","url":"{}"}}"#, expected_testnet_url))
        .create();

    let network_url = account.set_network("testnet")?;
    println!("Connected to testnet: {}", network_url);

    // 3. Update account to get nonce
    account.update_account()?;
    assert_eq!(account.get_nonce(), 6);
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_update_account_api_error() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();

    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());
    let mock_address = "0x1234567890abcdef1234567890abcdef12345678";
    account.open(mock_address)?;
    let initial_nonce = account.get_nonce();

    let mock_api_response = r#"{ "Result": 400, "Message": "Bad Request" }"#;
    let _m = mockito::mock("POST", "/NAG.php?cep=Circular_GetWalletNonce_")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_api_response)
        .create();

    let result = account.update_account();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        circular_enterprise_apis::error::Error::ApiError("Failed to update account, API result: 400".to_string()).to_string()
    );
    assert_eq!(account.get_nonce(), initial_nonce);
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_update_account_network_error() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();

    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());
    let mock_address = "0x1234567890abcdef1234567890abcdef12345678";
    account.open(mock_address)?;
    let initial_nonce = account.get_nonce();

    let _m = mockito::mock("POST", "/NAG.php?cep=Circular_GetWalletNonce_")
        .expect(1)
        .with_status(500)
        .create();

    let result = account.update_account();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("status: 500"));
    assert_eq!(account.get_nonce(), initial_nonce);
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_update_account_not_open() {
    let mut account = circular_enterprise_apis::CEPAccount::new();
    let result = account.update_account();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        circular_enterprise_apis::error::Error::AccountNotOpen.to_string()
    );
    
    println!("Submitting certificate: {}", certificate_data);
    account.submit_certificate(&certificate_data, &private_key)?;
    
    // 5. Get transaction ID
    let tx_id = account.get_latest_tx_id().expect("Failed to get transaction ID after submission");
    println!("Transaction ID: {}", tx_id);
    
    // 6. Wait for transaction outcome
    println!("Waiting for transaction to be processed...");
    let outcome = account.get_transaction_outcome(tx_id, 120, 5)?;
    assert_eq!(outcome.result, 200, "Transaction should be successful");
    println!("Transaction processed successfully: {:?}", outcome.response);

    // To match Node.js sha256(str), we need to ensure the `str` is exactly the same.
    // However, the `Timestamp` is dynamically generated. For a precise mock,
    // we'd either need to control the timestamp or match loosely.
    // For now, let's generate the signature based on a mock timestamp for the matcher.
    // For a real test, the timestamp would ideally be injected or mocked more robustly.

    // Given the `submit_certificate` function's current behavior, we can't easily
    // pre-calculate the exact `ID` or `Signature` for the mock's `match_body`
    // without duplicating some internal logic or making assumptions about `Timestamp`.
    // The Node.js test `(body) => { ... expect(body.From).to.equal(cleanedMockAddress); ... return true; }`
    // is a more flexible matcher.

    // A more robust way in Rust is to use a custom matcher if we can't pre-calculate.
    // For simplicity, let's start with a less strict matcher or match known constant fields.
    // The `mockito` crate allows `match_body` with `Matcher::Json` and `serde_json::json!`.

    // We'll mock the response, and then verify the request body content using `_m.assert()`.
    // For now, I'll match the static parts of the request body and rely on `assert` for the dynamic parts.

    let mock_api_response = r#"{ "Result": 200, "TxID": "newTxID789", "Message": "Transaction Added" }"#;

    let _m = mockito::mock("POST", "/NAG.php?cep=Circular_AddTransaction_")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_api_response)
        // More specific body matching can be added here if needed,
        // but it's hard to match dynamic fields like ID and Timestamp
        // without duplicating the hashing logic or mocking time.
        // For now, we'll verify key fields after the call.
        .create();

    let submit_result = account.submit_certificate(cert_data, MOCK_PRIVATE_KEY)?;

    assert_eq!(submit_result["Result"], 200);
    assert_eq!(submit_result["TxID"], "newTxID789");
    assert_eq!(submit_result["Message"], "Transaction Added");
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_submit_certificate_network_failure() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();
    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());
    account.open(MOCK_ADDRESS)?;
    account.set_nonce(1);

    let cert_data = "my certificate data";

    let _m = mockito::mock("POST", "/NAG.php?cep=Circular_AddTransaction_")
        .with_status(500)
        .with_body("Simulated network error")
        .create();

    let result = account.submit_certificate(cert_data, MOCK_PRIVATE_KEY);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("status: 500"));
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_submit_certificate_http_error_status() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();
    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());
    account.open(MOCK_ADDRESS)?;
    account.set_nonce(1);

    let cert_data = "my certificate data";

    let _m = mockito::mock("POST", "/NAG.php?cep=Circular_AddTransaction_")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{ "message": "Internal Server Error" }"#)
        .create();

    let result = account.submit_certificate(cert_data, MOCK_PRIVATE_KEY);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("status: 500")); // Check for HTTP status error
    _m.assert();

    Ok(())
}

#[test]
fn test_cep_account_submit_certificate_not_open() {
    let account = circular_enterprise_apis::CEPAccount::new(); // Not opened
    let cert_data = "my certificate data";

    let result = account.submit_certificate(cert_data, MOCK_PRIVATE_KEY);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        circular_enterprise_apis::error::Error::AccountNotOpen.to_string()
    );
}

#[test]
fn test_cep_account_get_transaction_outcome_confirmed_quickly() -> circular_enterprise_apis::error::Result<()> {
    let mockito_client = test_setup::get_mockito_client();
    let mut account = circular_enterprise_apis::CEPAccount::new_with_client(mockito_client.clone());
    account.open(MOCK_ADDRESS)?;

    let tx_id = "pollTxID456";
    let timeout_sec = 3;
    let interval_sec = 1;

    let confirmed_response_payload = serde_json::json!({
        "id": tx_id,
        "Status": "Confirmed",
        "data": "some data",
        "BlockID": "block123" // Added BlockID for realism, though not explicitly in Node.js mock response for this test
    });
    let confirmed_response = serde_json::json!({ "Result": 200, "Response": confirmed_response_payload });

    let tx_data = account.get_transaction(block_id, tx_id)?;
    assert_eq!(tx_data.result, 200, "Direct transaction query should be successful");
    println!("Transaction verified in block: {}", block_id);
    println!("Transaction details: {:?}", tx_data.response);

    // Sequence of mocks: Not Found, Confirmed
    let _m1 = mockito::mock("POST", "/NAG.php?cep=Circular_GetTransactionbyID_")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(not_found_response.to_string())
        .expect(1)
        .create();
    let _m2 = mockito::mock("POST", "/NAG.php?cep=Circular_GetTransactionbyID_")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(confirmed_response.to_string())
        .expect(1)
        .create();

    let outcome = account.get_transaction_outcome(tx_id, timeout_sec, interval_sec)?;
    assert_eq!(outcome.result, 200);
    assert_eq!(outcome.response, confirmed_response_payload);
    _m1.assert();
    _m2.assert();

    Ok(())
}