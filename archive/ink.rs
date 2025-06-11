use cep_sdk::c_certificate::CCertificate;
use cep_sdk::cep_account::CEPAccount;
use rstest::*;
use tokio;
use assert_matches::assert_matches;
use mockito::Server;

// Import the necessary modules from your library
use cep_sdk::models::{SubmitTxResponse, GetTxResponse};
use cep_sdk::error::CEPError;

mod common; // For shared setup/teardown if needed later

#[cfg(test)]
#[allow(unused_variables)] // Temporarily allow unused variables for placeholders
mod c_certificate_tests {
    use super::*;

    // Helper function to match JavaScript hex encoding
    fn js_style_hex_encode(data: &str) -> String {
        let mut hex = String::new();
        for byte in data.as_bytes() {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    // Environment Variable Setup
    #[test]
    fn should_have_all_required_env_variables_for_testnet() {
        // This test would typically check for the presence of specific environment variables.
        // For now, it's a placeholder.
        println!("TODO: Implement environment variable check");
    }

    // C_CERTIFICATE Class
    #[test]
    fn should_initialize_with_default_values() {
        let cert = CCertificate::new();
        assert_eq!(cert.get_data(), ""); // Default data is an empty string after hex conversion
        assert_eq!(cert.get_type(), "");
        assert_eq!(cert.get_issuer(), "");
        assert_eq!(cert.get_uri(), "");
        assert_eq!(cert.get_hash(), ""); // Default hash will be for empty strings
        assert_eq!(cert.get_signature(), "");
    }

    // setData method
    #[test]
    fn set_data_should_store_data_as_hex() {
        let mut cert = CCertificate::new();
        let test_data = "Hello World!";
        cert.set_data(test_data);
        
        // Verify hex encoding matches JavaScript implementation
        let expected_hex = js_style_hex_encode(test_data);
        assert_eq!(cert.data, expected_hex);
    }

    // getData method
    #[test]
    fn get_data_should_retrieve_original_data_for_simple_strings() {
        let mut cert = CCertificate::new();
        let test_data = "Simple string";
        cert.set_data(test_data);
        assert_eq!(cert.get_data(), test_data);
    }

    #[test]
    fn get_data_should_return_empty_string_if_data_is_null_or_empty_hex() {
        let mut cert = CCertificate::new();
        cert.set_data(""); // Setting empty string should result in empty data
        assert_eq!(cert.get_data(), "");
        assert_eq!(cert.data, ""); // Verify hex is also empty
    }

    #[test]
    fn get_data_should_return_empty_string_if_data_is_0x() {
        let mut cert = CCertificate::new();
        cert.data = "0x".to_string();
        assert_eq!(cert.get_data(), "");
    }

    #[test]
    fn get_data_should_correctly_retrieve_multi_byte_unicode_data() {
        let mut cert = CCertificate::new();
        let unicode_data = "你好世界 👋"; // Chinese characters and an emoji
        cert.set_data(unicode_data);
        
        // Verify hex encoding matches JavaScript implementation
        let expected_hex = js_style_hex_encode(unicode_data);
        assert_eq!(cert.data, expected_hex);
        assert_eq!(cert.get_data(), unicode_data);
    }

    // getJSONCertificate method
    #[test]
    fn get_json_certificate_should_return_a_valid_json_string() {
        let mut cert = CCertificate::new();
        let test_data = "test";
        cert.set_data(test_data);
        cert.set_type("type");
        cert.set_issuer("issuer");
        cert.set_uri("uri");
        
        let json_str = cert.to_json_string().unwrap();
        println!("Generated JSON: {}", json_str); // Debug print
        let parsed_json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Verify hex encoding matches JavaScript implementation
        let expected_hex = js_style_hex_encode(test_data);

        assert!(parsed_json.is_object());
        assert_eq!(parsed_json["data"], expected_hex); // Verify hex without 0x prefix
        assert_eq!(parsed_json["type"], "type");
        assert_eq!(parsed_json["issuer"], "issuer");
        assert_eq!(parsed_json["uri"], "uri");
        assert_eq!(parsed_json["code_version"], "1.0.0-rust");
        assert!(parsed_json.get("hash").is_some());
        assert!(parsed_json.get("signature").is_some());
        assert!(parsed_json.get("previous_tx_id").is_some());
        assert!(parsed_json.get("previous_block").is_some());
    }

    // getCertificateSize method
    #[test]
    fn get_certificate_size_should_return_correct_byte_length() {
        let mut cert = CCertificate::new();
        let data = "This is some test data.";
        cert.set_data(data);
        cert.set_type("doc");
        cert.set_issuer("me");
        cert.set_uri("http://example.com/doc1");

        let expected_size = cert.to_json_string().unwrap().as_bytes().len(); // Use to_json_string
        assert_eq!(cert.get_certificate_size(), expected_size);
    }
}

#[cfg(test)]
mod cep_account_tests {
    use super::*;

    #[fixture]
    fn default_account() -> CEPAccount {
        CEPAccount::new()
    }

    // CEP_Account Class
    #[test]
    fn should_initialize_with_default_values() {
        let account = CEPAccount::new();
        assert_eq!(account.get_address(), "");
        assert_eq!(account.get_blockchain(), "Circular-Main-Public-Chain"); // Corrected default
        assert_eq!(account.get_network(), "");
        assert_eq!(account.get_public_key(), "");
        assert_eq!(account.get_private_key(), "");
        assert_eq!(account.get_nonce(), 0);
        assert!(!account.is_open());
    }

    // open method
    #[tokio::test]
    async fn open_should_set_the_account_address() {
        let mut account = CEPAccount::new();
        let address = "0x123abc"; // Example address
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.open(address, private_key).await.unwrap();
        assert_eq!(account.get_address(), address);
        assert!(account.is_open());
        assert_eq!(account.get_private_key(), private_key);
        assert!(!account.get_public_key().is_empty()); // Public key should be derived
    }

    #[tokio::test]
    #[should_panic(expected = "InvalidAddressFormat")]
    async fn open_should_throw_an_error_for_invalid_address_format() {
        let mut account = CEPAccount::new();
        let invalid_address = "invalid_address";
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.open(invalid_address, private_key).await.unwrap(); // Corrected call
    }

    // close method
    #[test]
    fn close_should_reset_account_properties_to_default() {
        let mut account = CEPAccount::new();
        // Simulate an open account using setters
        account.set_address("0x123");
        account.set_blockchain("some_chain");
        account.set_public_key("pub_key");
        account.set_private_key("priv_key");
        account.set_nonce(10);
        account.set_open(true); // Explicitly set open state for simulation

        account.close();

        assert_eq!(account.get_address(), "");
        assert_eq!(account.get_blockchain(), "Circular-Main-Public-Chain"); // Default blockchain
        assert_eq!(account.get_network(), ""); // Default network
        assert_eq!(account.get_public_key(), "");
        assert_eq!(account.get_private_key(), "");
        assert_eq!(account.get_nonce(), 0);
        assert!(!account.is_open());
    }

    // setBlockchain method
    #[test]
    fn set_blockchain_should_update_the_blockchain_property() {
        let mut account = CEPAccount::new();
        let blockchain_name = "ethereum";
        account.set_blockchain(blockchain_name);
        assert_eq!(account.get_blockchain(), blockchain_name);
    }

    // setNetwork method - these tests would require mocking HTTP requests or actual network calls
    // For now, focus on the property update and error handling logic.

    #[tokio::test]
    async fn set_network_should_update_nag_url_for_mainnet() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/network/getNAG?network=mainnet")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","nag":"http://127.0.0.1:1234/mainnet"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("mainnet").await.unwrap();
        assert_eq!(account.get_network(), "mainnet");
    }

    #[tokio::test]
    async fn set_network_should_update_nag_url_for_testnet() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/network/getNAG?network=testnet")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","nag":"http://127.0.0.1:1234/testnet"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url();
        account.set_network("testnet").await.unwrap();
        assert_eq!(account.get_network(), "testnet");
    }

    #[tokio::test]
    async fn set_network_should_update_nag_url_for_devnet() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/network/getNAG?network=devnet")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","nag":"http://127.0.0.1:1234/devnet"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("devnet").await.unwrap();
        assert_eq!(account.get_network(), "devnet");
    }

    #[tokio::test]
    async fn set_network_should_throw_an_error_if_network_request_fails() {
        // Mock a network error (e.g., connection refused)
        let mut server = Server::new();
        let _m = server.mock("GET", "/network/getNAG?network=invalid_network_that_will_fail")
            .expect(1) // Expect one call
            .with_status(500) // Simulate an internal server error or other failure
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        let result = account.set_network("invalid_network_that_will_fail").await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_));
    }

    #[tokio::test]
    async fn set_network_should_throw_an_error_if_api_response_indicates_failure() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/network/getNAG?network=mock_fail_api")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"error","message":"Mocked API error"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        let result = account.set_network("mock_fail_api").await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::ApiError { .. });
    }

    // updateAccount method - will require mocking HTTP calls

    #[tokio::test]
    async fn update_account_should_update_nonce_on_successful_api_call() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetWalletNonce_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":200,"nonce":123}"#)
            .create();

        let mut account = CEPAccount::new();
        // Mock account to be open and network set
        account.set_open(true);
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_address("0x123abc");
        account.set_private_key("0x1111111111111111111111111111111111111111111111111111111111111111");

        let _initial_nonce = account.get_nonce();
        let result = account.update_account().await;
        assert!(result.is_ok());
        assert_eq!(account.get_nonce(), 124); // Nonce should be updated (123 + 1)
    }

    #[tokio::test]
    async fn update_account_should_return_false_and_not_update_nonce_on_api_error() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetWalletNonce_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":500,"message":"Internal Server Error"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.set_open(true);
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_address("0x123abc");
        account.set_private_key("0x1111111111111111111111111111111111111111111111111111111111111111");

        let _initial_nonce = account.get_nonce();
        let result = account.update_account().await;
        assert!(result.is_err());
        assert_eq!(account.get_nonce(), _initial_nonce); // Nonce should not change
        assert_matches!(result.unwrap_err(), CEPError::ApiError { .. });
    }

    #[tokio::test]
    async fn update_account_should_return_false_on_network_error() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetWalletNonce_")
            .expect(1)
            .with_status(500) // Simulate a network error
            .create();

        let mut account = CEPAccount::new();
        account.set_open(true);
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_address("0x123abc");
        account.set_private_key("0x1111111111111111111111111111111111111111111111111111111111111111");

        let _initial_nonce = account.get_nonce();
        let result = account.update_account().await;
        assert!(result.is_err());
        assert_eq!(account.get_nonce(), _initial_nonce); // Nonce should not change
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_));
    }

    #[tokio::test]
    #[should_panic(expected = "Logic(\"Account is not open\")")] // Updated panic message
    async fn update_account_should_throw_an_error_if_account_is_not_open() {
        let mut account = CEPAccount::new();
        account.update_account().await.unwrap();
    }

    #[tokio::test]
    async fn update_account_should_return_false_if_response_is_malformed() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetWalletNonce_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"Invalid JSON"#) // Malformed JSON
            .create();

        let mut account = CEPAccount::new();
        account.set_open(true);
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_address("0x123abc");
        account.set_private_key("0x1111111111111111111111111111111111111111111111111111111111111111");

        let _initial_nonce = account.get_nonce();
        let result = account.update_account().await;
        assert!(result.is_err());
        assert_eq!(account.get_nonce(), _initial_nonce); // Nonce should not change
        assert_matches!(result.unwrap_err(), CEPError::DeserializationError(_));
    }

    // signData method
    #[tokio::test]
    #[should_panic(expected = "Logic(\"Account is not open\")")] // Updated panic message
    async fn sign_data_should_throw_an_error_if_account_is_not_open() {
        let account = CEPAccount::new();
        account.sign_data("some data", "dummy_private_key").unwrap();
    }

    #[tokio::test]
    async fn sign_data_should_produce_different_signatures_for_different_data() {
        let mut account = CEPAccount::new();
        let address = "0x123abc";
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.open(address, private_key).await.unwrap();

        let data1 = "first data";
        let data2 = "second data";

        let signature1 = account.sign_data(data1, private_key).unwrap(); // Corrected call
        let signature2 = account.sign_data(data2, private_key).unwrap(); // Corrected call

        assert_ne!(signature1, signature2);
        assert!(!signature1.is_empty());
        assert!(!signature2.is_empty());
    }

    #[tokio::test]
    async fn sign_data_should_produce_different_signatures_for_different_private_key() {
        let mut account1 = CEPAccount::new();
        let mut account2 = CEPAccount::new();
        let address = "0x123abc";
        let private_key1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let private_key2 = "0x2222222222222222222222222222222222222222222222222222222222222222";

        account1.open(address, private_key1).await.unwrap();
        account2.open(address, private_key2).await.unwrap();

        let data = "some data";

        let signature1 = account1.sign_data(data, private_key1).unwrap(); // Corrected call
        let signature2 = account2.sign_data(data, private_key2).unwrap(); // Corrected call

        assert_ne!(signature1, signature2);
        assert!(!signature1.is_empty());
        assert!(!signature2.is_empty());
    }

    // getTransaction and getTransactionbyID methods - will require mocking HTTP calls

    #[tokio::test]
    async fn get_transaction_by_id_should_fetch_a_transaction() { // Renamed test function
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":200,"tx":{"id":"tx123","status":"confirmed","block":10,"timestamp":1234567890,"data":"test_data"}}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap(); // Account needs to be open

        let tx_id = "tx123";
        let start_block = 1;
        let end_block = 1000;
        let result = account.get_transaction_by_id(tx_id, start_block, end_block).await;
        assert!(result.is_ok());
        if let Ok(GetTxResponse::Found { response, result: _ }) = result {
            assert_eq!(response.id, tx_id);
            assert_eq!(response.status, "confirmed");
            // Check block number in other_fields
            if let Some(block) = response.other_fields.get("block").and_then(|b| b.as_u64()) {
                assert_eq!(block, 10);
            } else {
                panic!("Block number not found in response");
            }
        } else {
            panic!("Expected successful transaction fetch.");
        }
    }

    #[tokio::test]
    async fn get_transaction_by_id_should_throw_on_network_error() { // Renamed test function
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTx_")
            .expect(1)
            .with_status(500) // Simulate a network error
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let result = account.get_transaction_by_id("mock_network_fail", 0, 0).await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_));
    }

    #[tokio::test]
    async fn get_transaction_by_id_should_fetch_a_transaction_within_a_block_range() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":200,"tx":{"id":"tx456","status":"confirmed","block":500,"timestamp":1234567890,"data":"test_data"}}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let tx_id = "tx456";
        let start_block = 1;
        let end_block = 1000;
        let result = account.get_transaction_by_id(tx_id, start_block, end_block).await;
        assert!(result.is_ok());
        if let Ok(GetTxResponse::Found { response, result: _ }) = result {
            assert_eq!(response.id, tx_id);
            assert_eq!(response.status, "confirmed");
            // Check block number in other_fields
            if let Some(block) = response.other_fields.get("block").and_then(|b| b.as_u64()) {
                assert!(block >= start_block && block <= end_block);
            } else {
                panic!("Block number not found in response");
            }
        } else {
            panic!("Expected successful transaction fetch within block range.");
        }
    }

    #[tokio::test]
    async fn get_transaction_by_id_should_handle_transaction_not_found() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":404,"message":"Transaction not found"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let result = account.get_transaction_by_id("not_found_tx", 1, 100).await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::TransactionNotFound);
    }

    #[tokio::test]
    async fn get_transaction_by_id_should_throw_on_network_error_specific_test() { // Renamed for clarity
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTx_")
            .expect(1)
            .with_status(500) // Simulate a network error
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let result = account.get_transaction_by_id("mock_network_fail_tx", 1, 100).await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_));
    }

    // submitCertificate method - will require mocking HTTP calls

    fn generate_certificate_with_size(size_bytes: usize) -> CCertificate {
        let mut cert = CCertificate::new();
        let base_data_char = 'a';
        let mut data = String::new();

        // Calculate how much data is needed to reach size_bytes
        // This is an approximation as JSON serialization adds overhead
        // A rough estimate: each character is 1 byte for ASCII, hex encoding doubles it.
        // Other fields like type, issuer, uri, hash, signature, etc., also contribute.
        // Let's assume a fixed overhead for other fields, and fill the rest with data.
        let estimated_overhead = cert.to_json_string().unwrap().len() - cert.data.len();
        let data_payload_size = size_bytes.saturating_sub(estimated_overhead);

        for _i in 0..data_payload_size {
            data.push(base_data_char);
        }
        
        cert.set_data(&data);
        cert.set_type("test_type");
        cert.set_issuer("test_issuer");
        cert.set_uri("http://example.com/test");
        cert
    }


    #[tokio::test]
    async fn submit_certificate_should_submit_successfully() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_SubmitTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":200,"txId":"mock_tx_id_123"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        let address = "0x123abc";
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.open(address, private_key).await.unwrap();

        let cert = CCertificate::new();
        let cert_json = cert.to_json_string().unwrap();
        let result = account.submit_certificate(&cert_json, private_key).await; // Corrected call
        assert!(result.is_ok());
        if let Ok(SubmitTxResponse::Success { response, .. }) = result {
            assert_eq!(response.tx_id, "mock_tx_id_123");
        } else {
            panic!("Certificate submission failed or returned unexpected response.");
        }
    }

    #[rstest(size_kb,
        case(1),
        case(2),
        case(5)
    )]
    #[tokio::test]
    async fn submit_certificate_should_submit_x_kb_certificate_successfully(size_kb: usize) {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_SubmitTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":200,"txId":"mock_tx_id_sized"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        let address = "0x123abc";
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.open(address, private_key).await.unwrap();

        let cert = generate_certificate_with_size(size_kb * 1024);
        let cert_json = cert.to_json_string().unwrap();
        let result = account.submit_certificate(&cert_json, private_key).await; // Corrected call
        assert!(result.is_ok());
        if let Ok(SubmitTxResponse::Success { response, .. }) = result {
            assert_eq!(response.tx_id, "mock_tx_id_sized");
        } else {
            panic!("Certificate submission failed or returned unexpected response for {}KB size.", size_kb);
        }
    }

    #[tokio::test]
    async fn submit_certificate_should_return_error_object_on_network_failure() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_SubmitTx_")
            .expect(1)
            .with_status(500) // Simulate a network error
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let cert = CCertificate::new();
        let cert_json = cert.to_json_string().unwrap();
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111"; // Dummy
        let result = account.submit_certificate(&cert_json, private_key).await;
        assert!(result.is_err());
        // Mocking framework would return a reqwest::Error
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_));
    }

    #[tokio::test]
    async fn submit_certificate_should_return_error_object_on_http_error_status() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_SubmitTx_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":500,"message":"Internal Server Error"}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let cert = CCertificate::new();
        let cert_json = cert.to_json_string().unwrap();
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111"; // Dummy
        let result = account.submit_certificate(&cert_json, private_key).await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::ApiError { .. });
    }

    #[tokio::test]
    #[should_panic(expected = "Logic(\"Account is not open\")")] // Updated panic message
    async fn submit_certificate_should_throw_an_error_if_account_is_not_open() {
        let account = CEPAccount::new();
        let cert = CCertificate::new();
        let cert_json = cert.to_json_string().unwrap();
        let private_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        account.submit_certificate(&cert_json, private_key).await.unwrap();
    }

    // getTransactionOutcome method - polling mechanism, requires careful mocking or real network

    #[tokio::test]
    async fn get_transaction_outcome_should_resolve_with_transaction_data_if_found_and_confirmed_quickly() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"quick_confirm_tx","status":"Confirmed","block":1,"timestamp":123}}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let tx_id = "quick_confirm_tx";
        let result = account.get_transaction_outcome(tx_id, 5).await; // 5 second timeout
        assert!(result.is_ok());
        let tx_data = result.unwrap();
        assert_eq!(tx_data.id, tx_id);
        assert_eq!(tx_data.status, "Confirmed");
    }

    #[tokio::test]
    async fn get_transaction_outcome_should_poll_and_resolve_when_transaction_is_confirmed_after_being_pending() {
        // Mock the first response as pending, then the second as confirmed
        let mut server = Server::new();
        let _m1 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"pending_then_confirm_tx","status":"Pending","block":0,"timestamp":0}}"#)
            .expect(1) // Expect this response once
            .create();

        let _m2 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"pending_then_confirm_tx","status":"Confirmed","block":1,"timestamp":123}}"#)
            .expect(1) // Expect this response once
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let tx_id = "pending_then_confirm_tx";
        let result = account.get_transaction_outcome(tx_id, 10).await; // 10 second timeout
        assert!(result.is_ok());
        let tx_data = result.unwrap();
        assert_eq!(tx_data.id, tx_id);
        assert_eq!(tx_data.status, "Confirmed");
    }

    #[tokio::test]
    async fn get_transaction_outcome_should_poll_and_resolve_when_transaction_is_confirmed_after_transaction_not_found() {
        // Mock the first response as not found, then the second as confirmed
        let mut server = Server::new();
        let _m1 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":404,"Response":"Transaction Not Found"}"#)
            .expect(1) // Expect this response once
            .create();

        let _m2 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"not_found_then_confirm_tx","status":"Confirmed","block":1,"timestamp":123}}"#)
            .expect(1) // Expect this response once
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let tx_id = "not_found_then_confirm_tx";
        let result = account.get_transaction_outcome(tx_id, 10).await;
        assert!(result.is_ok());
        let tx_data = result.unwrap();
        assert_eq!(tx_data.id, tx_id);
        assert_eq!(tx_data.status, "Confirmed");
    }

    #[tokio::test]
    async fn get_transaction_outcome_should_reject_if_get_transaction_by_id_call_fails_during_polling() {
        // Mock an initial successful response, then a network error for subsequent calls
        let mut server = Server::new();
        let _m1 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"polling_fail_tx","status":"Pending","block":0,"timestamp":0}}"#)
            .expect(1) // Expect this response once
            .create();

        let _m2 = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .expect(1)
            .with_status(500) // Simulate a network error
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let result = account.get_transaction_outcome("polling_fail_tx", 5).await;
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::NetworkError(_)); // Or other specific error from get_transaction_by_id
    }

    #[tokio::test]
    async fn get_transaction_outcome_should_reject_with_timeout_exceeded_if_polling_duration_exceeds_timeout_sec() {
        let mut server = Server::new();
        let _m = server.mock("POST", "/API/Circular_GetTransactionbyID_")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Result":200,"Response":{"ID":"timeout_tx","status":"Pending","block":0,"timestamp":0}}"#)
            .create();

        let mut account = CEPAccount::new();
        account.nag_url = server.url(); // Set NAG_URL to mock server URL
        account.set_network("testnet").await.unwrap();
        account.open("0x123abc", "private_key_dummy").await.unwrap();

        let result = account.get_transaction_outcome("timeout_tx", 1).await; // Short timeout
        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), CEPError::TimeoutExceeded);
    }
}

// TODO: Implement tests for Permissions and Live Network Integration as discussed in the .md file.
// These will likely require more complex setup, mocking, or actual network access. 