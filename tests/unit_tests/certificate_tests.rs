use circular_enterprise_apis::{Certificate, string_to_hex, hex_to_string};
use rstest::rstest;
use serde_json;

/// Helper function to verify certificate size is within acceptable range
fn verify_certificate_size(cert: &Certificate, expected_size: usize) -> bool {
    let actual_size = cert.get_certificate_size();
    let tolerance = 50; // Allow for some variation in JSON formatting
    actual_size >= expected_size && actual_size <= expected_size + tolerance
}

/// Helper function to generate a certificate with specific size
fn generate_certificate_with_size(size_bytes: usize) -> Certificate {
    let mut cert = Certificate::new();
    let data_size = size_bytes.saturating_sub(100); // Approximate JSON overhead
    let test_data = "x".repeat(data_size);
    cert.set_data(&test_data);
    cert
}

#[test]
fn test_certificate_initialization() {
    let cert = Certificate::new();
    assert!(cert.data.is_none());
    assert!(cert.previous_tx_id.is_none());
    assert!(cert.previous_block.is_none());
    assert_eq!(cert.version, "1.0.13");
}

#[test]
fn test_set_data_stores_as_hex() {
    let mut cert = Certificate::new();
    let test_data = "test data";
    cert.set_data(test_data);
    
    // Verify the data is stored as hex
    assert!(cert.data.is_some());
    let stored_hex = cert.data.as_ref().unwrap();
    let expected_hex = string_to_hex(test_data);
    assert_eq!(stored_hex, &expected_hex);
}

#[test]
fn test_get_data_retrieves_original_data() {
    let mut cert = Certificate::new();
    let test_data = "test data";
    cert.set_data(test_data);
    
    let retrieved_data = cert.get_data().unwrap();
    assert_eq!(retrieved_data, test_data);
}

#[test]
fn test_get_data_handles_empty_data() {
    let cert = Certificate::new();
    assert!(cert.get_data().is_none());
}

#[test]
fn test_get_data_handles_0x_prefix() {
    let mut cert = Certificate::new();
    cert.data = Some("0x".to_string());
    assert!(cert.get_data().is_none());
}

#[test]
fn test_get_data_handles_multi_byte_unicode() {
    let mut cert = Certificate::new();
    let test_data = "Hello, 世界! 🌍";
    cert.set_data(test_data);
    
    let retrieved_data = cert.get_data().unwrap();
    assert_eq!(retrieved_data, test_data);
}

#[test]
fn test_get_json_certificate_returns_valid_json() {
    let mut cert = Certificate::new();
    cert.set_data("test data");
    
    let json = cert.get_json_certificate();
    assert!(json.contains("\"data\""));
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"previous_tx_id\""));
    assert!(json.contains("\"previous_block\""));
}

#[test]
fn test_get_certificate_size_returns_correct_length() {
    let mut cert = Certificate::new();
    cert.set_data("test data");
    
    let size = cert.get_certificate_size();
    assert!(size > 0);
    
    // Verify the size matches the JSON string length
    let json = cert.get_json_certificate();
    assert_eq!(size, json.as_bytes().len());
}

// Test with various data sizes
#[rstest]
#[case("small data")]
#[case("medium data ".repeat(10))]
#[case("large data ".repeat(100))]
fn test_certificate_with_various_data_sizes(#[case] test_data: String) {
    let mut cert = Certificate::new();
    cert.set_data(&test_data);
    
    let retrieved_data = cert.get_data().unwrap();
    assert_eq!(retrieved_data, test_data);
    
    let size = cert.get_certificate_size();
    assert!(size > 0);
    assert!(size >= test_data.len());
}

// Specific size tests
#[test]
fn test_1kb_certificate() {
    let cert = generate_certificate_with_size(1024);
    assert!(verify_certificate_size(&cert, 1024));
}

#[test]
fn test_2kb_certificate() {
    let cert = generate_certificate_with_size(2048);
    assert!(verify_certificate_size(&cert, 2048));
}

#[test]
fn test_5kb_certificate() {
    let cert = generate_certificate_with_size(5120);
    assert!(verify_certificate_size(&cert, 5120));
}

#[test]
fn test_certificate_size_consistency() {
    let sizes = [1024, 2048, 5120];
    
    for size in sizes {
        let cert = generate_certificate_with_size(size);
        let json = cert.get_json_certificate();
        
        // Verify the certificate can be parsed back
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .expect("Failed to parse certificate JSON");
            
        // Verify the data field exists and is a string
        assert!(parsed.get("data").is_some());
        assert!(parsed.get("data").unwrap().is_string());
        
        // Verify the size is within expected range
        assert!(verify_certificate_size(&cert, size));
    }
} 