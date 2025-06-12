use circular_enterprise_apis::Certificate;

/// Generates a certificate with a specific size in bytes
pub fn generate_certificate_with_size(size_bytes: usize) -> Certificate {
    let mut cert = Certificate::new();
    
    // Generate data that will result in approximately the desired size
    // We account for the JSON structure overhead
    let data_size = size_bytes.saturating_sub(100); // Approximate JSON overhead
    let test_data = "x".repeat(data_size);
    
    cert.set_data(&test_data);
    cert
}

/// Verifies that a certificate's size is within an acceptable range
pub fn verify_certificate_size(cert: &Certificate, expected_size: usize) -> bool {
    let actual_size = cert.get_certificate_size();
    let tolerance = 50; // Allow for some variation in JSON formatting
    
    actual_size >= expected_size && actual_size <= expected_size + tolerance
} 