use crate::account::Account;
use crate::LIB_VERSION;

#[test]
fn test_public_methods_existence() {
    // Create an instance of Account
    let mut account = Account::new();
    
    // Test constructor
    assert_eq!(account.version, LIB_VERSION);
    
    // Test open method
    assert!(account.open("test_address").is_ok());
    
    // Test set_blockchain
    account.set_blockchain("test_chain");
    assert_eq!(account.blockchain, "test_chain");
    
    // Test set_network_node
    account.set_network_node("test_node");
    assert_eq!(account.network_node, "test_node");
    
    // Test set_interval
    account.set_interval(5);
    assert_eq!(account.interval_sec, 5);
    
    // Test close
    account.close();
    assert!(account.address.is_none());
}

#[tokio::test]
async fn test_async_methods_existence() {
    let mut account = Account::new();
    
    // Test set_network (async)
    // Note: This might fail if network is unreachable, but we're just testing method existence
    let _ = account.set_network("test_network").await;
    
    // Test update_account (async)
    let _ = account.update_account().await;
    
    // Test submit_certificate (async)
    let _ = account.submit_certificate("test_data", "test_key").await;
    
    // Test get_transaction (async)
    let _ = account.get_transaction(0, "test_id").await;
    
    // Test get_transaction_by_id (async)
    let _ = account.get_transaction_by_id("test_id", 0, 10).await;
    
    // Test get_transaction_outcome (async)
    let _ = account.get_transaction_outcome("test_id", 5).await;
} 