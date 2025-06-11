

## UNIT TESTS

- **Circular ESM Enterprise APIs**

### C_CERTIFICATE Class Tests

  - **Environment Variable Setup**
    - should have all required env variables for testnet
  - **C_CERTIFICATE Class**
    - should initialize with default values
    - **setData method**
      - should store data as hex (using librarys stringToHex)
    - **getData method**
      - should retrieve original data for simple strings
      - should return empty string if data is null or empty hex
      - should return empty string if data is "0x"
      - should correctly retrieve multi-byte unicode data
    - **getJSONCertificate method**
      - should return a valid JSON string
    - **getCertificateSize method**
      - should return correct byte length

### CEP_Account Class Test

  - **CEP_Account Class**
    - should initialize with default values

    - **open method**
      - should set the account address
      - should throw an error for invalid address format

    - **close method**
      - should reset account properties to default

    - **setBlockchain method**
      - should update the blockchain property

    - **setNetwork method**
      - should update NAG_URL for "mainnet"
      - should update NAG_URL for "testnet"
      - should update NAG_URL for "devnet"
      - should throw an error if network request fails
      - should throw an error if API response indicates failuz

    - **updateAccount method**
      - should update Nonce on successful API call
      - should return false and not update Nonce on API error (Result != 200)
      - should return false on network error
      - should throw an error if account is not open
      - should return false if response is malformed (missing Nonce)

    - **signData method**
      - should throw an error if account is not open
      - should produce different signatures for different data
      - should produce different signatures for different private key

    - **getTransaction and getTransactionbyID methods**
      - getTransaction(BlockID, TxID) should fetch a transaction
      - getTransaction(BlockID, TxID) should throw on network error
      - getTransactionbyID should fetch a transaction within a block range
      - getTransactionbyID should handle "Transaction Not Found"
      - getTransactionbyID should throw on network error

    - **submitCertificate method**
      - should submit a certificate successfully
      - should submit a 1KB certificate successfully
        ```pseudocode
        // Assuming 'account' is an initialized CEP_Account instance
        // Assuming 'certificate' is a C_CERTIFICATE instance

        // 1. Generate a 1KB certificate (or data that results in 1KB certificate)
        cert_1kb = generateCertificateWithSize(1024)

        // 2. Submit the 1KB certificate
        result = account.submitCertificate(cert_1kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should submit a 2KB certificate successfully
        ```pseudocode
        // 1. Generate a 2KB certificate
        cert_2kb = generateCertificateWithSize(2048)

        // 2. Submit the 2KB certificate
        result = account.submitCertificate(cert_2kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should submit a 5KB certificate successfully
        ```pseudocode
        // 1. Generate a 5KB certificate
        cert_5kb = generateCertificateWithSize(5120)

        // 2. Submit the 5KB certificate
        result = account.submitCertificate(cert_5kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should return error object on network failure
      - should return error object on HTTP error status
      - should throw an error if account is not open

    - **getTransactionOutcome method**
      - should resolve with transaction data if found and confirmed quickly
      - should poll and resolve when transaction is confirmed after being pending
      - should poll and resolve when transaction is confirmed after "Transaction Not Found"
      - should reject if getTransactionbyID call fails during polling
      - should reject with "Timeout exceeded" if polling duration exceeds timeoutSec



    - **CEP_Account Live Network Tests (against various live networks)**
      - should update account nonce on real network
      - should submit a certificate and get its outcome on real network
      - should fetch a transaction by block number and ID on real network
      - should correctly reflect network URL configuration status

### Permissions
  - **Non-Permissioned Account Behavior**
    - should not update account nonce for a non-permissioned address
    - should not allow submitting a certificate from a non-permissioned account

### BLOCKCHAIN NETWORK INTEGRATION TESTINGs  
- **Circular ESM Enterprise APIs - Live Network Integration**

### C_CERTIFICATE Class Tests

  - **C_CERTIFICATE Class**
    - should initialize with default values

    - **setData method**
      - should store data as hex (using librarys stringToHex)

    - **getData method**
      - should retrieve original data for simple strings
      - should return empty string if data is null or empty hex
      - should return empty string if data is "0x"
      - should correctly retrieve multi-byte unicode data (EXPECTED TO FAIL WITH CURRENT LIBRARY

    - **getJSONCertificate method**
      - should return a valid JSON string

    - **getCertificateSize method**
      - should return correct byte length

### CEP_Account Class Tests

  - **CEP_Account Class**
    - should initialize with default values
  
    - **open method**
      - should set the account address
      - should throw an error for invalid address format
  
    - **close method**
      - should reset account properties to defaults
  
    - **setBlockchain method**
      - should update the blockchain property
  
    - **setNetwork method**
      - should update NAG_URL for "mainnet"
      - should update NAG_URL for "testnet"
      - should update NAG_URL for "devnet"
      - should throw an error if network request fails
      - should throw an error if API response indicates failure
  
    - **updateAccount method**
      - should update Nonce on successful API call
      - should return false and not update Nonce on API error (Result != 200)
      - should return false on network error
      - should throw an error if account is not open
      - should return false if response is malformed (missing Nonce)
  
     - **signData method**
      - should sign data correctly
      - should throw an error if account is not open
      - should produce different signatures for different data
      - should produce different signatures for different private keys
  
   - **getTransaction and getTransactionbyID methods**
      - getTransaction(BlockID, TxID) should fetch a transaction
      - getTransaction(BlockID, TxID) should throw on network error
      - getTransactionbyID should fetch a transaction within a block range
      - getTransactionbyID should handle "Transaction Not Found"
      - getTransactionbyID should throw on network error
  
    - **submitCertificate method**
      - should submit a certificate successfully
      - should submit a 1KB certificate successfully
        ```pseudocode
        // Assuming 'account' is an initialized CEP_Account instance
        // Assuming 'certificate' is a C_CERTIFICATE instance

        // 1. Generate a 1KB certificate (or data that results in 1KB certificate)
        cert_1kb = generateCertificateWithSize(1024)

        // 2. Submit the 1KB certificate
        result = account.submitCertificate(cert_1kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should submit a 2KB certificate successfully
        ```pseudocode
        // 1. Generate a 2KB certificate
        cert_2kb = generateCertificateWithSize(2048)

        // 2. Submit the 2KB certificate
        result = account.submitCertificate(cert_2kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should submit a 5KB certificate successfully
        ```pseudocode
        // 1. Generate a 5KB certificate
        cert_5kb = generateCertificateWithSize(5120)

        // 2. Submit the 5KB certificate
        result = account.submitCertificate(cert_5kb)

        // 3. Assert successful submission
        ASSERT result.success IS TRUE
        ASSERT result.certificateId IS NOT NULL
        ```
      - should return error object on network failure
      - should return error object on HTTP error status
      - should throw an error if account is not open

    - **getTransactionOutcome method**
      - should resolve with transaction data if found and confirmed quickly
      - should poll and resolve when transaction is confirmed after being pending
      - should poll and resolve when transaction is confirmed after "Transaction Not Found"
      - should reject if getTransactionbyID call fails during polling
      - should reject with "Timeout exceeded" if polling duration exceeds timeoutSec
  
    - **CEP_Account Live Network Tests (against various live networks)** (Conditional: only if targetNetwork is set)
      - should update account nonce on real network
      - should submit a certificate and get its outcome on real network
      - should fetch a transaction by ID on real network
      - should fetch a transaction by block number and ID on real network
      - should correctly reflect network URL configuration status