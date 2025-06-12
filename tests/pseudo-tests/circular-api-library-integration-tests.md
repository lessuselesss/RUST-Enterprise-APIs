# Circular Enterprise APIs Test Suite

## 1. Unit Tests
### 1.1 Core Component Tests
#### C_CERTIFICATE Class Tests

  - **Environment Variable Setup**
    - [1.1.1] should have all required env variables for testnet
      ```pseudocode
      // 1. List all required environment variables
      requiredVars = [
          'TESTNET_CIRCULAR_MAIN_PUBLIC_CHAIN_ADDRESS',
          'TESTNET_CIRCULAR_MAIN_PUBLIC_ACCOUNT_PUBKEY',
          'TESTNET_CIRCULAR_MAIN_PUBLIC_ACCOUNT_PVTKEY',
          'TESTNET_CIRCULAR_MAIN_PUBLIC_ACCOUNT_SEED'
      ]
      
      // 2. Check each variable exists and is not a placeholder
      FOR each var IN requiredVars
          VERIFY process.env[var] IS_NOT_EMPTY
          VERIFY process.env[var] DOES_NOT_MATCH_PATTERN "placeholder"
      ```
  
  - **C_CERTIFICATE Class**
    - [1.1.2] should initialize with default values
      ```pseudocode
      // 1. Create new certificate instance
      certificate = NEW C_CERTIFICATE()
      
      // 2. Verify default values
      VERIFY certificate.data IS EMPTY
      VERIFY certificate.previousTxID IS EMPTY
      VERIFY certificate.previousBlock IS EMPTY
      VERIFY certificate.codeVersion IS LIB_VERSION
      ```
    - [1.1.3] shouldn't expose any methods publically
    
    - **set data method**
      - [1.1.4] should store data as hex (using librarys stringToHex)
        ```pseudocode
        // 1. Create certificate and test data
        certificate = NEW C_CERTIFICATE()
        testData = "test data is a string"
        
        // 2. Set data and verify hex conversion
        certificate.setData(testData)
        expectedHex = CONVERT_TO_HEX(testData)
        VERIFY certificate.data IS expectedHex
        ```
    
    - **get data method**
      - [1.1.5] should retrieve original data for simple strings
        ```pseudocode
        // 1. Setup
        certificate = NEW C_CERTIFICATE()
        originalData = "another test"
        
        // 2. Set and get data
        certificate.setData(originalData)
        VERIFY certificate.getData() IS originalData
        ```
      - [1.1.6] should return empty string if data is null or empty hex
        ```pseudocode
        // 1. Test null data
        certificate = NEW C_CERTIFICATE()
        EXPECT_ERROR WHEN certificate.getData(NULL) WITH_MESSAGE "Data is null"
        
        // 2. Test empty hex
        certificate.data = ""
        EXPECT_ERROR WHEN certificate.getData("") WITH_MESSAGE "Data is empty"
        ```
      - [1.1.7] should return empty string if data is "0x"
        ```pseudocode
        // 1. Setup
        certificate = NEW C_CERTIFICATE()
        certificate.data = "0x"
        
        // 2. Verify
        VERIFY certificate.getData() IS ""
        ```
      - [1.1.8] should correctly retrieve multi-byte unicode data
        ```pseudocode
        // 1. Setup
        certificate = NEW C_CERTIFICATE()
        unicodeData = "你好世界 😊"
        
        // 2. Test
        certificate.setData(unicodeData)
        VERIFY certificate.getData() IS unicodeData
        ```
    
    - **get JSON certificate method**
      - [1.1.9] should return a valid JSON string
        ```pseudocode
        // 1. Setup
        certificate = NEW C_CERTIFICATE()
        testData = "json test"
        certificate.setData(testData)
        certificate.previousTxID = "tx123"
        certificate.previousBlock = "block456"
        
        // 2. Get and verify JSON
        jsonCert = certificate.getJSONCertificate()
        parsedCert = JSON.parse(jsonCert)
        
        // 3. Verify structure
        VERIFY parsedCert HAS_PROPERTY "data"
        VERIFY parsedCert HAS_PROPERTY "previousTxID"
        VERIFY parsedCert HAS_PROPERTY "previousBlock"
        VERIFY parsedCert HAS_PROPERTY "version"
        VERIFY parsedCert.version IS LIB_VERSION
        ```
    
    - **get certificate size method**
      - [1.1.10] should return correct byte length
        ```pseudocode
        // 1. Setup
        certificate = NEW C_CERTIFICATE()
        testData = "size test"
        certificate.setData(testData)
        certificate.previousTxID = "txIDForSize"
        certificate.previousBlock = "blockIDForSize"
        
        // 2. Calculate expected size
        jsonString = JSON.stringify({
            data: CONVERT_TO_HEX(testData),
            previousTxID: "txIDForSize",
            previousBlock: "blockIDForSize",
            version: LIB_VERSION
        })
        expectedSize = BUFFER_BYTE_LENGTH(jsonString)
        
        // 3. Verify
        VERIFY certificate.getCertificateSize() IS expectedSize
        ```

### 1.2 Account Management Tests
#### CEP_Account Class Tests

  - **CEP_Account Class**
    - [1.2.1] should initialize with default values
      ```pseudocode
      // 1. Create new account
      account = NEW CEP_Account()
      
      // 2. Verify default values
      VERIFY account.address IS EMPTY
      VERIFY account.publicKey IS EMPTY
      VERIFY account.info IS EMPTY
      VERIFY account.codeVersion IS LIB_VERSION
      VERIFY account.lastError IS ""
      VERIFY account.NAG_URL IS DEFAULT_NAG
      VERIFY account.NETWORK_NODE IS ""
      VERIFY account.blockchain IS DEFAULT_CHAIN
      VERIFY account.LatestTxID IS ""
      VERIFY account.Nonce IS 0
      VERIFY account.data IS EMPTY_OBJECT
      VERIFY account.intervalSec IS 2
      ```
    - [1.2.2] should only expose the open, set network, set blockchain, update account, submit certificate, get transaction outcome, get transaction & close methods publically.
    
    - **open account method**
      - [1.2.3] should set the account address
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        mockAddress = "0x123..."
        
        // 2. Test
        account.open(mockAddress)
        VERIFY account.address IS mockAddress
        ```
      - [1.2.4] should throw an error for invalid address format
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        
        // 2. Test invalid inputs
        EXPECT_ERROR WHEN account.open(NULL) WITH_MESSAGE "Invalid address format"
        EXPECT_ERROR WHEN account.open(123) WITH_MESSAGE "Invalid address format"
        EXPECT_ERROR WHEN account.open({}) WITH_MESSAGE "Invalid address format"
        ```

    - **close account method**
      - [1.2.5] should reset account properties to default
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        
        // 2. Test
        account.close()
        VERIFY account.address IS EMPTY
        VERIFY account.publicKey IS EMPTY
        VERIFY account.info IS EMPTY
        VERIFY account.lastError IS ""
        VERIFY account.NAG_URL IS DEFAULT_NAG
        VERIFY account.NETWORK_NODE IS ""
        VERIFY account.blockchain IS DEFAULT_CHAIN
        VERIFY account.LatestTxID IS ""
        VERIFY account.Nonce IS 0
        VERIFY account.data IS EMPTY_OBJECT
        VERIFY account.intervalSec IS 2
        ```

    - **set blockchain method**
      - [1.2.6] should update the blockchain property
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        newChain = "0xmynewchain"
        
        // 2. Test
        account.setBlockchain(newChain)
        VERIFY account.blockchain IS newChain
        ```

    - **set network method**
      - [1.2.7] should update NAG_URL for "mainnet"
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        initialNAG = account.NAG_URL
        
        // 2. Set mainnet
        await account.setNetwork('mainnet')
        
        // 3. Verify configuration
        VERIFY account.NAG_URL IS "https://mainnet-nag.circularlabs.io/API/"
        VERIFY account.NETWORK_NODE IS_NOT_EMPTY
        VERIFY account.NETWORK_NODE INCLUDES "mainnet"
        
        // 4. Verify account state
        VERIFY account.address IS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        VERIFY account.blockchain IS DEFAULT_CHAIN
        ```

      - [1.2.8] should update NAG_URL for "testnet"
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        initialNAG = account.NAG_URL
        
        // 2. Set testnet
        await account.setNetwork('testnet')
        
        // 3. Verify configuration
        VERIFY account.NAG_URL IS "https://testnet-nag.circularlabs.io/API/"
        VERIFY account.NETWORK_NODE IS_NOT_EMPTY
        VERIFY account.NETWORK_NODE INCLUDES "testnet"
        
        // 4. Verify account state
        VERIFY account.address IS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        VERIFY account.blockchain IS DEFAULT_CHAIN
        ```

      - [1.2.9] should update NAG_URL for "devnet"
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        initialNAG = account.NAG_URL
        
        // 2. Set devnet
        await account.setNetwork('devnet')
        
        // 3. Verify configuration
        VERIFY account.NAG_URL IS "https://devnet-nag.circularlabs.io/API/"
        VERIFY account.NETWORK_NODE IS_NOT_EMPTY
        VERIFY account.NETWORK_NODE INCLUDES "devnet"
        
        // 4. Verify account state
        VERIFY account.address IS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        VERIFY account.blockchain IS DEFAULT_CHAIN
        ```

      - [1.2.10] should throw an error if network request fails
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        initialNAG = account.NAG_URL
        
        // 2. Test various network failure scenarios
        NETWORK_ERRORS = [
            { type: "timeout", message: "Request timeout" },
            { type: "connection", message: "Connection refused" },
            { type: "dns", message: "DNS lookup failed" },
            { type: "reset", message: "Connection reset" }
        ]
        
        // 3. Test each network error
        FOR each error IN NETWORK_ERRORS
            MOCK_NETWORK_ERROR = error
            
            // Attempt network change
            try {
                await account.setNetwork('mainnet')
                VERIFY false  // Should not reach here
            } catch (error) {
                // Verify error
                VERIFY error.message INCLUDES error.message
                VERIFY error.type IS "NetworkError"
                VERIFY account.NAG_URL IS initialNAG  // Should not change
            }
        
        // 4. Test partial network failure
        MOCK_PARTIAL_NETWORK_FAILURE = TRUE
        
        try {
            await account.setNetwork('mainnet')
            VERIFY false  // Should not reach here
        } catch (error) {
            VERIFY error.message INCLUDES "Connection lost"
            VERIFY error.type IS "NetworkError"
            VERIFY account.NAG_URL IS initialNAG  // Should not change
        }
        
        // 5. Verify account state remains unchanged
        VERIFY account.address IS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        VERIFY account.blockchain IS DEFAULT_CHAIN
        ```

      - [1.2.11] should throw an error if API response indicates failure
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        initialNAG = account.NAG_URL
        
        // 2. Test various API error responses
        API_ERRORS = [
            { Result: 400, Message: "Bad Request" },
            { Result: 401, Message: "Unauthorized" },
            { Result: 403, Message: "Forbidden" },
            { Result: 404, Message: "Network Not Found" },
            { Result: 429, Message: "Too Many Requests" },
            { Result: 500, Message: "Internal Server Error" },
            { Result: 503, Message: "Service Unavailable" }
        ]
        
        // 3. Test each error case
        FOR each error IN API_ERRORS
            MOCK_API_RESPONSE = error
            
            // Attempt network change
            try {
                await account.setNetwork('mainnet')
                VERIFY false  // Should not reach here
            } catch (error) {
                // Verify error
                VERIFY error.message INCLUDES error.Message
                VERIFY error.type IS "APIError"
                VERIFY account.NAG_URL IS initialNAG  // Should not change
            }
        
        // 4. Test malformed API responses
        MALFORMED_RESPONSES = [
            { Result: 200 },  // Missing Response
            { Result: 200, Response: null },  // Null Response
            { Result: 200, Response: {} },  // Empty Response
            { Result: 200, Response: { Status: "Error" } }  // Error Status
        ]
        
        FOR each response IN MALFORMED_RESPONSES
            MOCK_API_RESPONSE = response
            
            try {
                await account.setNetwork('mainnet')
                VERIFY false  // Should not reach here
            } catch (error) {
                VERIFY error.message INCLUDES "Invalid response"
                VERIFY error.type IS "APIError"
                VERIFY account.NAG_URL IS initialNAG  // Should not change
            }
        
        // 5. Verify account state remains unchanged
        VERIFY account.address IS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        VERIFY account.blockchain IS DEFAULT_CHAIN
        ```

    - **update account method**
      - [1.2.12] should update Nonce on successful API call
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        initialNonce = account.Nonce

        // 2. Mock successful API response
        MOCK_API_RESPONSE = { 
            Result: 200, 
            Response: { 
                Nonce: 5,
                Address: account.address,
                PublicKey: account.publicKey,
                LatestTxID: "0x123...",
                Status: "Active"
            } 
        }

        // 3. Update account
        result = await account.updateAccount()

        // 4. Verify successful update
        VERIFY result IS TRUE
        VERIFY account.Nonce EQUALS 6  // Should increment by 1
        VERIFY account.LatestTxID EQUALS MOCK_API_RESPONSE.Response.LatestTxID
        VERIFY account.info.Status EQUALS "Active"

        // 5. Verify account state
        VERIFY account.address EQUALS MOCK_API_RESPONSE.Response.Address
        VERIFY account.publicKey EQUALS MOCK_API_RESPONSE.Response.PublicKey
        ```

      - [1.2.13] should return false and not update Nonce on API error (Result != 200)
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        initialNonce = account.Nonce

        // 2. Test various API error responses
        API_ERRORS = [
            { Result: 400, Message: "Bad Request" },
            { Result: 401, Message: "Unauthorized" },
            { Result: 403, Message: "Forbidden" },
            { Result: 404, Message: "Account Not Found" },
            { Result: 429, Message: "Too Many Requests" },
            { Result: 500, Message: "Internal Server Error" },
            { Result: 503, Message: "Service Unavailable" }
        ]

        // 3. Test each error case
        FOR each error IN API_ERRORS
            MOCK_API_RESPONSE = error
            
            // Attempt update
            result = await account.updateAccount()
            
            // Verify error handling
            VERIFY result IS FALSE
            VERIFY account.Nonce EQUALS initialNonce  // Nonce should not change
            VERIFY account.lastError INCLUDES error.Message
            VERIFY account.lastError INCLUDES error.Result.toString()

        // 4. Verify account state remains unchanged
        VERIFY account.address EQUALS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        ```

      - [1.2.14] should return false on network error
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        initialNonce = account.Nonce

        // 2. Test various network error scenarios
        NETWORK_ERRORS = [
            { type: "timeout", message: "Request timeout" },
            { type: "connection", message: "Connection refused" },
            { type: "dns", message: "DNS lookup failed" },
            { type: "reset", message: "Connection reset" }
        ]

        // 3. Test each network error
        FOR each error IN NETWORK_ERRORS
            MOCK_NETWORK_ERROR = error
            
            // Attempt update
            result = await account.updateAccount()
            
            // Verify error handling
            VERIFY result IS FALSE
            VERIFY account.Nonce EQUALS initialNonce  // Nonce should not change
            VERIFY account.lastError INCLUDES error.message
            VERIFY account.lastError INCLUDES "Network error"

        // 4. Test partial network failure
        MOCK_PARTIAL_NETWORK_FAILURE = TRUE
        result = await account.updateAccount()
        VERIFY result IS FALSE
        VERIFY account.Nonce EQUALS initialNonce
        VERIFY account.lastError INCLUDES "Connection lost"
        ```

      - [1.2.15] should throw an error if account is not open
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()

        // 2. Attempt update without opening account
        EXPECT_ERROR WHEN account.updateAccount() WITH {
            message: "Account not open",
            type: "AccountError"
        }

        // 3. Verify account remains in default state
        VERIFY account.address IS EMPTY
        VERIFY account.publicKey IS EMPTY
        VERIFY account.info IS EMPTY
        VERIFY account.Nonce IS 0
        VERIFY account.LatestTxID IS ""
        VERIFY account.lastError IS ""
        ```

      - [1.2.16] should return false if response is malformed (missing Nonce)
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        initialNonce = account.Nonce

        // 2. Test various malformed responses
        MALFORMED_RESPONSES = [
            { Result: 200, Response: {} },  // Empty response
            { Result: 200, Response: { Address: "0x123..." } },  // Missing Nonce
            { Result: 200, Response: { Nonce: "invalid" } },  // Invalid Nonce type
            { Result: 200, Response: { Nonce: -1 } },  // Negative Nonce
            { Result: 200, Response: { Nonce: null } },  // Null Nonce
            { Result: 200, Response: { Nonce: undefined } },  // Undefined Nonce
            { Result: 200 },  // Missing Response
            { Result: 200, Response: null },  // Null Response
            { Result: 200, Response: undefined }  // Undefined Response
        ]

        // 3. Test each malformed response
        FOR each response IN MALFORMED_RESPONSES
            MOCK_API_RESPONSE = response
            
            // Attempt update
            result = await account.updateAccount()
            
            // Verify error handling
            VERIFY result IS FALSE
            VERIFY account.Nonce EQUALS initialNonce  // Nonce should not change
            VERIFY account.lastError INCLUDES "Invalid response"
            VERIFY account.lastError INCLUDES "Nonce"

        // 4. Verify account state remains unchanged
        VERIFY account.address EQUALS mockAddress
        VERIFY account.publicKey IS_NOT_EMPTY
        VERIFY account.info IS_NOT_EMPTY
        ```

    - **sign data method**
      - [1.2.17] should throw an error if account is not open
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        testData = "test data for signing"
        testPrivateKey = "0x1234567890abcdef"

        // 2. Attempt to sign without opening account
        EXPECT_ERROR WHEN account.signData(testData, testPrivateKey) WITH {
            message: "Account not open",
            type: "AccountError"
        }

        // 3. Verify account remains in default state
        VERIFY account.address IS EMPTY
        VERIFY account.publicKey IS EMPTY
        VERIFY account.info IS EMPTY
        VERIFY account.Nonce IS 0
        VERIFY account.LatestTxID IS ""
        ```

      - [1.2.18] should produce different signatures for different data
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        testPrivateKey = "0x1234567890abcdef"

        // 2. Test with different data types
        TEST_DATA = [
            "simple string",
            "Hello 世界",  // Unicode
            "Special chars: !@#$%^&*()",
            "1234567890",
            "0x1234567890abcdef",
            "",  // Empty string
            "   ",  // Whitespace
            "a".repeat(1000)  // Long string
        ]

        // 3. Generate signatures for each data type
        signatures = []
        FOR each data IN TEST_DATA
            signature = account.signData(data, testPrivateKey)
            signatures.push(signature)
            
            // Verify signature format
            VERIFY signature IS STRING
            VERIFY signature.length GREATER THAN 0
            VERIFY signature MATCHES /^[0-9a-f]+$/  // Should be hex

        // 4. Verify all signatures are unique
        FOR i = 0 TO signatures.length - 1
            FOR j = i + 1 TO signatures.length - 1
                VERIFY signatures[i] NOT EQUALS signatures[j]

        // 5. Verify signatures are deterministic
        FOR each data IN TEST_DATA
            signature1 = account.signData(data, testPrivateKey)
            signature2 = account.signData(data, testPrivateKey)
            VERIFY signature1 EQUALS signature2
        ```

      - [1.2.19] should produce different signatures for different private key
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        testData = "test data for signing"

        // 2. Test with different private keys
        TEST_PRIVATE_KEYS = [
            "0x" + "1".repeat(64),  // All ones
            "0x" + "a".repeat(64),  // All a's
            "0x" + "f".repeat(64),  // All f's
            "0x" + "0".repeat(64),  // All zeros
            "0x" + "5".repeat(64),  // All fives
            "0x" + "9".repeat(64)   // All nines
        ]

        // 3. Generate signatures for each private key
        signatures = []
        FOR each key IN TEST_PRIVATE_KEYS
            signature = account.signData(testData, key)
            signatures.push(signature)
            
            // Verify signature format
            VERIFY signature IS STRING
            VERIFY signature.length GREATER THAN 0
            VERIFY signature MATCHES /^[0-9a-f]+$/  // Should be hex

        // 4. Verify all signatures are unique
        FOR i = 0 TO signatures.length - 1
            FOR j = i + 1 TO signatures.length - 1
                VERIFY signatures[i] NOT EQUALS signatures[j]

        // 5. Test with invalid private keys
        INVALID_KEYS = [
            "0x",                    // Too short
            "0x123",                 // Invalid length
            "0xabcdefghijklmnop",   // Invalid characters
            "1234567890abcdef",     // Missing 0x prefix
            null,                    // Null key
            undefined,              // Undefined key
            "",                     // Empty string
            "not_a_hex_string"      // Non-hex string
        ]

        FOR each key IN INVALID_KEYS
            EXPECT_ERROR WHEN account.signData(testData, key) WITH {
                message: "Invalid private key",
                type: "ValidationError"
            }

        // 6. Verify signature verification
        FOR each key IN TEST_PRIVATE_KEYS
            signature = account.signData(testData, key)
            verificationResult = VERIFY_SIGNATURE(testData, signature, account.publicKey)
            VERIFY verificationResult IS TRUE
        ```

    - **get transaction and get transaction by ID methods**
      - [1.2.20] get transaction(BlockID, TxID) should fetch a transaction
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        
        // 2. Submit a test transaction first
        testData = "test transaction data"
        submitResult = await account.submitCertificate(testData, mockPrivateKey)
        
        // 3. Get transaction details
        txResult = await account.getTransaction(
            submitResult.blockNumber,
            submitResult.TxID
        )
        
        // 4. Verify transaction data
        VERIFY txResult.Result EQUALS 200
        VERIFY txResult.Response.id EQUALS submitResult.TxID
        VERIFY txResult.Response.status EQUALS "Confirmed"
        VERIFY txResult.Response.data EQUALS testData
        VERIFY txResult.Response.blockNumber EQUALS submitResult.blockNumber
        VERIFY txResult.Response.timestamp IS NOT NULL
        
        // 5. Verify transaction metadata
        VERIFY txResult.Response.signature IS NOT NULL
        VERIFY txResult.Response.publicKey EQUALS account.publicKey
        VERIFY txResult.Response.nonce EQUALS account.Nonce - 1  // Previous nonce
        ```

      - [1.2.21] get transaction(BlockID, TxID) should throw on network error
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        blockNum = 100
        txID = "testTxID123"
        
        // 2. Simulate network errors
        NETWORK_ERRORS = [
            { type: "timeout", message: "Request timeout" },
            { type: "connection", message: "Connection refused" },
            { type: "dns", message: "DNS lookup failed" }
        ]
        
        // 3. Test each network error
        FOR each error IN NETWORK_ERRORS
            MOCK_NETWORK_ERROR = error
            
            // Attempt to get transaction
            try {
                await account.getTransaction(blockNum, txID)
                VERIFY false  // Should not reach here
            } catch (error) {
                // Verify error
                VERIFY error.message INCLUDES error.message
                VERIFY error.type IS "NetworkError"
            }
        
        // 4. Verify account state remains unchanged
        VERIFY account.Nonce EQUALS initialNonce
        VERIFY account.LatestTxID IS ""
        ```

      - [1.2.22] get transaction by ID should fetch a transaction within a block range
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        
        // 2. Submit multiple test transactions
        testData = ["tx1", "tx2", "tx3"]
        submitResults = []
        
        FOR each data IN testData
            result = await account.submitCertificate(data, mockPrivateKey)
            submitResults.push(result)
        
        // 3. Get transactions within block range
        startBlock = submitResults[0].blockNumber
        endBlock = submitResults[2].blockNumber
        
        FOR each result IN submitResults
            txResult = await account.getTransactionByID(
                result.TxID,
                startBlock,
                endBlock
            )
            
            // Verify transaction data
            VERIFY txResult.Result EQUALS 200
            VERIFY txResult.Response.id EQUALS result.TxID
            VERIFY txResult.Response.blockNumber GREATER THAN OR EQUAL TO startBlock
            VERIFY txResult.Response.blockNumber LESS THAN OR EQUAL TO endBlock
            VERIFY txResult.Response.data EQUALS testData[submitResults.indexOf(result)]
        
        // 4. Test block range edge cases
        // Test with exact block numbers
        txResult = await account.getTransactionByID(
            submitResults[0].TxID,
            submitResults[0].blockNumber,
            submitResults[0].blockNumber
        )
        VERIFY txResult.Result EQUALS 200
        
        // Test with invalid block range
        try {
            await account.getTransactionByID(
                submitResults[0].TxID,
                endBlock,
                startBlock  // Reversed range
            )
            VERIFY false  // Should not reach here
        } catch (error) {
            VERIFY error.message INCLUDES "Invalid block range"
        }
        ```

      - [1.2.23] get transaction by ID should handle "Transaction Not Found"
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        
        // 2. Test various "not found" scenarios
        NOT_FOUND_SCENARIOS = [
            { txID: "0x" + "0".repeat(64), blockRange: [1, 100] },  // Non-existent TxID
            { txID: "0x123", blockRange: [1, 100] },                // Invalid TxID format
            { txID: "0x" + "f".repeat(64), blockRange: [999999, 1000000] }  // Far future block
        ]
        
        // 3. Test each scenario
        FOR each scenario IN NOT_FOUND_SCENARIOS
            txResult = await account.getTransactionByID(
                scenario.txID,
                scenario.blockRange[0],
                scenario.blockRange[1]
            )
            
            // Verify not found response
            VERIFY txResult.Result EQUALS 404
            VERIFY txResult.Message INCLUDES "Transaction Not Found"
            VERIFY txResult.Response IS NULL
        
        // 4. Test with valid TxID but wrong block range
        // First submit a transaction
        submitResult = await account.submitCertificate("test data", mockPrivateKey)
        
        // Try to find it in wrong block range
        txResult = await account.getTransactionByID(
            submitResult.TxID,
            submitResult.blockNumber + 1000,  // Far future block
            submitResult.blockNumber + 2000
        )
        
        VERIFY txResult.Result EQUALS 404
        VERIFY txResult.Message INCLUDES "Transaction Not Found"
        ```

      - [1.2.24] get transaction by ID should throw on network error
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open(mockAddress)
        account.setNetwork("testnet")
        txID = "testTxID123"
        
        // 2. Simulate various network error scenarios
        NETWORK_ERRORS = [
            { type: "timeout", message: "Request timeout", retryCount: 3 },
            { type: "connection", message: "Connection refused", retryCount: 2 },
            { type: "dns", message: "DNS lookup failed", retryCount: 1 }
        ]
        
        // 3. Test each network error with retries
        FOR each error IN NETWORK_ERRORS
            MOCK_NETWORK_ERROR = error
            retryAttempts = 0
            
            // Attempt to get transaction with retries
            try {
                await account.getTransactionByID(txID, 1, 100)
                VERIFY false  // Should not reach here
            } catch (error) {
                // Verify error and retry behavior
                VERIFY error.message INCLUDES error.message
                VERIFY error.type IS "NetworkError"
                VERIFY retryAttempts EQUALS error.retryCount
            }
        
        // 4. Test partial network failure
        // Simulate network failure after successful connection
        MOCK_PARTIAL_NETWORK_FAILURE = TRUE
        
        try {
            await account.getTransactionByID(txID, 1, 100)
            VERIFY false  // Should not reach here
        } catch (error) {
            VERIFY error.message INCLUDES "Connection lost"
            VERIFY error.type IS "NetworkError"
        }
        
        // 5. Verify account state remains unchanged after errors
        VERIFY account.Nonce EQUALS initialNonce
        VERIFY account.LatestTxID IS ""
        ```

    - **submit certificate method**
      - [1.2.25] should submit a certificate successfully on real network
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        testData = "test certificate data"
        initialNonce = account.Nonce
        
        // 2. Submit certificate
        result = await account.submitCertificate(testData, mockPrivateKey)
        
        // 3. Verify submission
        VERIFY result.Result EQUALS 200
        VERIFY result.TxID IS NOT NULL
        VERIFY result.Message EQUALS "Transaction Added"
        VERIFY account.LatestTxID EQUALS result.TxID
        VERIFY account.Nonce EQUALS initialNonce + 1
        ```
      - [1.2.26] should handle certificate submission with 1KB data
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        
        // 2. Generate 1KB test data
        cert_1kb = generateCertificateWithSize(1024)
        
        // 3. Submit certificate
        result = await account.submitCertificate(cert_1kb, mockPrivateKey)
        
        // 4. Verify submission
        VERIFY result.Result EQUALS 200
        VERIFY result.TxID IS NOT NULL
        VERIFY result.Message EQUALS "Transaction Added"
        
        // 5. Verify data integrity
        txOutcome = await account.getTransactionOutcome(result.TxID, 5)
        VERIFY txOutcome.data EQUALS cert_1kb
        ```
      - [1.2.27] should handle certificate submission with 2KB data
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        
        // 2. Generate 2KB test data
        cert_2kb = generateCertificateWithSize(2048)
        
        // 3. Submit certificate
        result = await account.submitCertificate(cert_2kb, mockPrivateKey)
        
        // 4. Verify submission
        VERIFY result.Result EQUALS 200
        VERIFY result.TxID IS NOT NULL
        VERIFY result.Message EQUALS "Transaction Added"
        
        // 5. Verify data integrity
        txOutcome = await account.getTransactionOutcome(result.TxID, 5)
        VERIFY txOutcome.data EQUALS cert_2kb
        ```
      - [1.2.28] should handle certificate submission with 5KB data
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        
        // 2. Generate 5KB test data
        cert_5kb = generateCertificateWithSize(5120)
        
        // 3. Submit certificate
        result = await account.submitCertificate(cert_5kb, mockPrivateKey)
        
        // 4. Verify submission
        VERIFY result.Result EQUALS 200
        VERIFY result.TxID IS NOT NULL
        VERIFY result.Message EQUALS "Transaction Added"
        
        // 5. Verify data integrity
        txOutcome = await account.getTransactionOutcome(result.TxID, 5)
        VERIFY txOutcome.data EQUALS cert_5kb
        ```
      - [1.2.29] should handle concurrent certificate submissions
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        initialNonce = account.Nonce
        
        // 2. Prepare multiple certificates
        certs = [
            "cert1",
            "cert2",
            "cert3"
        ]
        
        // 3. Submit concurrently
        results = await Promise.all(
            certs.map(cert => account.submitCertificate(cert, mockPrivateKey))
        )
        
        // 4. Verify all submissions
        FOR each result IN results
            VERIFY result.Result EQUALS 200
            VERIFY result.TxID IS NOT NULL
        
        // 5. Verify nonce sequence
        VERIFY account.Nonce EQUALS initialNonce + certs.length
        ```
      - [1.2.30] should handle network errors during submission
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        initialNonce = account.Nonce
        
        // 2. Simulate network error
        MOCK_NETWORK_ERROR = TRUE
        
        // 3. Attempt submission
        result = await account.submitCertificate("test data", mockPrivateKey)
        
        // 4. Verify error handling
        VERIFY result.Result EQUALS 500
        VERIFY result.Message INCLUDES "Network error"
        VERIFY account.Nonce EQUALS initialNonce
        ```
      - [1.2.31] should maintain transaction order with multiple submissions
        ```pseudocode
        // 1. Setup
        account = NEW CEP_Account()
        account.open("0x123...")
        account.setNetwork("testnet")
        initialNonce = account.Nonce
        
        // 2. Submit sequence of certificates
        certs = [
            "cert1",
            "cert2",
            "cert3"
        ]
        results = []
        
        FOR each cert IN certs
            result = await account.submitCertificate(cert, mockPrivateKey)
            results.push(result)
        
        // 3. Verify transaction order
        FOR i = 0 TO results.length - 1
            txOutcome = await account.getTransactionOutcome(results[i].TxID, 5)
            VERIFY txOutcome.data EQUALS certs[i]
            VERIFY txOutcome.nonce EQUALS initialNonce + i + 1
        ```

  - **network resilience tests**
    - [1.2.32] should handle network timeouts and retries
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      account.setNetwork("testnet")
      initialNonce = account.Nonce

      // 2. Test various timeout scenarios
      TIMEOUT_SCENARIOS = [
          { timeout: 1000, retries: 3 },  // Short timeout, multiple retries
          { timeout: 5000, retries: 2 },  // Medium timeout, fewer retries
          { timeout: 10000, retries: 1 }  // Long timeout, single retry
      ]

      // 3. Test each timeout scenario
      FOR each scenario IN TIMEOUT_SCENARIOS
          MOCK_TIMEOUT = scenario.timeout
          MOCK_RETRIES = scenario.retries
          retryAttempts = 0

          // Attempt operation
          try {
              await account.updateAccount()
              VERIFY false  // Should not reach here
          } catch (error) {
              // Verify retry behavior
              VERIFY retryAttempts EQUALS scenario.retries
              VERIFY error.message INCLUDES "Timeout"
              VERIFY error.type IS "NetworkError"
          }

      // 4. Test exponential backoff
      MOCK_TIMEOUT = 1000
      MOCK_RETRIES = 3
      retryDelays = []

      try {
          await account.updateAccount()
          VERIFY false  // Should not reach here
      } catch (error) {
          // Verify backoff timing
          FOR i = 1 TO retryDelays.length - 1
              VERIFY retryDelays[i] GREATER THAN retryDelays[i-1]
      }
      ```

    - [1.2.33] should handle temporary network disconnections
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      account.setNetwork("testnet")
      initialNonce = account.Nonce

      // 2. Test various disconnection scenarios
      DISCONNECTION_SCENARIOS = [
          { duration: 1000, shouldRecover: true },   // Short disconnection
          { duration: 5000, shouldRecover: true },   // Medium disconnection
          { duration: 10000, shouldRecover: false }  // Long disconnection
      ]

      // 3. Test each disconnection scenario
      FOR each scenario IN DISCONNECTION_SCENARIOS
          MOCK_DISCONNECTION = scenario.duration
          
          // Attempt operation
          try {
              await account.updateAccount()
              VERIFY scenario.shouldRecover  // Should only succeed if shouldRecover is true
          } catch (error) {
              VERIFY NOT scenario.shouldRecover  // Should only fail if shouldRecover is false
              VERIFY error.message INCLUDES "Connection lost"
              VERIFY error.type IS "NetworkError"
          }

      // 4. Test reconnection behavior
      MOCK_DISCONNECTION = 2000
      MOCK_RECONNECTION_DELAY = 1000

      // First attempt should fail
      try {
          await account.updateAccount()
          VERIFY false  // Should not reach here
      } catch (error) {
          VERIFY error.message INCLUDES "Connection lost"
      }

      // Wait for recovery
      await WAIT(MOCK_RECONNECTION_DELAY)

      // Second attempt should succeed
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```

    - [1.2.34] should handle rate limiting and backoff
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      account.setNetwork("testnet")
      initialNonce = account.Nonce

      // 2. Test rate limiting scenarios
      RATE_LIMIT_SCENARIOS = [
          { limit: 10, window: 1000 },  // 10 requests per second
          { limit: 100, window: 60000 } // 100 requests per minute
      ]

      // 3. Test each rate limit scenario
      FOR each scenario IN RATE_LIMIT_SCENARIOS
          MOCK_RATE_LIMIT = scenario
          requestCount = 0
          startTime = Date.now()

          // Make multiple requests
          FOR i = 1 TO scenario.limit + 5  // Exceed the limit
              try {
                  await account.updateAccount()
                  requestCount++
              } catch (error) {
                  // Verify rate limit error
                  VERIFY error.message INCLUDES "Rate limit exceeded"
                  VERIFY error.type IS "RateLimitError"
                  break
              }

          // Verify rate limit behavior
          elapsedTime = Date.now() - startTime
          VERIFY requestCount LESS THAN OR EQUAL TO scenario.limit
          VERIFY elapsedTime LESS THAN scenario.window

      // 4. Test backoff behavior
      MOCK_RATE_LIMIT = { limit: 5, window: 1000 }
      backoffDelays = []

      // Exceed rate limit
      FOR i = 1 TO 10
          try {
              await account.updateAccount()
          } catch (error) {
              backoffDelays.push(error.retryAfter)
          }

      // Verify increasing backoff
      FOR i = 1 TO backoffDelays.length - 1
          VERIFY backoffDelays[i] GREATER THAN backoffDelays[i-1]
      ```

    - [1.2.35] should maintain state during network issues
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      account.setNetwork("testnet")
      initialNonce = account.Nonce
      initialState = {
          address: account.address,
          publicKey: account.publicKey,
          info: account.info,
          blockchain: account.blockchain
      }

      // 2. Test state preservation during various network issues
      NETWORK_ISSUES = [
          { type: "timeout", duration: 5000 },
          { type: "disconnection", duration: 3000 },
          { type: "rate_limit", duration: 2000 },
          { type: "partial_failure", duration: 1000 }
      ]

      // 3. Test each network issue
      FOR each issue IN NETWORK_ISSUES
          MOCK_NETWORK_ISSUE = issue
          
          // Attempt operation
          try {
              await account.updateAccount()
          } catch (error) {
              // Verify state preservation
              VERIFY account.address EQUALS initialState.address
              VERIFY account.publicKey EQUALS initialState.publicKey
              VERIFY account.info EQUALS initialState.info
              VERIFY account.blockchain EQUALS initialState.blockchain
          }

      // 4. Test state recovery after network issues
      MOCK_NETWORK_ISSUE = { type: "disconnection", duration: 2000 }
      
      // First attempt should fail
      try {
          await account.updateAccount()
          VERIFY false  // Should not reach here
      } catch (error) {
          // Verify state preserved
          VERIFY account.address EQUALS initialState.address
      }

      // Wait for recovery
      await WAIT(2000)

      // Second attempt should succeed
      result = await account.updateAccount()
      VERIFY result IS TRUE
      VERIFY account.Nonce GREATER THAN initialNonce
      ```

### 1.3 Transaction Management Tests
#### CEP_Account Class Tests

  - **CEP_Account Class**
    - [1.3.1] should handle transaction submission with valid data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = "test data"
      
      // 2. Submit transaction
      result = await account.submitTransaction(testData)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      VERIFY account.LatestTxID EQUALS result.TxID
      VERIFY account.Nonce EQUALS initialNonce + 1
      ```
    - [1.3.2] should handle transaction submission with 1KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = GENERATE_RANDOM_DATA(1024)  // 1KB
      
      // 2. Submit transaction
      result = await account.submitTransaction(testData)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS testData
      VERIFY txOutcome.size EQUALS 1024
      ```
    - [1.3.3] should handle transaction submission with 2KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = GENERATE_RANDOM_DATA(2048)  // 2KB
      
      // 2. Submit transaction
      result = await account.submitTransaction(testData)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS testData
      VERIFY txOutcome.size EQUALS 2048
      ```
    - [1.3.4] should handle transaction submission with 5KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = GENERATE_RANDOM_DATA(5120)  // 5KB
      
      // 2. Submit transaction
      result = await account.submitTransaction(testData)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS testData
      VERIFY txOutcome.size EQUALS 5120
      ```
    - [1.3.5] should handle concurrent transaction submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = ["data1", "data2", "data3"]
      
      // 2. Submit transactions concurrently
      results = await Promise.all(
          testData.map(data => account.submitTransaction(data))
      )
      
      // 3. Verify all submissions
      FOR each result IN results
          VERIFY result.Result EQUALS 200
          VERIFY result.TxID IS_NOT_EMPTY
      
      // 4. Verify nonce sequence
      VERIFY account.Nonce EQUALS initialNonce + testData.length
      ```
    - [1.3.6] should handle network errors during submission
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      MOCK_NETWORK_ERROR = TRUE
      
      // 2. Submit transaction
      result = await account.submitTransaction("test data")
      
      // 3. Verify error handling
      VERIFY result.Result EQUALS 500
      VERIFY result.Message INCLUDES "Network error"
      VERIFY account.Nonce EQUALS initialNonce
      ```
    - [1.3.7] should maintain transaction order with multiple submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      testData = ["data1", "data2", "data3"]
      
      // 2. Submit transactions sequentially
      results = []
      FOR each data IN testData
          result = await account.submitTransaction(data)
          results.push(result)
      
      // 3. Verify transaction order
      FOR i = 0 TO results.length - 1
          txOutcome = await account.getTransactionOutcome(results[i].TxID, 5)
          VERIFY txOutcome.data EQUALS testData[i]
          VERIFY txOutcome.nonce EQUALS initialNonce + i + 1
      ```
    - [1.3.8] should handle transaction submission with invalid data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      
      // 2. Test invalid data types
      invalidData = [NULL, 123, {}, [], UNDEFINED]
      
      FOR each data IN invalidData
          result = await account.submitTransaction(data)
          VERIFY result.Result EQUALS 400
          VERIFY result.Message INCLUDES "Invalid data format"
          VERIFY account.Nonce EQUALS initialNonce
      ```
    - [1.3.9] should handle transaction submission with empty data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      
      // 2. Submit empty transaction
      result = await account.submitTransaction("")
      
      // 3. Verify error handling
      VERIFY result.Result EQUALS 400
      VERIFY result.Message INCLUDES "Empty data"
      VERIFY account.Nonce EQUALS initialNonce
      ```
    - [1.3.10] should handle transaction submission with oversized data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      initialNonce = account.Nonce
      oversizedData = GENERATE_RANDOM_DATA(1024 * 1024)  // 1MB
      
      // 2. Submit oversized transaction
      result = await account.submitTransaction(oversizedData)
      
      // 3. Verify error handling
      VERIFY result.Result EQUALS 400
      VERIFY result.Message INCLUDES "Data too large"
      VERIFY account.Nonce EQUALS initialNonce
      ```
# Circular Enterprise APIs Test Suite

## 2. Integration Tests
### 2.1 Network Integration
- **CEP_Account Live Network Tests (against mainnet, testnet & devnet live networks)**
  - **open account method**
    - [2.1.1] should open account with valid address on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..." // Real blockchain address
      
      // 2. Open account
      account.open(validAddress)
      
      // 3. Verify account state
      VERIFY account.address EQUALS validAddress
      VERIFY account.publicKey IS_NOT_EMPTY
      VERIFY account.info IS_NOT_EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      ```
    - [2.1.2] should handle invalid address formats on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      invalidAddresses = [
          "0x",                    // Too short
          "0x123",                 // Invalid length
          "0xabcdefghijklmnop",   // Invalid characters
          "1234567890abcdef"      // Missing 0x prefix
      ]
      
      // 2. Test each invalid address
      FOR each addr IN invalidAddresses
          VERIFY CALLING account.open(addr) RAISES "Invalid address format"
      ```
    - [2.1.3] should maintain account state after opening on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account
      account.open(validAddress)
      initialState = {
          address: account.address,
          publicKey: account.publicKey,
          info: account.info
      }
      
      // 3. Perform some operations
      account.setBlockchain("0xnewchain")
      account.setNetwork("testnet")
      
      // 4. Verify state maintained
      VERIFY account.address EQUALS initialState.address
      VERIFY account.publicKey EQUALS initialState.publicKey
      VERIFY account.info EQUALS initialState.info
      ```

  - **close account method**
    - [2.1.4] should close account and reset state on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setBlockchain("0xchain")
      account.setNetwork("testnet")
      
      // 2. Close account
      account.close()
      
      // 3. Verify reset state
      VERIFY account.address IS EMPTY
      VERIFY account.publicKey IS EMPTY
      VERIFY account.info IS EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      VERIFY account.NAG_URL EQUALS DEFAULT_NAG
      VERIFY account.Nonce IS 0
      ```
    - [2.1.5] should handle closing non-existent account on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      
      // 2. Close without opening
      account.close()
      
      // 3. Verify default state
      VERIFY account.address IS EMPTY
      VERIFY account.publicKey IS EMPTY
      VERIFY account.info IS EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      ```

  - **set blockchain method**
    - [2.1.6] should set blockchain and maintain state on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      newChain = "0xmynewchain"
      
      // 2. Set blockchain
      account.setBlockchain(newChain)
      
      // 3. Verify state
      VERIFY account.blockchain IS newChain
      VERIFY account.address IS NOT EMPTY
      VERIFY account.publicKey IS NOT EMPTY
      
      // 4. Verify network connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.7] should handle invalid blockchain IDs on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      invalidChains = [
          NULL,
          "",
          "invalid",
          "0x",           // Too short
          "0x123"         // Invalid format
      ]
      
      // 2. Test each invalid chain
      FOR each chain IN invalidChains
          VERIFY CALLING account.setBlockchain(chain) RAISES "Invalid blockchain ID"
      ```

  - **set network method**
    - [2.1.8] should set network and update NAG_URL for mainnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      
      // 2. Set mainnet
      await account.setNetwork('mainnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://mainnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.9] should set network and update NAG_URL for testnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      
      // 2. Set testnet
      await account.setNetwork('testnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://testnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.10] should set network and update NAG_URL for devnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      
      // 2. Set devnet
      await account.setNetwork('devnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://devnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.11] should handle network connection failures
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      
      // 2. Simulate network failure
      MOCK_NETWORK_FAILURE = TRUE
      
      // 3. Attempt network change
      VERIFY CALLING account.setNetwork('mainnet') RAISES "Network connection failed"
      
      // 4. Verify state unchanged
      VERIFY account.NAG_URL EQUALS DEFAULT_NAG
      ```

  - **update account method**
    - [2.1.12] should update account nonce on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      initialNonce = account.Nonce
      
      // 2. Update account
      result = await account.updateAccount()
      
      // 3. Verify nonce update
      VERIFY result IS TRUE
      VERIFY account.Nonce GREATER THAN initialNonce
      ```
    - [2.1.13] should maintain correct nonce sequence across multiple updates
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      nonces = []
      
      // 2. Perform multiple updates
      FOR i = 1 TO 5
          await account.updateAccount()
          nonces.push(account.Nonce)
      
      // 3. Verify nonce sequence
      FOR i = 1 TO nonces.length - 1
          VERIFY nonces[i] EQUALS nonces[i-1] + 1
      ```
    - [2.1.14] should handle network errors during update
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      initialNonce = account.Nonce
      
      // 2. Simulate network error
      MOCK_NETWORK_ERROR = TRUE
      
      // 3. Attempt update
      result = await account.updateAccount()
      
      // 4. Verify error handling
      VERIFY result IS FALSE
      VERIFY account.Nonce EQUALS initialNonce
      VERIFY account.lastError INCLUDES "Network error"
      ```

  - **sign data method**
    - [2.1.15] should sign data and verify signature on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(realAddress)
      account.setNetwork("testnet")
      testData = "test data for signing"
      realPrivateKey = "0x1234567890abcdef"  // Real private key for testnet

      // 2. Test signature generation
      signature = account.signData(testData, realPrivateKey)

      // 3. Verify signature format
      VERIFY signature IS STRING
      VERIFY signature.length GREATER THAN 0
      VERIFY signature MATCHES /^[0-9a-f]+$/  // Should be hex

      // 4. Verify signature on real network
      verificationResult = await VERIFY_SIGNATURE_ON_NETWORK(
          testData,
          signature,
          account.publicKey,
          "testnet"
      )
      VERIFY verificationResult IS TRUE

      // 5. Test with different data types
      TEST_DATA_TYPES = [
          "simple string",
          "Hello 世界",  // Unicode
          "Special chars: !@#$%^&*()",
          "1234567890",
          "0x1234567890abcdef"
      ]

      FOR each data IN TEST_DATA_TYPES
          signature = account.signData(data, realPrivateKey)
          verificationResult = await VERIFY_SIGNATURE_ON_NETWORK(
              data,
              signature,
              account.publicKey,
              "testnet"
          )
          VERIFY verificationResult IS TRUE
      ```
    - [2.1.16] should handle signing with invalid private keys
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(realAddress)
      account.setNetwork("testnet")
      testData = "test data"

      // 2. Test invalid private key formats
      INVALID_PRIVATE_KEYS = [
          "0x",                    // Too short
          "0x123",                 // Invalid length
          "0xabcdefghijklmnop",   // Invalid characters
          "1234567890abcdef",     // Missing 0x prefix
          "0x" + "0".repeat(64),  // All zeros
          "0x" + "f".repeat(64),  // All ones
          null,                    // Null key
          undefined,              // Undefined key
          "",                     // Empty string
          "not_a_hex_string"      // Non-hex string
      ]

      // 3. Test each invalid key
      FOR each key IN INVALID_PRIVATE_KEYS
          try {
              account.signData(testData, key)
              VERIFY false  // Should not reach here
          } catch (error) {
              // Verify error
              VERIFY error.message INCLUDES "Invalid private key"
          }

      // 4. Test with malformed but valid-length keys
      MALFORMED_KEYS = [
          "0x" + "1".repeat(64),  // Valid length but invalid key
          "0x" + "a".repeat(64),  // Valid length but invalid key
          "0x" + "9".repeat(64)   // Valid length but invalid key
      ]

      FOR each key IN MALFORMED_KEYS
          try {
              account.signData(testData, key)
              VERIFY false  // Should not reach here
          } catch (error) {
              // Verify error
              VERIFY error.message INCLUDES "Invalid private key"
          }
      ```
    - [2.1.17] should maintain signature consistency across networks
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(realAddress)
      testData = "test data for consistency"
      realPrivateKey = "0x1234567890abcdef"
      networks = ["mainnet", "testnet", "devnet"]
      signatures = []

      // 2. Generate signatures on each network
      FOR each network IN networks
          account.setNetwork(network)
          signature = account.signData(testData, realPrivateKey)
          signatures.push(signature)

      // 3. Verify all signatures are identical
      FOR i = 1 TO signatures.length - 1
          VERIFY signatures[i] EQUALS signatures[0]

      // 4. Verify each signature on its respective network
      FOR i = 0 TO networks.length - 1
          verificationResult = await VERIFY_SIGNATURE_ON_NETWORK(
              testData,
              signatures[i],
              account.publicKey,
              networks[i]
          )
          VERIFY verificationResult IS TRUE

      // 5. Test with different data types across networks
      TEST_DATA_TYPES = [
          "simple string",
          "Hello 世界",  // Unicode
          "Special chars: !@#$%^&*()",
          "1234567890",
          "0x1234567890abcdef"
      ]

      FOR each data IN TEST_DATA_TYPES
          signatures = []
          FOR each network IN networks
              account.setNetwork(network)
              signature = account.signData(data, realPrivateKey)
              signatures.push(signature)
          
          // Verify consistency
          FOR i = 1 TO signatures.length - 1
              VERIFY signatures[i] EQUALS signatures[0]
          
          // Verify on each network
          FOR i = 0 TO networks.length - 1
              verificationResult = await VERIFY_SIGNATURE_ON_NETWORK(
                  data,
                  signatures[i],
                  account.publicKey,
                  networks[i]
              )
              VERIFY verificationResult IS TRUE

      // 6. Test signature uniqueness
      // Generate signatures for different data
      data1 = "test data 1"
      data2 = "test data 2"
      signature1 = account.signData(data1, realPrivateKey)
      signature2 = account.signData(data2, realPrivateKey)
      VERIFY signature1 NOT EQUALS signature2

      // 7. Test signature determinism
      // Generate multiple signatures for same data
      signature1 = account.signData(testData, realPrivateKey)
      signature2 = account.signData(testData, realPrivateKey)
      VERIFY signature1 EQUALS signature2
      ```

  - **get transaction method**
    - [2.1.18] should fetch a transaction by block number and ID on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Submit a test transaction
      testData = "test transaction data"
      submitResult = await account.submitCertificate(testData, mockPrivateKey)
      
      // 3. Get transaction details
      txResult = await account.getTransaction(
          submitResult.blockNumber,
          submitResult.TxID
      )
      
      // 4. Verify transaction data
      VERIFY txResult.Result EQUALS 200
      VERIFY txResult.Response.id EQUALS submitResult.TxID
      VERIFY txResult.Response.status EQUALS "Confirmed"
      VERIFY txResult.Response.data EQUALS testData
      VERIFY txResult.Response.blockNumber EQUALS submitResult.blockNumber
      VERIFY txResult.Response.timestamp IS NOT NULL
      ```
    - [2.1.19] should handle non-existent transactions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Attempt to get non-existent transaction
      nonExistentTxID = "0x" + "0".repeat(64)  // Valid format but non-existent
      blockNum = 1000000  // Far future block
      
      // 3. Get transaction details
      txResult = await account.getTransaction(blockNum, nonExistentTxID)
      
      // 4. Verify error handling
      VERIFY txResult.Result EQUALS 404
      VERIFY txResult.Message INCLUDES "Transaction Not Found"
      VERIFY txResult.Response IS NULL
      ```
    - [2.1.20] should handle invalid block numbers
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Test various invalid block numbers
      invalidBlocks = [
          -1,           // Negative block
          0,            // Zero block
          999999999,   // Far future block
          "invalid",    // Non-numeric
          NULL         // Null value
      ]
      
      // 3. Test each invalid block
      FOR each block IN invalidBlocks
          txResult = await account.getTransaction(block, "0x123...")
          VERIFY txResult.Result EQUALS 400
          VERIFY txResult.Message INCLUDES "Invalid block number"
          VERIFY txResult.Response IS NULL
      ```

  - **get transaction outcome method**
    - [2.1.21] should handle transaction polling and timeouts on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      txID = "pollTxID456"
      account.intervalSec = 1
      
      // 2. Submit transaction and get outcome
      result = await account.submitCertificate("test data", mockPrivateKey)
      outcome = await account.getTransactionOutcome(result.TxID, 3)
      
      // 3. Verify outcome
      VERIFY outcome.Status EQUALS "Confirmed"
      VERIFY outcome.data EQUALS "test data"
      ```
    - [2.1.22] should handle pending transaction states
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      txID = "pendingTx789"
      account.intervalSec = 1
      
      // 2. Submit transaction
      result = await account.submitCertificate("pending test", mockPrivateKey)
      
      // 3. Get outcome with short timeout
      outcome = await account.getTransactionOutcome(result.TxID, 1)
      
      // 4. Verify pending state
      VERIFY outcome.Status EQUALS "Pending"
      ```
    - [2.1.23] should handle transaction not found scenarios
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      nonExistentTxID = "nonexistent123"
      
      // 2. Attempt to get outcome
      outcome = await account.getTransactionOutcome(nonExistentTxID, 2)
      
      // 3. Verify not found handling
      VERIFY outcome.Status EQUALS "Not Found"
      ```
    - [2.1.24] should validate transaction outcomes match submitted data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open(mockAddress)
      testData = "validation test data"
      
      // 2. Submit and verify
      result = await account.submitCertificate(testData, mockPrivateKey)
      outcome = await account.getTransactionOutcome(result.TxID, 5)
      
      // 3. Verify data integrity
      VERIFY outcome.Status EQUALS "Confirmed"
      VERIFY outcome.data EQUALS testData
      VERIFY outcome.timestamp IS NOT NULL
      VERIFY outcome.blockNumber IS NOT NULL
      ```

  - **submit certificate method**
    - [2.1.25] should submit a certificate successfully on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      testData = "test certificate data"
      initialNonce = account.Nonce
      
      // 2. Submit certificate
      result = await account.submitCertificate(testData, mockPrivateKey)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS NOT NULL
      VERIFY result.Message EQUALS "Transaction Added"
      VERIFY account.LatestTxID EQUALS result.TxID
      VERIFY account.Nonce EQUALS initialNonce + 1
      ```
    - [2.1.26] should handle certificate submission with 1KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Generate 1KB test data
      cert_1kb = generateCertificateWithSize(1024)
      
      // 3. Submit certificate
      result = await account.submitCertificate(cert_1kb, mockPrivateKey)
      
      // 4. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS NOT NULL
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 5. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_1kb
      ```
    - [2.1.27] should handle certificate submission with 2KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Generate 2KB test data
      cert_2kb = generateCertificateWithSize(2048)
      
      // 3. Submit certificate
      result = await account.submitCertificate(cert_2kb, mockPrivateKey)
      
      // 4. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS NOT NULL
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 5. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_2kb
      ```
    - [2.1.28] should handle certificate submission with 5KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      
      // 2. Generate 5KB test data
      cert_5kb = generateCertificateWithSize(5120)
      
      // 3. Submit certificate
      result = await account.submitCertificate(cert_5kb, mockPrivateKey)
      
      // 4. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS NOT NULL
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 5. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_5kb
      ```
    - [2.1.29] should handle concurrent certificate submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      initialNonce = account.Nonce
      
      // 2. Prepare multiple certificates
      certs = [
          "cert1",
          "cert2",
          "cert3"
      ]
      
      // 3. Submit concurrently
      results = await Promise.all(
          certs.map(cert => account.submitCertificate(cert, mockPrivateKey))
      )
      
      // 4. Verify all submissions
      FOR each result IN results
          VERIFY result.Result EQUALS 200
          VERIFY result.TxID IS NOT NULL
      
      // 5. Verify nonce sequence
      VERIFY account.Nonce EQUALS initialNonce + certs.length
      ```
    - [2.1.30] should handle network errors during submission
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      initialNonce = account.Nonce
      
      // 2. Simulate network error
      MOCK_NETWORK_ERROR = TRUE
      
      // 3. Attempt submission
      result = await account.submitCertificate("test data", mockPrivateKey)
      
      // 4. Verify error handling
      VERIFY result.Result EQUALS 500
      VERIFY result.Message INCLUDES "Network error"
      VERIFY account.Nonce EQUALS initialNonce
      ```
    - [2.1.31] should maintain transaction order with multiple submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      account.open("0x123...")
      account.setNetwork("testnet")
      initialNonce = account.Nonce
      
      // 2. Submit sequence of certificates
      certs = [
          "cert1",
          "cert2",
          "cert3"
      ]
      results = []
      
      FOR each cert IN certs
          result = await account.submitCertificate(cert, mockPrivateKey)
          results.push(result)
      
      // 3. Verify transaction order
      FOR i = 0 TO results.length - 1
          txOutcome = await account.getTransactionOutcome(results[i].TxID, 5)
          VERIFY txOutcome.data EQUALS certs[i]
          VERIFY txOutcome.nonce EQUALS initialNonce + i + 1
      ```

  - **network resilience tests**
    - [2.1.32] should handle network timeouts and retries
    - [2.1.33] should handle temporary network disconnections
    - [2.1.34] should handle rate limiting and backoff
    - [2.1.35] should maintain state during network issues


### 2.1 Network Integration Tests
#### CEP_Account Class Tests

  - **CEP_Account Class**
    - [2.1.1] should connect to mainnet successfully
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Connect to mainnet
      await account.setNetwork('mainnet')
      await account.open(validAddress)
      
      // 3. Verify account state
      VERIFY account.address EQUALS validAddress
      VERIFY account.publicKey IS_NOT_EMPTY
      VERIFY account.info IS_NOT_EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      ```
    - [2.1.2] should handle invalid address formats on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      invalidAddresses = [
          "0x",  // Too short
          "0x123",  // Invalid length
          "0x1234567890abcdef",  // Invalid checksum
          "0x1234567890abcdef1234567890abcdef12345678",  // Invalid format
          "0x1234567890abcdef1234567890abcdef1234567890"  // Too long
      ]
      
      // 2. Test each invalid address
      FOR each addr IN invalidAddresses
          VERIFY CALLING account.open(addr) RAISES "Invalid address format"
      ```
    - [2.1.3] should maintain account state after opening on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account
      await account.open(validAddress)
      initialState = {
          address: account.address,
          publicKey: account.publicKey,
          info: account.info
      }
      
      // 3. Perform network operations
      await account.updateAccount()
      await account.setNetwork('testnet')
      await account.setNetwork('mainnet')
      
      // 4. Verify state maintained
      VERIFY account.address EQUALS initialState.address
      VERIFY account.publicKey EQUALS initialState.publicKey
      VERIFY account.info EQUALS initialState.info
      ```
    - [2.1.4] should handle closing account on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open and close account
      await account.open(validAddress)
      await account.close()
      
      // 3. Verify reset state
      VERIFY account.address IS EMPTY
      VERIFY account.publicKey IS EMPTY
      VERIFY account.info IS EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      VERIFY account.NAG_URL EQUALS DEFAULT_NAG
      VERIFY account.Nonce IS 0
      ```
    - [2.1.5] should handle closing non-existent account on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      
      // 2. Close non-existent account
      await account.close()
      
      // 3. Verify default state
      VERIFY account.address IS EMPTY
      VERIFY account.publicKey IS EMPTY
      VERIFY account.info IS EMPTY
      VERIFY account.blockchain EQUALS DEFAULT_CHAIN
      ```
    - [2.1.6] should handle blockchain changes on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      newChain = "0xmynewchain"
      
      // 2. Open account and change blockchain
      await account.open(validAddress)
      await account.setBlockchain(newChain)
      
      // 3. Verify state
      VERIFY account.blockchain IS newChain
      VERIFY account.address IS_NOT_EMPTY
      VERIFY account.publicKey IS_NOT_EMPTY
      
      // 4. Verify network connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.7] should handle invalid blockchain IDs on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      invalidChains = [
          "",  // Empty
          "0x",  // Too short
          "0x123",  // Invalid format
          "0x1234567890abcdef",  // Invalid length
          "0x1234567890abcdef1234567890abcdef12345678"  // Too long
      ]
      
      // 2. Test each invalid chain
      FOR each chain IN invalidChains
          VERIFY CALLING account.setBlockchain(chain) RAISES "Invalid blockchain ID"
      ```
    - [2.1.8] should set network and update NAG_URL for mainnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Set mainnet
      await account.open(validAddress)
      await account.setNetwork('mainnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://mainnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.9] should set network and update NAG_URL for testnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Set testnet
      await account.open(validAddress)
      await account.setNetwork('testnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://testnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.10] should set network and update NAG_URL for devnet
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Set devnet
      await account.open(validAddress)
      await account.setNetwork('devnet')
      
      // 3. Verify configuration
      VERIFY account.NAG_URL IS "https://devnet-nag.circularlabs.io/API/"
      VERIFY account.NETWORK_NODE IS_NOT_EMPTY
      
      // 4. Verify connectivity
      result = await account.updateAccount()
      VERIFY result IS TRUE
      ```
    - [2.1.11] should handle network connection failures
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      MOCK_NETWORK_ERROR = TRUE
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Attempt network change
      VERIFY CALLING account.setNetwork('mainnet') RAISES "Network connection failed"
      
      // 4. Verify state unchanged
      VERIFY account.NAG_URL EQUALS DEFAULT_NAG
      ```
    - [2.1.12] should handle account updates on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account and update
      await account.open(validAddress)
      initialNonce = account.Nonce
      result = await account.updateAccount()
      
      // 3. Verify nonce update
      VERIFY result IS TRUE
      VERIFY account.Nonce GREATER THAN initialNonce
      ```
    - [2.1.13] should maintain correct nonce sequence across multiple updates
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account and perform updates
      await account.open(validAddress)
      nonces = []
      
      FOR i = 1 TO 5
          await account.updateAccount()
          nonces.push(account.Nonce)
      
      // 3. Verify nonce sequence
      FOR i = 1 TO nonces.length - 1
          VERIFY nonces[i] EQUALS nonces[i-1] + 1
      ```
    - [2.1.14] should handle network errors during update
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      MOCK_NETWORK_ERROR = TRUE
      
      // 2. Open account and attempt update
      await account.open(validAddress)
      initialNonce = account.Nonce
      result = await account.updateAccount()
      
      // 4. Verify error handling
      VERIFY result IS FALSE
      VERIFY account.Nonce EQUALS initialNonce
      VERIFY account.lastError INCLUDES "Network error"
      ```
    - [2.1.15] should handle data signing on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      realPrivateKey = "0xabc..."
      
      // 2. Open account and sign data
      await account.open(validAddress)
      signature = account.signData(testData, realPrivateKey)
      
      // 3. Verify signature format
      VERIFY signature IS STRING
      VERIFY signature.length GREATER THAN 0
      VERIFY signature MATCHES /^[0-9a-f]+$/  // Should be hex
      
      // 4. Verify signature on real network
      verificationResult = await VERIFY_SIGNATURE(
          testData,
          signature,
          account.publicKey,
          "testnet"
      )
      VERIFY verificationResult IS TRUE
      
      // 5. Test with different data types
      testDataTypes = [
          "string",
          123,
          { key: "value" },
          [1, 2, 3],
          true,
          null
      ]
      
      FOR each data IN testDataTypes
          signature = account.signData(data, realPrivateKey)
          verificationResult = await VERIFY_SIGNATURE(
              data,
              signature,
              account.publicKey,
              "testnet"
          )
          VERIFY verificationResult IS TRUE
      ```
    - [2.1.16] should handle signing with invalid private keys
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Test invalid private keys
      invalidKeys = [
          "",  // Empty
          "0x",  // Too short
          "0x123",  // Invalid length
          "0x1234567890abcdef",  // Invalid format
          "0x1234567890abcdef1234567890abcdef12345678",  // Invalid checksum
          "0x1234567890abcdef1234567890abcdef1234567890"  // Too long
      ]
      
      FOR each key IN invalidKeys
          try {
              account.signData(testData, key)
              VERIFY false  // Should not reach here
          } catch (error) {
              // Verify error
              VERIFY error.message INCLUDES "Invalid private key"
          }
      
      // 4. Test with wrong network private key
      wrongNetworkKey = "0xdef..."  // Key from different network
      
      try {
          account.signData(testData, wrongNetworkKey)
          VERIFY false  // Should not reach here
      } catch (error) {
          // Verify error
          VERIFY error.message INCLUDES "Invalid private key"
      }
      ```
    - [2.1.17] should maintain signature consistency across networks
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      realPrivateKey = "0xabc..."
      networks = ["mainnet", "testnet", "devnet"]
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Generate signatures on each network
      signatures = []
      
      FOR each network IN networks
          await account.setNetwork(network)
          signature = account.signData(testData, realPrivateKey)
          signatures.push(signature)
      
      // 3. Verify all signatures are identical
      FOR i = 1 TO signatures.length - 1
          VERIFY signatures[i] EQUALS signatures[0]
      
      // 4. Verify each signature on its respective network
      FOR i = 0 TO networks.length - 1
          verificationResult = await VERIFY_SIGNATURE(
              testData,
              signatures[i],
              account.publicKey,
              networks[i]
          )
          VERIFY verificationResult IS TRUE
      
      // 5. Test with different data types across networks
      testDataTypes = [
          "string",
          123,
          { key: "value" },
          [1, 2, 3],
          true,
          null
      ]
      
      FOR each data IN testDataTypes
          signatures = []
          
          FOR each network IN networks
              await account.setNetwork(network)
              signature = account.signData(data, realPrivateKey)
              signatures.push(signature)
          
          // Verify consistency
          FOR i = 1 TO signatures.length - 1
              VERIFY signatures[i] EQUALS signatures[0]
          
          // Verify on each network
          FOR i = 0 TO networks.length - 1
              verificationResult = await VERIFY_SIGNATURE(
                  data,
                  signatures[i],
                  account.publicKey,
                  networks[i]
              )
              VERIFY verificationResult IS TRUE
      
      // 6. Test signature uniqueness
      data1 = "test data 1"
      data2 = "test data 2"
      
      signature1 = account.signData(data1, realPrivateKey)
      signature2 = account.signData(data2, realPrivateKey)
      VERIFY signature1 NOT EQUALS signature2
      
      // 7. Test signature determinism
      // Generate multiple signatures for same data
      signature1 = account.signData(testData, realPrivateKey)
      signature2 = account.signData(testData, realPrivateKey)
      VERIFY signature1 EQUALS signature2
      ```
    - [2.1.18] should handle transaction retrieval on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      
      // 2. Submit transaction
      await account.open(validAddress)
      submitResult = await account.submitTransaction(testData)
      
      // 3. Retrieve transaction
      txResult = await account.getTransaction(
          submitResult.blockNumber,
          submitResult.TxID
      )
      
      // 4. Verify transaction data
      VERIFY txResult.Result EQUALS 200
      VERIFY txResult.Response.id EQUALS submitResult.TxID
      VERIFY txResult.Response.status EQUALS "Confirmed"
      VERIFY txResult.Response.data EQUALS testData
      VERIFY txResult.Response.blockNumber EQUALS submitResult.blockNumber
      VERIFY txResult.Response.timestamp IS_NOT_EMPTY
      
      // 5. Verify transaction metadata
      VERIFY txResult.Response.signature IS_NOT_EMPTY
      VERIFY txResult.Response.publicKey EQUALS account.publicKey
      VERIFY txResult.Response.nonce EQUALS account.Nonce - 1  // Previous nonce
      ```
    - [2.1.19] should handle non-existent transactions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Attempt to retrieve non-existent transaction
      txResult = await account.getTransaction(1, "0x123...")
      
      // 4. Verify error handling
      VERIFY txResult.Result EQUALS 404
      VERIFY txResult.Message INCLUDES "Transaction Not Found"
      VERIFY txResult.Response IS EMPTY
      ```
    - [2.1.20] should handle invalid block numbers
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Test invalid block numbers
      invalidBlocks = [
          -1,  // Negative
          0,   // Zero
          999999999  // Too large
      ]
      
      FOR each block IN invalidBlocks
          txResult = await account.getTransaction(block, "0x123...")
          VERIFY txResult.Result EQUALS 400
          VERIFY txResult.Message INCLUDES "Invalid block number"
          VERIFY txResult.Response IS EMPTY
      ```
    - [2.1.21] should handle transaction outcome retrieval
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      
      // 2. Submit transaction
      await account.open(validAddress)
      result = await account.submitTransaction(testData)
      
      // 3. Verify outcome
      outcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY outcome.Status EQUALS "Confirmed"
      VERIFY outcome.data EQUALS "test data"
      ```
    - [2.1.22] should handle pending transaction states
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      
      // 2. Submit transaction
      await account.open(validAddress)
      result = await account.submitTransaction(testData)
      
      // 3. Get outcome immediately
      outcome = await account.getTransactionOutcome(result.TxID, 0)
      
      // 4. Verify pending state
      VERIFY outcome.Status EQUALS "Pending"
      ```
    - [2.1.23] should handle transaction not found scenarios
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      
      // 2. Open account
      await account.open(validAddress)
      
      // 3. Get outcome for non-existent transaction
      outcome = await account.getTransactionOutcome("0x123...", 5)
      
      // 3. Verify not found handling
      VERIFY outcome.Status EQUALS "Not Found"
      ```
    - [2.1.24] should validate transaction outcomes match submitted data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      
      // 2. Submit transaction
      await account.open(validAddress)
      result = await account.submitTransaction(testData)
      
      // 3. Verify data integrity
      outcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY outcome.Status EQUALS "Confirmed"
      VERIFY outcome.data EQUALS testData
      VERIFY outcome.timestamp IS_NOT_EMPTY
      VERIFY outcome.blockNumber IS_NOT_EMPTY
      ```
    - [2.1.25] should handle certificate submission on real network
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificate
      await account.open(validAddress)
      initialNonce = account.Nonce
      result = await account.submitCertificate(testData, mockPrivateKey)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      VERIFY account.LatestTxID EQUALS result.TxID
      VERIFY account.Nonce EQUALS initialNonce + 1
      ```
    - [2.1.26] should handle certificate submission with 1KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      cert_1kb = GENERATE_RANDOM_DATA(1024)  // 1KB
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificate
      await account.open(validAddress)
      result = await account.submitCertificate(cert_1kb, mockPrivateKey)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_1kb
      ```
    - [2.1.27] should handle certificate submission with 2KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      cert_2kb = GENERATE_RANDOM_DATA(2048)  // 2KB
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificate
      await account.open(validAddress)
      result = await account.submitCertificate(cert_2kb, mockPrivateKey)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_2kb
      ```
    - [2.1.28] should handle certificate submission with 5KB data
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      cert_5kb = GENERATE_RANDOM_DATA(5120)  // 5KB
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificate
      await account.open(validAddress)
      result = await account.submitCertificate(cert_5kb, mockPrivateKey)
      
      // 3. Verify submission
      VERIFY result.Result EQUALS 200
      VERIFY result.TxID IS_NOT_EMPTY
      VERIFY result.Message EQUALS "Transaction Added"
      
      // 4. Verify data integrity
      txOutcome = await account.getTransactionOutcome(result.TxID, 5)
      VERIFY txOutcome.data EQUALS cert_5kb
      ```
    - [2.1.29] should handle concurrent certificate submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      certs = [
          "cert1",
          "cert2",
          "cert3"
      ]
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificates concurrently
      await account.open(validAddress)
      initialNonce = account.Nonce
      results = await Promise.all(
          certs.map(cert => account.submitCertificate(cert, mockPrivateKey))
      )
      
      // 3. Verify all submissions
      FOR each result IN results
          VERIFY result.Result EQUALS 200
          VERIFY result.TxID IS_NOT_EMPTY
      
      // 4. Verify nonce sequence
      VERIFY account.Nonce EQUALS initialNonce + certs.length
      ```
    - [2.1.30] should handle network errors during submission
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      testData = "test data"
      mockPrivateKey = "0xabc..."
      MOCK_NETWORK_ERROR = TRUE
      
      // 2. Submit certificate
      await account.open(validAddress)
      initialNonce = account.Nonce
      result = await account.submitCertificate(testData, mockPrivateKey)
      
      // 3. Verify error handling
      VERIFY result.Result EQUALS 500
      VERIFY result.Message INCLUDES "Network error"
      VERIFY account.Nonce EQUALS initialNonce
      ```
    - [2.1.31] should maintain transaction order with multiple submissions
      ```pseudocode
      // 1. Setup
      account = NEW CEP_Account()
      validAddress = "0x123..."
      certs = [
          "cert1",
          "cert2",
          "cert3"
      ]
      mockPrivateKey = "0xabc..."
      
      // 2. Submit certificates sequentially
      await account.open(validAddress)
      initialNonce = account.Nonce
      results = []
      
      FOR each cert IN certs
          result = await account.submitCertificate(cert, mockPrivateKey)
          results.push(result)
      
      // 3. Verify transaction order
      FOR i = 0 TO results.length - 1
          txOutcome = await account.getTransactionOutcome(results[i].TxID, 5)
          VERIFY txOutcome.data EQUALS certs[i]
          VERIFY txOutcome.nonce EQUALS initialNonce + i + 1
    ```
    
## 3. Security & Permission Tests
### 3.1 Account Permissions
- **Non-Permissioned Account Behavior**
  - [3.1.1] should not update account nonce for a non-permissioned address
  - [3.1.2] should not allow submitting a certificate from a non-permissioned account



## 4. Edge Case Tests
### 4.1 Data Handling
- **Certificate Size Tests**
  - [4.1.1] should handle 1KB certificates
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Generate 1KB certificate
    cert_1kb = generateCertificateWithSize(1024)
    
    // 3. Submit certificate
    result = await account.submitCertificate(cert_1kb, mockPrivateKey)
    
    // 4. Verify submission
    VERIFY result.Result EQUALS 200
    VERIFY result.TxID IS NOT NULL
    
    // 5. Verify data integrity
    txOutcome = await account.getTransactionOutcome(result.TxID, 5)
    VERIFY txOutcome.data EQUALS cert_1kb
    VERIFY txOutcome.size EQUALS 1024
    ```

  - [4.1.2] should handle 2KB certificates
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Generate 2KB certificate
    cert_2kb = generateCertificateWithSize(2048)
    
    // 3. Submit certificate
    result = await account.submitCertificate(cert_2kb, mockPrivateKey)
    
    // 4. Verify submission
    VERIFY result.Result EQUALS 200
    VERIFY result.TxID IS NOT NULL
    
    // 5. Verify data integrity
    txOutcome = await account.getTransactionOutcome(result.TxID, 5)
    VERIFY txOutcome.data EQUALS cert_2kb
    VERIFY txOutcome.size EQUALS 2048
    ```

  - [4.1.3] should handle 5KB certificates
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Generate 5KB certificate
    cert_5kb = generateCertificateWithSize(5120)
    
    // 3. Submit certificate
    result = await account.submitCertificate(cert_5kb, mockPrivateKey)
    
    // 4. Verify submission
    VERIFY result.Result EQUALS 200
    VERIFY result.TxID IS NOT NULL
    
    // 5. Verify data integrity
    txOutcome = await account.getTransactionOutcome(result.TxID, 5)
    VERIFY txOutcome.data EQUALS cert_5kb
    VERIFY txOutcome.size EQUALS 5120
    ```

### 4.2 Network Conditions
- **Transaction Processing**
  - [4.2.1] should handle network timeouts
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Test various timeout scenarios
    TIMEOUT_SCENARIOS = [
        { timeout: 1000, shouldFail: true },
        { timeout: 5000, shouldFail: false },
        { timeout: 10000, shouldFail: false }
    ]

    // 3. Test each timeout scenario
    FOR each scenario IN TIMEOUT_SCENARIOS
        MOCK_TIMEOUT = scenario.timeout
        
        // Attempt transaction
        try {
            result = await account.submitCertificate("test data", mockPrivateKey)
            VERIFY NOT scenario.shouldFail
        } catch (error) {
            VERIFY scenario.shouldFail
            VERIFY error.message INCLUDES "Timeout"
            VERIFY error.type IS "NetworkError"
        }
    ```

  - [4.2.2] should handle API errors
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Test various API error scenarios
    API_ERRORS = [
        { status: 400, message: "Bad Request" },
        { status: 401, message: "Unauthorized" },
        { status: 403, message: "Forbidden" },
        { status: 429, message: "Too Many Requests" },
        { status: 500, message: "Internal Server Error" },
        { status: 503, message: "Service Unavailable" }
    ]

    // 3. Test each error scenario
    FOR each error IN API_ERRORS
        MOCK_API_ERROR = error
        
        // Attempt transaction
        result = await account.submitCertificate("test data", mockPrivateKey)
        
        // Verify error handling
        VERIFY result.Result EQUALS error.status
        VERIFY result.Message INCLUDES error.message
        VERIFY result.TxID IS NULL
    ```

  - [4.2.3] should handle malformed responses
    ```pseudocode
    // 1. Setup
    account = NEW CEP_Account()
    account.open(mockAddress)
    account.setNetwork("testnet")

    // 2. Test various malformed response scenarios
    MALFORMED_RESPONSES = [
        { Result: 200 },  // Missing Response
        { Result: 200, Response: null },  // Null Response
        { Result: 200, Response: {} },  // Empty Response
        { Result: 200, Response: { Status: "Error" } },  // Error Status
        { Result: 200, Response: { TxID: null } },  // Null TxID
        { Result: 200, Response: { TxID: "" } },  // Empty TxID
        { Result: 200, Response: { TxID: "invalid" } }  // Invalid TxID
    ]

    // 3. Test each malformed response
    FOR each response IN MALFORMED_RESPONSES
        MOCK_API_RESPONSE = response
        
        // Attempt transaction
        result = await account.submitCertificate("test data", mockPrivateKey)
        
        // Verify error handling
        VERIFY result.Result EQUALS 500
        VERIFY result.Message INCLUDES "Invalid response"
        VERIFY result.TxID IS NULL
    ```
