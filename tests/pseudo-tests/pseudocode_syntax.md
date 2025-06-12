# Pseudocode Testing Language Syntax

This document defines a pseudocode syntax for writing test outlines, drawing inspiration from the `recover.md` file. It aims to provide a consistent and reusable structure for describing test scenarios.

## Core Concepts

*   **Suite**: A top-level collection of related tests. Represented by a main heading.
*   **Test**: A specific test case within a suite. Represented by a sub-heading.
*   **Setup/Teardown**: Actions performed before or after tests (e.g., `beforeEach`, `afterEach`).
*   **Action**: A step or operation performed within a test.
*   **Assertion**: A check or validation of expected behavior.
*   **Logging**: Outputting information for debugging or tracing.
*   **Conditional**: Logic that depends on certain conditions.
*   **Loop**: Repetitive execution of actions.
*   **Skip Condition**: A condition under which a test or action should be skipped.
*   **Retry Logic**: A mechanism for retrying actions on failure.

## Syntax Primitives and Grammar

Each action, assertion, logging, etc., should be clearly prefixed with its type. Indentation indicates nesting and hierarchy.

### Suite Definition

```pseudocode
# <Suite Name> - <Context/Purpose> (Top-level Suite)

- **Overall Timeout**: <Duration> (Adjustable, <Note about adjustment>)
```

**Example:**

```pseudocode
# Circular ESM Enterprise APIs - Live Network Integration (Top-level Suite)

- **Overall Timeout**: 150 seconds (Adjustable, 60 seconds from first JS, 150 from final JS)
```

### Test Definition

```pseudocode
#### <Test ID> - **Test**: <Test Description>
    - **Action**: <Description of action>
    - **Assertion**: <Description of assertion>
    - **Logging**: <Description of logging>
```

**Example:**

```pseudocode
#### 3.5.1 - **Test**: should update account nonce on real network
    - **Action**: Call `liveAccount.updateAccount()`.
    - **Assertion**: Result is true.
    - **Assertion**: `liveAccount.Nonce` is a number greater than 0.
    - **Logging**: Log "[PASS] Initial Nonce fetched: [account.Nonce]".
```

### Setup/Teardown Block

```pseudocode
#### <Section ID> - **Setup/Teardown**: <Description>
- **Action**: <Description of action>
- **Logging**: <Description of logging>
- **Conditional**: If <condition>, then <action>.
```

**Example (Setup):**

```pseudocode
#### 3.3.1 - **Setup**: (beforeEach for Live Network Tests)
- **Action**: Create a new `CEP_Account` instance (`account` or `liveAccount`).
- **Action**: Call `account.open(TESTNET_ACCOUNT_ADDRESS)`.
- **Logging**: Log "[TEST] Setting network...".
- **Conditional**: If `HARDCODED_NAG_URLS[currentNetwork]` exists, override `liveAccount.NAG_URL`.
```

**Example (Teardown):**

```pseudocode
#### 3.4.1 - **Teardown**: (afterEach for Live Network Tests)
- **Action**: Ensure `nock` is active (if it was used for mocking during setup).
- **Action**: Call `account.close()`.
```

### Environment Variable Setup

```pseudocode
#### <Section ID> - **Setup**: <Description>
    - **Action**: <Description of action>
    - **Logging**: **<Severity> DEBUG LOGS**: <Description of log content>.
    - `<Function Name>` function:
        - **Action**: <Description of function action>.
        - **Action**: <Description of function action>.
    - **Assertion**: <Variable Name>: <Description of assertion>.
```

**Example:**

```pseudocode
#### 3.2.2 - **Setup**: Live Network Specific Environment Variables
    - **Action**: Load `.env` file.
    - **Logging**: **CRITICAL DEBUG LOGS**: Log presence and type of key environment variables.
    - `requireEnv` function:
        - **Action**: Gets a required env variable.
        - **Action**: Throws a FATAL error if missing, placeholder, or length < 10.
    - **Assertion**: `TESTNET_CHAIN_ADDRESS`: Required env var `TESTNET_CIRCULAR_MAIN_PUBLIC_CHAIN_ADDRESS`.
```

### Detailed Test Flow with Retry Logic

```pseudocode
#### <Test ID> - **Test**: <Test Description>
- **Skip Condition**: If <condition>.
- **Logging**: Log <variable>.
- **Assertion**: <variable> equals <expected value>.

- **Action**: Await <function call>.
- **Assertion**: <variable> is <condition>.

- **Action**: Define <variable> with <value>.

- **Logging**: Log account state before submission (Address, Blockchain, Nonce, Data to sign, Private Key presence).

- **Retry Logic (MAX_RETRIES = <number>)**:
    - **Logging**: Log attempt number.
    - **Action**: Await <function call> (re-fetch nonce).
    - **Try-Catch Block**:
        - **Action**: Await <function call>.
        - **Logging**: Log full <result> from API.
        - **Conditional**:
            - If <condition>:
                - **Logging**: Log successful submission.
                - `break` from retry loop.
            - Else if <condition>:
                - **Logging**: Warn about <reason>.
                - **Action**: Increment `retries`.
                - **Action**: Wait <duration>.
            - Else (other errors):
                - **Action**: Throw error indicating <failure reason>.
        - **Catch (Error)**:
            - **Logging**: Log error during attempt.
            - **Action**: Rethrow error.

- **Assertion**: <variable> is not undefined.
- **Assertion**: <variable> equals <value>.

- **Action**: Await <function call>.
- **Logging**: Log received <outcome> data.

- **Assertion**: <variable> has property <property> equal to <value>.
```

**Example (from 3.6.1):**

```pseudocode
#### 3.6.1 - **Test**: should submit a certificate and confirm its outcome on the live network
- **Skip Condition**: If `TESTNET_ACCOUNT_ADDRESS` or `TESTNET_PRIVATE_KEY` are missing.
- **Logging**: Log the `targetNetwork`.
- **Assertion**: `account.address` equals `TESTNET_ACCOUNT_ADDRESS`.

- **Action**: Await `account.updateAccount()`.
- **Assertion**: `updateSuccess` is true.

- **Retry Logic (MAX_RETRIES = 3)**:
    - **Logging**: Log attempt number.
    - **Action**: Await `account.updateAccount()` (re-fetch nonce).
    - **Try-Catch Block**:
        - **Action**: Await `account.submitCertificate(certData, privateKey)`.
        - **Logging**: Log full `submitResult` from API.
        - **Conditional**:
            - If `submitResult.Result` is `200`:
                - **Logging**: Log successful submission.
                - `break` from retry loop.
            - Else if `submitResult.Result` is `120` AND `submitResult.Response` is 'Duplicate Nonce':
                - **Logging**: Warn about duplicate nonce.
                - **Action**: Increment `retries`.
                - **Action**: Wait 500ms.
            - Else (other non-200 errors):
                - **Action**: Throw error indicating submission failure.
        - **Catch (Error)**:
            - **Logging**: Log error during attempt.
            - **Action**: Rethrow error.

- **Assertion**: `submitResult` is not undefined.
- **Assertion**: `submitResult.Result` equals `200`.

- **Action**: Await `account.getTransactionOutcome(txID, 120)`.
- **Logging**: Log received `outcome` data.

- **Assertion**: `outcome` has property `ID` equal to `txID`.
- **Assertion**: `outcome` has property `Status` equal to 'Executed'.
```

## General Guidelines

*   Use clear, concise language.
*   Be specific in actions and assertions.
*   Indent to show nesting and logical flow.
*   Use bold for keywords like **Action**, **Assertion**, **Logging**, **Conditional**, **Loop**, **Skip Condition**, **Retry Logic**.
*   Refer to variables and function calls in `backticks`.
*   Use `// ... existing code ...` to indicate parts of the code that are not relevant to the current pseudocode description but would exist in a real implementation.

This pseudocode syntax provides a flexible framework for describing complex test scenarios in a human-readable format, bridging the gap between high-level test plans and actual code implementation. 