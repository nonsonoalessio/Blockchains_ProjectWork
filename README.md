This project implements a blockchain-based system for the secure management of medical documents and access control. The system relies on two main smart contracts and includes a comprehensive test suite.

## Contract Architecture

The system consists of two smart contracts written in Solidity:

### MedChainGovernance (GSC)

* It is an M-of-N governance contract.
* Manages the consortium authorities (validators) and the "Break-Glass" emergency protocol.
* Allows validators to submit and sign proposals to add (whitelist) identity authorities.
* Handles emergency data access requests, requiring a specific signature threshold (e.g., 2 out of 3) for approval.

### MedChainVault (MSC)

* Acts as the Master Smart Contract and Document Vault.
* Handles the management of Access Control Tokens (ACT) and the implementation of cascading revocation.
* Interacts with the governance contract to verify that the caller's identity is valid and whitelisted.
* Allows document owners to register records (with CID, seal, and signature) and mint "Root ACTs" to delegate access.

## Key Security Features

* **Granular Access Control:** Supports specific `READ` and `WRITE` permissions for tokens.
* **Gas DoS Prevention:** The maximum access delegation depth is strictly limited to 3 to prevent Denial of Service attacks related to gas consumption.
* **Chain Integrity:** Whenever access is delegated or authorized, the contract verifies the entire token chain to ensure no parent node is expired or revoked.
* **Cascading Revocation:** Revoking a token automatically invalidates all tokens derived from it.

## Testing

The test suite is written in TypeScript using the Node.js test runner (`node:test`), Hardhat, and Viem.

The tests cover the following critical areas:

* **Governance Protocol:** Verifies the whitelisting of doctors and patients upon reaching the required threshold.
* **Document & ACT Management:** Tests the secure registration of documents, token minting, delegation, and cascading revocation while verifying gas consumption.
* **Edge Cases:**
* Emergency access approval (Break-Glass).
* Prevention of exceeding the delegation depth limit.
* Blocking revocation attempts by unauthorized users.
* Blocking privilege escalation attempts (e.g., using a `READ` token to authorize a `WRITE` operation).
* Rejection of expired or revoked tokens.
