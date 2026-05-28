// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MedChainVault
 * @dev Proof of Concept for the MedChain Document Vault & Master Smart Contract.
 * Implements plaintext ACT management, bypassing ZKP for rapid prototyping.
 */
contract MedChainVault {

    // --- Enums & Structs ---

    enum DocStatus { Created, Archived, Revoked }
    enum PermissionType { READ, WRITE }

    struct DocumentRecord {
        string cid;
        DocStatus status;
        bytes32 version;
        bytes seal;
        bytes signature;
        address owner; // Represents the Patient's DID
    }

    struct ACT {
        bytes32 tokenId;
        address ownerDid;
        bytes32 targetBlindedId; // Binding the ACT to a specific document
        PermissionType permType;
        uint256 expirationTimestamp;
        bool delegatable;
        bytes32 parentTokenId;
        uint256 delegationDepth;
    }

    // --- State Variables ---

    // The Document Vault mapping BlindedID to DocumentRecord
    mapping(bytes32 => DocumentRecord) public vault;
    
    // The ACT Registry mapping tokenId to ACT
    mapping(bytes32 => ACT) public acts;
    
    // Spent nonce registry for replay protection
    mapping(bytes32 => bool) public spentNonces;
    
    // Revocation registry
    mapping(bytes32 => bool) public revokedTokens;
    
    // Mocking the Identity Authority Bitstring Status List
    mapping(address => bool) public isIdentityRevoked;

    // --- Events ---

    event DocumentRegistered(bytes32 indexed blindedId, string cid);
    event ACTMinted(bytes32 indexed tokenId, address indexed ownerDid, PermissionType permType, uint256 expirationTimestamp);
    event TokenRevoked(bytes32 indexed tokenId);
    event AccessAuthorized(bytes32 indexed requestHash);

    // --- Modifiers ---

    modifier onlyValidIdentity(address _did) {
        require(!isIdentityRevoked[_did], "Identity is revoked by Authority");
        _;
    }

    // --- Document Management ---

    /**
     * @dev Issues a new document into the vault.
     */
    function issueDocument(
        bytes32 _blindedId,
        string calldata _cid,
        bytes calldata _seal,
        bytes calldata _signature
    ) external onlyValidIdentity(msg.sender) {
        require(bytes(vault[_blindedId].cid).length == 0, "Document already exists");

        vault[_blindedId] = DocumentRecord({
            cid: _cid,
            status: DocStatus.Created,
            version: bytes32(0),
            seal: _seal,
            signature: _signature,
            owner: msg.sender
        });

        emit DocumentRegistered(_blindedId, _cid);
    }

    // --- Access Control & Delegation ---

    /**
     * @dev Mints a root ACT. Can only be called by the document owner.
     */
    function mintRootACT(
        bytes32 _tokenId,
        bytes32 _targetBlindedId,
        address _granteeDid,
        PermissionType _permType,
        uint256 _expiration,
        bool _delegatable,
        bytes32 _nonce
    ) external onlyValidIdentity(msg.sender) {
        require(vault[_targetBlindedId].owner == msg.sender, "Only owner can mint root ACT");
        require(!spentNonces[_nonce], "Nonce already spent");
        require(acts[_tokenId].ownerDid == address(0), "Token ID already exists");
        require(_expiration > block.timestamp, "Expiration must be in the future");

        spentNonces[_nonce] = true;

        acts[_tokenId] = ACT({
            tokenId: _tokenId,
            ownerDid: _granteeDid,
            targetBlindedId: _targetBlindedId,
            permType: _permType,
            expirationTimestamp: _expiration,
            delegatable: _delegatable,
            parentTokenId: bytes32(0),
            delegationDepth: 0
        });

        emit ACTMinted(_tokenId, _granteeDid, _permType, _expiration);
    }

    /**
     * @dev Sub-delegates an existing ACT. Enforces scope containment in plaintext.
     */
    function delegateACT(
        bytes32 _childTokenId,
        bytes32 _parentTokenId,
        address _granteeDid,
        PermissionType _childPermType,
        uint256 _childExpiration,
        bool _childDelegatable,
        bytes32 _nonce
    ) external onlyValidIdentity(msg.sender) {
        ACT memory parent = acts[_parentTokenId];
        
        require(parent.ownerDid == msg.sender, "Not authorized to delegate this parent token");
        require(parent.delegatable, "Parent token is not delegatable");
        require(!revokedTokens[_parentTokenId], "Parent token is revoked");
        require(parent.expirationTimestamp >= block.timestamp, "Parent token expired");
        
        // Scope Containment Checks
        require(_childExpiration <= parent.expirationTimestamp, "Child expiration exceeds parent");
        if (parent.permType == PermissionType.READ) {
            require(_childPermType == PermissionType.READ, "Cannot escalate READ to WRITE");
        }
        
        require(!spentNonces[_nonce], "Nonce already spent");
        require(acts[_childTokenId].ownerDid == address(0), "Child Token ID already exists");

        spentNonces[_nonce] = true;

        acts[_childTokenId] = ACT({
            tokenId: _childTokenId,
            ownerDid: _granteeDid,
            targetBlindedId: parent.targetBlindedId,
            permType: _childPermType,
            expirationTimestamp: _childExpiration,
            delegatable: _childDelegatable,
            parentTokenId: _parentTokenId,
            delegationDepth: parent.delegationDepth + 1
        });

        emit ACTMinted(_childTokenId, _granteeDid, _childPermType, _childExpiration);
    }

    /**
     * @dev Revokes an ACT. In this plaintext POC, we target the tokenId directly.
     */
    function revokeACT(bytes32 _tokenId) external {
        ACT memory token = acts[_tokenId];
        require(token.ownerDid != address(0), "Token does not exist");
        
        // Only the patient/owner or the direct delegator can revoke
        require(
            msg.sender == vault[token.targetBlindedId].owner || 
            msg.sender == acts[token.parentTokenId].ownerDid,
            "Not authorized to revoke"
        );

        revokedTokens[_tokenId] = true;
        emit TokenRevoked(_tokenId);
    }

    // --- Policy Enforcement Point (PEP) ---

    /**
     * @dev Evaluates the 5-step access pipeline.
     */
    function authorizeAccess(
        bytes32 _tokenId,
        bytes32 _targetBlindedId,
        PermissionType _requestedPerm,
        bytes32 _requestHash
    ) external onlyValidIdentity(msg.sender) returns (bool) {
        ACT memory token = acts[_tokenId];
        
        // 1 & 2. Existence & Ownership Check
        require(token.ownerDid == msg.sender, "Caller does not own this token");
        require(token.targetBlindedId == _targetBlindedId, "Token does not grant access to this document");
        
        // 3. Permission Type Check
        require(uint8(token.permType) >= uint8(_requestedPerm), "Insufficient permission type");

        // 4 & 5. Lifecycle and Chain Integrity Check
        require(checkChainIntegrity(_tokenId), "Delegation chain is invalid, expired, or revoked");

        emit AccessAuthorized(_requestHash);
        return true;
    }

    /**
     * @dev Recursively traverses the delegation graph upward to ensure no ancestor is revoked or expired.
     */
    function checkChainIntegrity(bytes32 _tokenId) internal view returns (bool) {
        bytes32 currentToken = _tokenId;
        
        while (currentToken != bytes32(0)) {
            if (revokedTokens[currentToken]) {
                return false;
            }
            if (acts[currentToken].expirationTimestamp < block.timestamp) {
                return false;
            }
            currentToken = acts[currentToken].parentTokenId;
        }
        return true;
    }
}