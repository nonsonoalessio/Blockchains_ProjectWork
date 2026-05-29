// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// --- Interfaccia per la Cross-Contract Communication ---
interface IMedChainGovernance {
    function whitelistedIdentityAuthorities(address _authority) external view returns (bool);
}

/**
 * @title MedChainVault (MSC)
 * @dev Master Smart Contract & Document Vault.
 * Implements plaintext ACT management and cascading revocation.
 */
contract MedChainVault {

    enum DocStatus { Created, Archived, Revoked }
    enum PermissionType { READ, WRITE }

    struct DocumentRecord {
        string cid;
        DocStatus status;
        bytes32 version;
        bytes seal;
        bytes signature;
        address owner; 
    }

    struct ACT {
        bytes32 tokenId;
        address ownerDid;
        bytes32 targetBlindedId; 
        PermissionType permType;
        uint256 expirationTimestamp;
        bool delegatable;
        bytes32 parentTokenId;
        uint256 delegationDepth;
    }

    mapping(bytes32 => DocumentRecord) public vault;
    mapping(bytes32 => ACT) public acts;
    mapping(bytes32 => bool) public revokedTokens;

    // Puntatore al Governance Contract
    IMedChainGovernance public governanceContract;

    event DocumentRegistered(bytes32 indexed blindedId, string cid);
    event ActMinted(bytes32 indexed tokenId, bytes32 indexed targetBlindedId, address ownerDid);
    event AccessAuthorized(bytes32 indexed requestHash);
    event TokenRevoked(bytes32 indexed tokenId);

    // Il modificatore che "telefona" al GSC per verificare l'identità
    modifier onlyValidIdentity(address _caller) {
        require(governanceContract.whitelistedIdentityAuthorities(_caller) == true, 
                "Identity revoked or not whitelisted by Governance");
        _;
    }

    // Al momento del deploy, colleghiamo il MSC al GSC
    constructor(address _governanceAddress) {
        governanceContract = IMedChainGovernance(_governanceAddress);
    }

    // --- Core Functions ---

    function registerDocument(bytes32 _blindedId, string memory _cid, bytes memory _seal, bytes memory _signature) external onlyValidIdentity(msg.sender) {
        require(vault[_blindedId].owner == address(0), "Document already exists");
        
        vault[_blindedId] = DocumentRecord({
            cid: _cid,
            status: DocStatus.Created,
            version: bytes32(uint256(1)),
            seal: _seal,
            signature: _signature,
            owner: msg.sender
        });
        
        emit DocumentRegistered(_blindedId, _cid);
    }

    function mintRootAct(bytes32 _tokenId, bytes32 _blindedId, uint256 _expiration) external onlyValidIdentity(msg.sender) {
        require(vault[_blindedId].owner == msg.sender, "Only document owner can mint root ACT");
        
        acts[_tokenId] = ACT({
            tokenId: _tokenId,
            ownerDid: msg.sender,
            targetBlindedId: _blindedId,
            permType: PermissionType.WRITE,
            expirationTimestamp: _expiration,
            delegatable: true,
            parentTokenId: bytes32(0),
            delegationDepth: 0
        });
        
        emit ActMinted(_tokenId, _blindedId, msg.sender);
    }

    function delegateAccess(bytes32 _parentTokenId, bytes32 _newTokenId, address _delegatee, PermissionType _perm, uint256 _expiration) external onlyValidIdentity(msg.sender) {
        ACT memory parent = acts[_parentTokenId];
        require(parent.ownerDid == msg.sender, "Not the parent token owner");
        require(parent.delegatable == true, "Parent token is not delegatable");
        
        // Difesa contro il DoS del Gas (WP3)
        require(parent.delegationDepth < 3, "Max delegation depth reached"); 
        
        // Verifica l'integrità della catena prima di permettere una delega
        require(checkChainIntegrity(_parentTokenId), "Parent chain is invalid, expired or revoked");

        acts[_newTokenId] = ACT({
            tokenId: _newTokenId,
            ownerDid: _delegatee,
            targetBlindedId: parent.targetBlindedId,
            permType: _perm,
            expirationTimestamp: _expiration,
            delegatable: true,
            parentTokenId: _parentTokenId,
            delegationDepth: parent.delegationDepth + 1
        });
        
        emit ActMinted(_newTokenId, parent.targetBlindedId, _delegatee);
    }

    function revokeToken(bytes32 _tokenId) external onlyValidIdentity(msg.sender) {
        // Può revocare il possessore del token, o il proprietario originale del documento
        require(acts[_tokenId].ownerDid == msg.sender || vault[acts[_tokenId].targetBlindedId].owner == msg.sender, "Not authorized to revoke");
        revokedTokens[_tokenId] = true;
        
        emit TokenRevoked(_tokenId);
    }

    function authorizeAccess(bytes32 _tokenId, bytes32 _targetBlindedId, PermissionType _requestedPerm, bytes32 _requestHash) external onlyValidIdentity(msg.sender) returns (bool) {
        ACT memory token = acts[_tokenId];
        require(token.ownerDid == msg.sender, "Caller does not own this token");
        require(token.targetBlindedId == _targetBlindedId, "Token mismatch");
        require(uint8(token.permType) >= uint8(_requestedPerm), "Insufficient permission");
        
        // La Revoca a Cascata (WP2/WP3)
        require(checkChainIntegrity(_tokenId), "Delegation chain invalid, expired, or revoked");

        emit AccessAuthorized(_requestHash);
        return true;
    }

    // --- Internal Logic ---
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