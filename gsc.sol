// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MedChainGovernance (GSC)
 * @dev M-of-N Governance Smart Contract.
 * Manages the consortium authorities and the Break-Glass emergency protocol.
 */
contract MedChainGovernance {
    
    uint256 public validatorCount;
    uint256 public requiredSignatures; // La soglia 'M' (es. 17 su 25)

    mapping(address => bool) public isValidator; 
    mapping(address => bool) public whitelistedIdentityAuthorities; 
    
    // --- Strutture Dati ---
    struct Proposal {
        uint256 id;
        address targetAuthority;
        bool isWhitelisting; 
        uint256 signatureCount;
        bool executed;
        mapping(address => bool) hasSigned;
    }

    struct EmergencyRequest {
        uint256 id;
        address hospitalDid;
        bytes32 targetBlindedId;
        uint256 signatureCount;
        bool executed;
        mapping(address => bool) hasSigned;
        address[] approvers;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    uint256 public emergencyRequestCount;
    mapping(uint256 => EmergencyRequest) public emergencyRequests;

    // --- Eventi ---
    event ProposalCreated(uint256 id, address targetAuthority, bool isWhitelisting);
    event ProposalExecuted(uint256 id, address targetAuthority, bool isWhitelisting);
    event EmergencyAccessRequested(uint256 id, address hospitalDid, bytes32 blindedId);
    event EmergencyAccessGranted(address indexed hospitalDid, bytes32 indexed blindedId, address[] approvers);

    modifier onlyValidator() {
        require(isValidator[msg.sender], "Not a consortium validator");
        _;
    }

    constructor(address[] memory _validators, uint256 _requiredSignatures) {
        require(_validators.length > 0, "Validators required");
        require(_requiredSignatures > 0 && _requiredSignatures <= _validators.length, "Invalid threshold");

        for (uint256 i = 0; i < _validators.length; i++) {
            isValidator[_validators[i]] = true;
        }
        validatorCount = _validators.length;
        requiredSignatures = _requiredSignatures;
    }

    // --- 1. Gestione Identity Authorities ---
    function submitProposal(address _targetAuthority, bool _isWhitelisting) external onlyValidator {
        uint256 newId = proposalCount++;
        Proposal storage p = proposals[newId];
        p.id = newId;
        p.targetAuthority = _targetAuthority;
        p.isWhitelisting = _isWhitelisting;
        
        emit ProposalCreated(newId, _targetAuthority, _isWhitelisting);
    }

    function signProposal(uint256 _proposalId) external onlyValidator {
        Proposal storage p = proposals[_proposalId];
        require(!p.executed, "Proposal already executed");
        require(!p.hasSigned[msg.sender], "Already signed");

        p.hasSigned[msg.sender] = true;
        p.signatureCount++;

        if (p.signatureCount >= requiredSignatures) {
            p.executed = true;
            whitelistedIdentityAuthorities[p.targetAuthority] = p.isWhitelisting;
            emit ProposalExecuted(_proposalId, p.targetAuthority, p.isWhitelisting);
        }
    }

    // --- 2. Protocollo di Emergenza (Break-Glass) ---
    function requestEmergencyAccess(address _hospitalDid, bytes32 _blindedId) external {
        uint256 newId = emergencyRequestCount++;
        EmergencyRequest storage req = emergencyRequests[newId];
        req.id = newId;
        req.hospitalDid = _hospitalDid;
        req.targetBlindedId = _blindedId;

        emit EmergencyAccessRequested(newId, _hospitalDid, _blindedId);
    }

    function signEmergencyRequest(uint256 _reqId) external onlyValidator {
        EmergencyRequest storage req = emergencyRequests[_reqId];
        require(!req.executed, "Request already executed");
        require(!req.hasSigned[msg.sender], "Already signed");

        req.hasSigned[msg.sender] = true;
        req.approvers.push(msg.sender);
        req.signatureCount++;

        if (req.signatureCount >= requiredSignatures) {
            req.executed = true;
            emit EmergencyAccessGranted(req.hospitalDid, req.targetBlindedId, req.approvers);
        }
    }
}