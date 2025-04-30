// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/Strings.sol"; // For uint to string conversion in events if needed

/**
 * @title VotingAdmin
 * @notice Manages admins (3 max) and multi-signature proposals for actions like
 * cancelling pools or replacing admins in a linked Voting contract.
 * Requires 2 out of 3 admin approvals for proposals.
 */
contract VotingAdmin {
    using Strings for uint256; // If using uint to string conversion

    // --- State Variables ---

    address[3] public admins;
    uint256 public constant REQUIRED_APPROVALS = 2;
    uint256 public constant MAX_ADMINS = 3;

    address public votingContract; // Address of the main Voting contract

    // --- Proposal Data Structures ---

    enum ProposalType { CancelPool, ReplaceAdmin }

    struct Proposal {
        uint256 id;             // Unique ID for the proposal
        ProposalType pType;     // Type of proposal (e.g., CancelPool)
        address proposer;       // Admin who created the proposal
        bytes data;             // Encoded data specific to the proposal type
        mapping(address => bool) approvals; // Tracks which admins have approved
        uint256 approvalCount;  // Current number of approvals
        bool executed;          // Flag indicating if the proposal has been executed
    }

    uint256 public nextProposalId;
    mapping(uint256 => Proposal) public proposals;

    // --- Events ---

    event AdminAdded(address indexed admin);
    event AdminReplaced(address indexed oldAdmin, address indexed newAdmin);
    event ProposalCreated(uint256 indexed proposalId, ProposalType pType, address indexed proposer, bytes data);
    event ProposalApproved(uint256 indexed proposalId, address indexed approver);
    event ProposalExecuted(uint256 indexed proposalId);
    event VotingContractSet(address indexed contractAddress);

    // --- Modifiers ---

    modifier onlyAdmin() {
        bool isAdmin = false;
        for (uint i = 0; i < MAX_ADMINS; i++) {
            if (admins[i] == msg.sender) {
                isAdmin = true;
                break;
            }
        }
        require(isAdmin, "VotingAdmin: Caller is not an admin");
        _;
    }

    // --- Constructor ---

    /**
     * @notice Sets up the initial 3 admin addresses.
     * @param _admin1 Address of the first admin.
     * @param _admin2 Address of the second admin.
     * @param _admin3 Address of the third admin.
     */
    constructor(address _admin1, address _admin2, address _admin3) {
        require(_admin1 != address(0) && _admin2 != address(0) && _admin3 != address(0), "VotingAdmin: Invalid admin address provided");
        require(_admin1 != _admin2 && _admin1 != _admin3 && _admin2 != _admin3, "VotingAdmin: Duplicate admin addresses");

        admins[0] = _admin1;
        admins[1] = _admin2;
        admins[2] = _admin3;

        emit AdminAdded(_admin1);
        emit AdminAdded(_admin2);
        emit AdminAdded(_admin3);
    }

    // --- Admin Management (Requires Multi-sig Proposals) ---

    /**
     * @notice Proposes replacing an existing admin with a new one. Requires multi-sig approval.
     * @param _oldAdmin The current admin address to be replaced.
     * @param _newAdmin The new address to become an admin.
     */
    function proposeReplaceAdmin(address _oldAdmin, address _newAdmin) external onlyAdmin {
        require(_newAdmin != address(0), "VotingAdmin: New admin cannot be zero address");

        bool oldAdminFound = false;
        bool newAdminAlreadyExists = false;
        for(uint i = 0; i < MAX_ADMINS; i++) {
            if (admins[i] == _oldAdmin) oldAdminFound = true;
            if (admins[i] == _newAdmin) newAdminAlreadyExists = true;
        }
        require(oldAdminFound, "VotingAdmin: Address to replace is not an admin");
        require(!newAdminAlreadyExists, "VotingAdmin: New address is already an admin");

        bytes memory data = abi.encode(_oldAdmin, _newAdmin);
        _createProposal(ProposalType.ReplaceAdmin, data);
    }

    /**
     * @notice Internal function to execute the replacement after approval.
     * @param _oldAdmin The admin address being replaced.
     * @param _newAdmin The new admin address.
     */
    function _executeReplaceAdmin(address _oldAdmin, address _newAdmin) internal {
        bool replaced = false;
        for (uint i = 0; i < MAX_ADMINS; i++) {
            if (admins[i] == _oldAdmin) {
                admins[i] = _newAdmin;
                replaced = true;
                break;
            }
        }
        // This should always succeed if validation in proposeReplaceAdmin was correct
        require(replaced, "VotingAdmin: Failed to find old admin during execution");

        emit AdminReplaced(_oldAdmin, _newAdmin);
    }

    // --- Pool Cancellation (Requires Multi-sig Proposals) ---

    /**
     * @notice Proposes cancelling a voting pool in the linked Voting contract. Requires multi-sig approval.
     * @param _poolId The ID of the pool to cancel in the Voting contract.
     */
    function proposeCancelPool(uint256 _poolId) external onlyAdmin {
        // Optional: Add a check here to see if the pool ID is valid in the Voting contract,
        // but this requires an external call and might complicate things.
        // Relying on the Voting contract to revert if the poolId is invalid during execution is simpler.
        bytes memory data = abi.encode(_poolId);
        _createProposal(ProposalType.CancelPool, data);
    }

    /**
     * @notice Internal function to execute the cancellation on the Voting contract after approval.
     * @param _poolId The ID of the pool to cancel.
     */
    function _executeCancelPool(uint256 _poolId) internal {
        require(votingContract != address(0), "VotingAdmin: Voting contract address not set");

        // Call the specifically permissioned cancel function on the Voting contract
        (bool success, bytes memory returnData) = votingContract.call(abi.encodeWithSignature("adminCancelPool(uint256)", _poolId));

        // Check for success and provide a more informative revert message if possible
        if (!success) {
            if (returnData.length > 0) {
                // Attempt to decode the revert reason string
                revert(string(abi.decode(returnData, (string))));
            } else {
                revert("VotingAdmin: Failed to execute pool cancellation on Voting contract for unknown reason");
            }
        }
        // Event emission for cancellation happens within the Voting contract's adminCancelPool function
    }

    // --- Generic Proposal Workflow ---

    /**
     * @notice Internal function to create a new proposal and record the proposer's initial approval.
     * @param _pType The type of proposal being created.
     * @param _data Encoded data relevant to the proposal type.
     */
    function _createProposal(ProposalType _pType, bytes memory _data) internal {
        uint256 proposalId = nextProposalId++;
        Proposal storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.pType = _pType;
        proposal.proposer = msg.sender;
        proposal.data = _data;
        proposal.executed = false;
        proposal.approvalCount = 0; // Explicitly set count to 0

        emit ProposalCreated(proposalId, _pType, msg.sender, _data);

        // Automatically approve the proposal by the proposer
        // This calls the internal approval logic directly
        _approveProposalInternal(proposalId, msg.sender);
    }

    /**
     * @notice Allows an admin to approve a pending proposal.
     * @param _proposalId The ID of the proposal to approve.
     */
    function approveProposal(uint256 _proposalId) external onlyAdmin {
         _approveProposalInternal(_proposalId, msg.sender);
    }

    /**
      * @notice Internal logic for approving a proposal. Records approval and executes if threshold is met.
      * @param _proposalId The ID of the proposal.
      * @param _approver The address of the admin approving.
      */
     function _approveProposalInternal(uint256 _proposalId, address _approver) internal {
        Proposal storage proposal = proposals[_proposalId];
        require(proposal.id == _proposalId || (_proposalId == 0 && proposal.proposer != address(0)), "VotingAdmin: Proposal does not exist"); // Check if proposal exists
        require(!proposal.executed, "VotingAdmin: Proposal already executed");
        require(!proposal.approvals[_approver], "VotingAdmin: Admin already approved this proposal");

        proposal.approvals[_approver] = true;
        proposal.approvalCount++;

        emit ProposalApproved(_proposalId, _approver);

        // Check if the required number of approvals has been reached
        if (proposal.approvalCount >= REQUIRED_APPROVALS) {
            _executeProposal(_proposalId);
        }
    }

    /**
     * @notice Internal function to execute a proposal once it has enough approvals.
     * @param _proposalId The ID of the proposal to execute.
     */
    function _executeProposal(uint256 _proposalId) internal {
        Proposal storage proposal = proposals[_proposalId];
        // Redundant checks, but good for clarity and security
        require(!proposal.executed, "VotingAdmin: Proposal already executed");
        require(proposal.approvalCount >= REQUIRED_APPROVALS, "VotingAdmin: Not enough approvals to execute");

        proposal.executed = true;

        // Decode data and call the appropriate internal execution function
        if (proposal.pType == ProposalType.CancelPool) {
            (uint256 poolId) = abi.decode(proposal.data, (uint256));
            _executeCancelPool(poolId);
        } else if (proposal.pType == ProposalType.ReplaceAdmin) {
            (address oldAdmin, address newAdmin) = abi.decode(proposal.data, (address, address));
            _executeReplaceAdmin(oldAdmin, newAdmin);
        }
        // Add other proposal types here if needed

        emit ProposalExecuted(_proposalId);
    }

    // --- Configuration Functions ---

    /**
     * @notice Sets the address of the main Voting contract. Can only be called by an admin.
     * @dev Consider if this should require multi-sig or be callable only once for added security.
     * @param _contractAddress The address of the deployed Voting contract.
     */
    function setVotingContract(address _contractAddress) external onlyAdmin {
        require(_contractAddress != address(0), "VotingAdmin: Invalid voting contract address");
        votingContract = _contractAddress;
        emit VotingContractSet(_contractAddress);
    }

    // --- View Functions ---

    /**
     * @notice Returns the list of current admin addresses.
     * @return An array containing the 3 admin addresses.
     */
    function getAdmins() external view returns (address[3] memory) {
        return admins;
    }

    /**
     * @notice Checks if a specific admin has approved a given proposal.
     * @param _proposalId The ID of the proposal.
     * @param _admin The address of the admin to check.
     * @return True if the admin has approved, false otherwise.
     */
    function isProposalApprovedBy(uint256 _proposalId, address _admin) external view returns (bool) {
        require(proposals[_proposalId].proposer != address(0), "VotingAdmin: Proposal does not exist"); // Basic check
        return proposals[_proposalId].approvals[_admin];
    }

    /**
     * @notice Retrieves details about a specific proposal.
     * @param _proposalId The ID of the proposal.
     * @return id The unique identifier of the proposal.
     * @return pType The type of the proposal (CancelPool or ReplaceAdmin).
     * @return proposer The address of the admin who created the proposal.
     * @return data Encoded data specific to the proposal type.
     * @return approvalCount The current number of approvals the proposal has received.
     * @return executed A boolean indicating whether the proposal has been executed.
     */
    function getProposal(uint256 _proposalId)
        external
        view
        returns (
            uint256 id,
            ProposalType pType,
            address proposer,
            bytes memory data,
            uint256 approvalCount,
            bool executed
        )
    {
        Proposal storage proposal = proposals[_proposalId];
        require(proposal.proposer != address(0), "VotingAdmin: Proposal does not exist"); // Basic check
        return (
            proposal.id,
            proposal.pType,
            proposal.proposer,
            proposal.data,
            proposal.approvalCount,
            proposal.executed
        );
    }
}