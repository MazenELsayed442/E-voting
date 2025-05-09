// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/Strings.sol"; // For uint to string conversion in events

/**
 * @title IVotingAdmin Interface
 * @notice Defines the necessary functions expected from the VotingAdmin contract.
 */
interface IVotingAdmin {
    function getAdmins() external view returns (address[3] memory);
    // Add other functions if needed for checks within Voting.sol (currently not used directly)
    // function isProposalApprovedBy(uint256 proposalId, address admin) external view returns (bool);
}

/**
 * @title Voting
 * @notice Handles the creation, management, and voting process for decentralized polls.
 * Relies on a separate VotingAdmin contract for admin management and
 * authorization of sensitive actions like pool creation and cancellation.
 */
contract Voting {
    using Strings for uint256;

    // --- State Variables ---

    IVotingAdmin public immutable votingAdminContract; // Address of the VotingAdmin contract (set at deployment)

    // --- Voting Pool Data Structures ---
    enum PoolStatus { Pending, Active, Cancelled, Ended }

    struct VotingPool {
        uint256 id;              // Unique identifier for the pool
        string category;         // Name or category of the vote (e.g., "President")
        string[] candidates;     // List of candidates for this pool
        uint256 startTime;       // Timestamp when voting begins
        uint256 endTime;         // Timestamp when voting ends
        PoolStatus status;       // Current status of the pool (Pending, Active, etc.)
        mapping(string => uint256) votes; // Candidate name => vote count mapping for this pool
        mapping(address => bool) hasVoted; // Voter address => voted status mapping for this pool
    }

    uint256 public nextPoolId;
    mapping(uint256 => VotingPool) public votingPools;

    // --- Events ---

    event PoolCreated(uint256 indexed poolId, string category, string[] candidates, uint256 startTime, uint256 endTime);
    event PoolCancelled(uint256 indexed poolId);
    event PoolEnded(uint256 indexed poolId);
    event Voted(uint256 indexed poolId, address indexed voter, string category, string candidate, uint256 newVoteCount);

    // --- Modifiers ---

    /**
     * @dev Ensures the caller is the linked VotingAdmin contract.
     */
    modifier onlyVotingAdmin() {
        require(msg.sender == address(votingAdminContract), "Voting: Caller is not the authorized VotingAdmin contract");
        _;
    }

    /**
     * @dev Ensures the caller is one of the admins registered in the linked VotingAdmin contract.
     * Requires an external call to the VotingAdmin contract.
     */
    modifier onlyAnAdmin() {
        require(address(votingAdminContract) != address(0), "Voting: Admin contract not set (this shouldn't happen)");
        // Fetch current admins from the admin contract
        address[3] memory currentAdmins = votingAdminContract.getAdmins();
        bool isAdmin = false;
        for (uint i = 0; i < currentAdmins.length; i++) {
            if (currentAdmins[i] == msg.sender) {
                isAdmin = true;
                break;
            }
        }
        require(isAdmin, "Voting: Caller is not a registered admin");
        _;
    }


    // --- Constructor ---

    /**
     * @notice Sets the immutable address of the VotingAdmin contract.
     * @param _votingAdminAddress The address of the deployed VotingAdmin contract.
     */
    constructor(address _votingAdminAddress) {
        require(_votingAdminAddress != address(0), "Voting: Invalid admin contract address");
        votingAdminContract = IVotingAdmin(_votingAdminAddress);
    }

    // --- Pool Management Functions ---

    /**
     * @notice Creates a new voting pool. Only callable by a registered admin.
     * @param _category The name/category for the new pool.
     * @param _candidates An array of candidate names for the pool.
     * @param _startTime The UNIX timestamp when voting should start.
     * @param _endTime The UNIX timestamp when voting should end.
     */
    function createPool(
        string memory _category,
        string[] memory _candidates,
        uint256 _startTime,
        uint256 _endTime
    )
        external
        onlyAnAdmin // Requires the caller to be one of the admins defined in VotingAdmin
    {
        require(_startTime >= block.timestamp, "Voting: Start time must be now or in the future");
        require(_endTime > _startTime, "Voting: End time must be after start time");
        require(_candidates.length >= 2, "Voting: Must have at least two candidates");

        uint256 poolId = nextPoolId++;
        VotingPool storage pool = votingPools[poolId];
        pool.id = poolId;
        pool.category = _category;
        pool.candidates = _candidates; // Copies the array
        pool.startTime = _startTime;
        pool.endTime = _endTime;

        // Set initial status based on start time
        if (_startTime > block.timestamp) {
            pool.status = PoolStatus.Pending;
        } else {
            pool.status = PoolStatus.Active;
        }

        emit PoolCreated(poolId, _category, _candidates, _startTime, _endTime);
    }

    /**
     * @notice Cancels an active or pending pool. Only callable by the VotingAdmin contract.
     * @dev This function is called internally by the VotingAdmin contract after a
     * cancellation proposal receives enough approvals.
     * @param _poolId The ID of the pool to cancel.
     */
    function adminCancelPool(uint256 _poolId) external onlyVotingAdmin {
        VotingPool storage pool = votingPools[_poolId];
        require(pool.id == _poolId || (_poolId == 0 && bytes(pool.category).length != 0), "Voting: Pool does not exist"); // Check pool exists
        require(pool.status == PoolStatus.Active || pool.status == PoolStatus.Pending, "Voting: Pool not active or pending, cannot cancel");

        pool.status = PoolStatus.Cancelled;
        emit PoolCancelled(_poolId);
    }

    /**
     * @notice Allows anyone to transition an Active pool to Ended status if its endTime has passed.
     * @dev Helps keep pool statuses accurate without requiring admin intervention for normal ending.
     * @param _poolId The ID of the pool to potentially end.
     */
    function endPoolIfExpired(uint256 _poolId) external {
        VotingPool storage pool = votingPools[_poolId];
        require(pool.id == _poolId || (_poolId == 0 && bytes(pool.category).length != 0), "Voting: Pool does not exist"); // Check pool exists
        require(pool.status == PoolStatus.Active, "Voting: Pool is not active");
        require(block.timestamp >= pool.endTime, "Voting: Pool voting period has not ended yet");

        pool.status = PoolStatus.Ended;
        emit PoolEnded(_poolId);
    }

    // --- Voting Function ---

    /**
     * @notice Casts a vote for a specific candidate within an active voting pool.
     * @param _poolId The ID of the pool to vote in.
     * @param _candidate The name of the candidate to vote for.
     */
    function vote(uint256 _poolId, string memory _candidate) public {
        // --- START: MODIFICATION TO PREVENT ADMINS FROM VOTING ---
        require(address(votingAdminContract) != address(0), "Voting: Admin contract not set");
        address[3] memory currentAdmins = votingAdminContract.getAdmins();
        bool isCallerAdmin = false;
        for (uint i = 0; i < currentAdmins.length; i++) {
            if (currentAdmins[i] == msg.sender) {
                isCallerAdmin = true;
                break;
            }
        }
        require(!isCallerAdmin, "Voting: Admins are not allowed to vote");
        // --- END: MODIFICATION TO PREVENT ADMINS FROM VOTING ---

        VotingPool storage pool = votingPools[_poolId];
        require(pool.id == _poolId || (_poolId == 0 && bytes(pool.category).length != 0), "Voting: Pool does not exist"); // Check pool exists
        require(pool.status == PoolStatus.Active, "Voting: Voting pool is not active");
        require(block.timestamp >= pool.startTime, "Voting: Voting period has not started yet");
        require(block.timestamp < pool.endTime, "Voting: Voting period has ended");
        require(!pool.hasVoted[msg.sender], "Voting: Address has already voted in this pool");

        // Validate candidate exists within this specific pool
        bool validCandidate = false;
        for (uint i = 0; i < pool.candidates.length; i++) {
            // Use keccak256 for safe string comparison
            if (keccak256(bytes(pool.candidates[i])) == keccak256(bytes(_candidate))) {
                validCandidate = true;
                break;
            }
        }
        require(validCandidate, "Voting: Invalid candidate for this pool");

        // Record the vote
        pool.votes[_candidate]++;
        pool.hasVoted[msg.sender] = true;

        emit Voted(_poolId, msg.sender, pool.category, _candidate, pool.votes[_candidate]);
    }

    // --- View Functions ---

    /**
     * @notice Gets the current vote count for a specific candidate in a given pool.
     * @param _poolId The ID of the pool.
     * @param _candidate The name of the candidate.
     * @return The total number of votes for the candidate in that pool.
     */
    function getVotes(uint256 _poolId, string memory _candidate) public view returns (uint256) {
        // No need to check pool existence here, it will return 0 for non-existent pool/candidate implicitly
        return votingPools[_poolId].votes[_candidate];
    }
    
    /**
     * @notice Retrieves key details about a specific voting pool.
     * @param _poolId The ID of the pool.
     * @return id The pool's unique identifier.
     * @return category The pool's category name.
     * @return candidates An array of candidate names for the pool.
     * @return startTime The UNIX timestamp when voting starts.
     * @return endTime The UNIX timestamp when voting ends.
     * @return status The current status of the pool (Pending, Active, Cancelled, Ended).
     */
    function getPoolDetails(uint256 _poolId)
        public
        view
        returns (
            uint256 id,
            string memory category,
            string[] memory candidates,
            uint256 startTime,
            uint256 endTime,
            PoolStatus status
        )
    {
        // Accessing non-existent poolId will return default values (0, "", empty array, 0, 0, PoolStatus.Pending)
        VotingPool storage pool = votingPools[_poolId];
        return (
            pool.id,
            pool.category,
            pool.candidates,
            pool.startTime,
            pool.endTime,
            pool.status
        );
    }

    /**
     * @notice Gets the list of candidates for a specific pool.
     * @param _poolId The ID of the pool.
     * @return candidates An array of candidate names.
     */
    function getCandidates(uint256 _poolId) public view returns (string[] memory candidates) {
        return votingPools[_poolId].candidates;
    }


    /**
     * @notice Checks if a specific address has already voted in a given pool.
     * @param _poolId The ID of the pool.
     * @param _voter The address to check.
     * @return True if the address has voted in the pool, false otherwise.
     */
    function hasVotedInPool(uint256 _poolId, address _voter) public view returns (bool) {
        // No need to check pool existence, will return false for non-existent pool implicitly
        return votingPools[_poolId].hasVoted[_voter];
    }

    /**
     * @notice Returns the total number of pools created.
     * @return The next pool ID, which represents the count.
     */
    function getPoolCount() public view returns (uint256) {
        return nextPoolId;
    }
}