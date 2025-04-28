// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Voting {
    address public admin;

    // category => list of candidate names
    mapping(string => string[]) public candidates;
    // category => candidate name => vote count
    mapping(string => mapping(string => uint256)) public votes;
    // voter address => category => whether they've voted
    mapping(address => mapping(string => bool)) public hasVoted;

    constructor() {
        admin = msg.sender;

        // President candidates
        candidates["President"].push("Ahmed");
        candidates["President"].push("Sara");

        // Vice President candidates
        candidates["Vice President"].push("Mohamed");
        candidates["Vice President"].push("Nora");

        // Secretary candidates
        candidates["Secretary"].push("Omar");
        candidates["Secretary"].push("Laila");
    }

    /// @notice Cast a vote in a specific category for a given candidate
    /// @param category The category to vote in (e.g., "President")
    /// @param candidate The name of the candidate to vote for
    function vote(string memory category, string memory candidate) public {
        require(
            !hasVoted[msg.sender][category],
            "Already voted in this category!"
        );

        // Validate that the candidate exists in this category
        string[] storage list = candidates[category];
        bool valid = false;
        for (uint i = 0; i < list.length; i++) {
            if (
                keccak256(bytes(list[i])) == keccak256(bytes(candidate))
            ) {
                valid = true;
                break;
            }
        }
        require(valid, "Invalid candidate for this category");

        // Record the vote
        votes[category][candidate]++;
        hasVoted[msg.sender][category] = true;
    }

    /// @notice Get the vote count for a candidate in a category
    /// @param category The category name
    /// @param candidate The candidate name
    /// @return The number of votes
    function getVotes(string memory category, string memory candidate)
        public
        view
        returns (uint256)
    {
        return votes[category][candidate];
    }

    /// @notice Retrieve the list of candidates for a category
    /// @param category The category name
    /// @return Array of candidate names
    function getCandidates(string memory category)
        public
        view
        returns (string[] memory)
    {
        return candidates[category];
    }

    /// @notice Check if a voter has already voted in a category
    /// @param voter The address of the voter
    /// @param category The category name
    /// @return True if the voter has voted in that category
    function hasVotedInCategory(address voter, string memory category)
        public
        view
        returns (bool)
    {
        return hasVoted[voter][category];
    }
}
