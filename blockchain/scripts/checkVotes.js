// Import Hardhat Runtime Environment
const hre = require("hardhat");

async function main() {
  // --- Configuration ---
  const VOTING_CONTRACT_ADDRESS = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"; // Your deployed contract address
  const POOL_ID_TO_CHECK = 0n; // Replace with the correct pool ID if different
  const CANDIDATE_TO_CHECK = "Ahmed"; // Replace with the exact candidate name if different

  console.log(`Checking votes for candidate "${CANDIDATE_TO_CHECK}" in pool ${POOL_ID_TO_CHECK}`);
  console.log(`On contract: ${VOTING_CONTRACT_ADDRESS}`);
  console.log(`----------------------------------------------------`);

  try {
    // Get the contract factory
    const Voting = await hre.ethers.getContractFactory("Voting");

    // Attach to the deployed contract instance
    const votingContract = await Voting.attach(VOTING_CONTRACT_ADDRESS);
    console.log(`Attached to Voting contract at ${votingContract.address}`);

    // Get the votes for the specified candidate in the specified pool
    const currentVotes = await votingContract.getVotes(POOL_ID_TO_CHECK, CANDIDATE_TO_CHECK);

    // Log the result (convert BigInt to string for reliable logging)
    console.log(`\n-> Votes for "${CANDIDATE_TO_CHECK}" in pool ${POOL_ID_TO_CHECK}: ${currentVotes.toString()}`);

    console.log(`\n----------------------------------------------------`);
    console.log("Script finished successfully.");

  } catch (error) {
    console.error("❌ An error occurred during script execution:");
    console.error(error);
    process.exitCode = 1; // Indicate failure
  }
}

// Standard Hardhat script execution pattern
main().catch((error) => {
  console.error("❌ Unhandled error in main function:");
  console.error(error);
  process.exitCode = 1;
});
