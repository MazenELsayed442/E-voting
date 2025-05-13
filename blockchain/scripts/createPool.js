// Import Hardhat Runtime Environment
const hre = require("hardhat");

async function main() {
  // --- Configuration ---
  const VOTING_CONTRACT_ADDRESS = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"; // <-- REPLACE with your deployed Voting contract address if different
  const CATEGORY = "Manual Test Pool"; // The category name for the pool
  const CANDIDATES = ["Alice", "Ahmed","Omar",]; // List of candidates for this pool
  const DURATION_SECONDS = 3600 * 5; // Duration of the pool in seconds (5 hours)
  const TIME_BUFFER_SECONDS = 15; // Buffer time to add to current time for start time

  console.log(`Attempting to create a new voting pool on contract: ${VOTING_CONTRACT_ADDRESS}`);
  console.log(`Using network: ${hre.network.name}`); // Log the network being used
  console.log(`----------------------------------------------------`);

  // Ensure this script is running on localhost or hardhat network where time can be manipulated
  if (hre.network.name !== "localhost" && hre.network.name !== "hardhat") {
      console.error("❌ Error: This script manipulates block timestamps and should only be run on 'localhost' or 'hardhat' networks.");
      process.exit(1); // Exit with error code
  }

  try {
    // --- Control Next Block's Time ---
    console.log("Setting up block timestamp...");

    // 1. Get current timestamp from the node's latest block
    const latestBlock = await hre.ethers.provider.getBlock('latest');
    const currentTime = latestBlock.timestamp;
    console.log(`Current block timestamp: ${currentTime}`);

    // 2. Set the timestamp for the VERY NEXT block to be mined
    // We add a small buffer to ensure the transaction lands in the block with the desired timestamp
    const nextTimestamp = currentTime + TIME_BUFFER_SECONDS;
    await hre.network.provider.send("evm_setNextBlockTimestamp", [nextTimestamp]);
    console.log(`Requested next block timestamp: ${nextTimestamp}`);

    // 3. Use this EXACT timestamp as the startTime
    const startTime = nextTimestamp;
    const endTime = startTime + DURATION_SECONDS; // Calculate end time based on start time and duration

    console.log(`\nPool Parameters:`);
    console.log(`  Category:   '${CATEGORY}'`);
    console.log(`  Candidates: ${JSON.stringify(CANDIDATES)}`);
    console.log(`  Start Time: ${startTime} (Unix Timestamp)`);
    console.log(`  End Time:   ${endTime} (Unix Timestamp)`);

    // --- Get Admin Signer ---
    // Assumes the first signer is the admin/deployer. Adjust if needed.
    const [adminSigner] = await hre.ethers.getSigners();
    console.log(`\nUsing admin signer: ${adminSigner.address}`);

    // --- Get Contract Instance ---
    const Voting = await hre.ethers.getContractFactory("Voting");
    const votingContract = await Voting.attach(VOTING_CONTRACT_ADDRESS);
    console.log(`Attached to Voting contract at ${votingContract.address}`);

    // --- Call createPool Function ---
    // This transaction will be mined in the next block, which we've set the timestamp for.
    console.log("\nSending createPool transaction...");
    const tx = await votingContract.connect(adminSigner).createPool(CATEGORY, CANDIDATES, startTime, endTime);

    // --- Wait for Transaction Confirmation ---
    console.log(`Transaction sent! Hash: ${tx.hash}`);
    console.log("Waiting for transaction confirmation (this might take a moment)...");
    const receipt = await tx.wait(); // Wait for 1 confirmation

    // Log details from the receipt, including the actual block number and timestamp
    console.log(`Transaction confirmed!`);
    console.log(`  Block Number: ${receipt.blockNumber}`);
    // Fetch the block to verify the timestamp
    const minedBlock = await hre.ethers.provider.getBlock(receipt.blockNumber);
    console.log(`  Block Timestamp: ${minedBlock.timestamp} (Should match requested start time: ${startTime})`);
    console.log(`  Gas Used: ${receipt.gasUsed.toString()}`);

    // Check if the pool was created by trying to fetch its details (optional but good verification)
    // Note: Pool IDs might start from 0 or 1 depending on your contract logic. Assuming 0 for the first pool.
    // You might need a way to get the actual pool ID created if your contract emits an event.
    // const newPoolId = 0; // Replace with actual logic if possible
    // const poolDetails = await votingContract.pools(newPoolId);
    // console.log(`\nVerified Pool ${newPoolId} Start Time: ${poolDetails.startTime.toString()}`);


    console.log(`\n----------------------------------------------------`);
    console.log("Script finished successfully.");

  } catch (error) {
    console.error("\n❌ An error occurred during script execution:");
    console.error(error);
    process.exitCode = 1; // Indicate failure
  }
}

// Standard Hardhat script execution pattern
main().catch((error) => {
  console.error("\n❌ Unhandled error in main function:");
  console.error(error);
  process.exitCode = 1;
});
