// Import Hardhat Runtime Environment
const hre = require("hardhat");

// Define the PoolStatus enum values as they would appear in JavaScript (0-indexed)
const PoolStatus = {
  Pending: 0,
  Active: 1,
  Cancelled: 2,
  Ended: 3,
  // Helper to get status name from value
  getName: function(value) {
    return Object.keys(this).find(key => this[key] === value && typeof this[key] === 'number') || "Unknown";
  }
};

async function main() {
  // --- Configuration ---
  // !!! IMPORTANT: Make sure this address is correct for your deployment on localhost !!!
  const VOTING_CONTRACT_ADDRESS = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512";

  console.log(`Attempting to find active pools on contract: ${VOTING_CONTRACT_ADDRESS}`);
  console.log(`Using network: ${hre.network.name}`);
  console.log(`----------------------------------------------------`);

  try {
    // --- Get Contract Instance ---
    const Voting = await hre.ethers.getContractFactory("Voting"); // Use your contract's name
    const votingContract = await Voting.attach(VOTING_CONTRACT_ADDRESS);

    // !!! CRITICAL CHECK !!!
    if (!votingContract.address) {
        console.error("❌ Error: Failed to attach to the Voting contract. votingContract.address is undefined.");
        console.error("   Please ensure the VOTING_CONTRACT_ADDRESS is correct and the contract is deployed on the target network.");
        console.error("   Also, ensure your Hardhat artifacts are up to date (run 'npx hardhat compile').");
        process.exit(1);
    }
    console.log(`Attached to Voting contract at ${votingContract.address}`);

    // --- Get the current block's timestamp from the Hardhat network ---
    const latestBlock = await hre.ethers.provider.getBlock('latest');
    const currentTime = latestBlock.timestamp;
    const currentDate = new Date(currentTime * 1000);
    console.log(`\nCurrent blockchain timestamp: ${currentTime} (${currentDate.toUTCString()})`);

    // --- Get the total number of pools using getPoolCount() ---
    let totalPoolsBigNum;
    try {
      totalPoolsBigNum = await votingContract.getPoolCount();
    } catch (e) {
      console.error(`\n❌ Error: Could not retrieve total pool count using "getPoolCount()".`);
      console.error("   Ensure the 'getPoolCount' function is public in your Voting.sol contract.");
      console.error(e);
      process.exit(1);
    }

    const totalPools = totalPoolsBigNum.toNumber(); // Convert BigNumber to number for the loop

    if (totalPools === 0) {
      console.log("\nNo pools found in the contract (pool count is zero).");
      console.log("----------------------------------------------------");
      process.exit(0);
    }
    console.log(`Total pools created in contract (nextPoolId): ${totalPools}`);

    const activePoolIds = [];
    console.log("\nChecking pool statuses...");
    console.log("Format: Pool ID [Contract Status] (Time-based Status | Start Time --> End Time)");
    console.log("--------------------------------------------------------------------------------");


    // --- Iterate through all pools and check their status ---
    // Pool IDs are 0-indexed, from 0 to totalPools - 1
    for (let poolId = 0; poolId < totalPools; poolId++) {
      try {
        // Use the getPoolDetails function from your contract
        const poolDetails = await votingContract.getPoolDetails(poolId);

        // Extract details (ethers.js returns them as an array-like object with named properties)
        const id = poolDetails.id.toNumber(); // or poolDetails[0].toNumber()
        // const category = poolDetails.category; // or poolDetails[1]
        const startTime = poolDetails.startTime.toNumber(); // or poolDetails[3].toNumber()
        const endTime = poolDetails.endTime.toNumber(); // or poolDetails[4].toNumber()
        const contractStatusValue = poolDetails.status; // This is a number (0, 1, 2, or 3)
        const contractStatusName = PoolStatus.getName(contractStatusValue);

        let timeBasedStatus = "Pending";
        if (currentTime >= startTime && currentTime < endTime) {
            timeBasedStatus = "Should be Active";
        } else if (currentTime >= endTime) {
            timeBasedStatus = "Should be Ended";
        }

        console.log(
          `  Pool ${id}: [${contractStatusName}] (${timeBasedStatus} | ${new Date(startTime * 1000).toLocaleString()} --> ${new Date(endTime * 1000).toLocaleString()})`
        );

        // Check if the pool's status is Active (1) according to the contract
        if (contractStatusValue === PoolStatus.Active) {
          activePoolIds.push(id);
        }
      } catch (error) {
        console.warn(`  ⚠️ Warning: Could not retrieve details for Pool ID ${poolId}. It might not exist or there was an issue.`);
        // console.warn(error); // Uncomment for more detailed error on a specific pool
      }
    }

    console.log(`\n----------------------------------------------------`);
    if (activePoolIds.length > 0) {
      console.log("Found the following pool IDs with contract status 'Active':");
      activePoolIds.forEach(id => console.log(`  - Pool ID: ${id}`));
    } else {
      console.log("No pools with contract status 'Active' were found.");
    }
    console.log(`----------------------------------------------------`);
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