const hre = require("hardhat");

async function main() {
  try {
    const [signer] = await hre.ethers.getSigners();
    console.log("Deploying with account:", signer.address);

    const Voting = await hre.ethers.getContractFactory("Voting");
<<<<<<< HEAD
    const candidates = ["Alice", "Bob", "ahmed", "Ahmed", "Charlie"];
=======
    const candidates = ["Alice", "Bob", "Charlie"];
>>>>>>> fork/main
    
    console.log("Deploying Voting contract...");
    const voting = await Voting.deploy(candidates, { gasLimit: 3000000 });

    // Wait for deployment confirmation (ethers v6)
    await voting.waitForDeployment();
    const address = await voting.getAddress();

    console.log("Voting contract deployed to:", address);
    console.log("Transaction hash:", voting.deploymentTransaction().hash);
  } catch (error) {
    console.error("DEPLOYMENT FAILED:", error);
    process.exitCode = 1;
  }
}

main();