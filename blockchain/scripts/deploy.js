const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  try {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying contracts with the account:", deployer.address);

    // --- !! IMPORTANT: Define Initial Admin Addresses !! ---
    // Replace these with the actual addresses you want to be admins
    // For testing, you might use addresses from `npx hardhat node` or your own test wallets.
    const admin1 = deployer.address; // Often the deployer is the first admin
    const admin2 = "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"; // REPLACE WITH ACTUAL ADDRESS 2
    const admin3 = "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199"; // REPLACE WITH ACTUAL ADDRESS 3

    if (admin2 === "0x..." || admin3 === "0x...") {
        console.error("❌ ERROR: Please replace placeholder admin addresses in the deploy script!");
        process.exit(1); // Exit if addresses aren't set
    }
    console.log("Using Admins:", admin1, admin2, admin3);
    console.log("-------------------------------------------");


    // 1. Deploy VotingAdmin Contract
    console.log("Deploying VotingAdmin contract...");
    const VotingAdmin = await hre.ethers.getContractFactory("VotingAdmin");
    const votingAdmin = await VotingAdmin.deploy(admin1, admin2, admin3, { gasLimit: 3000000 });

    await votingAdmin.waitForDeployment();
    const votingAdminAddress = await votingAdmin.getAddress();
    console.log("✅ VotingAdmin contract deployed to:", votingAdminAddress);
    console.log("   Transaction hash:", votingAdmin.deploymentTransaction().hash);
    console.log("-------------------------------------------");


    // 2. Deploy Voting Contract, passing the VotingAdmin address
    console.log("Deploying Voting contract...");
    const Voting = await hre.ethers.getContractFactory("Voting");
    const voting = await Voting.deploy(votingAdminAddress, { gasLimit: 4000000 }); // May need more gas

    await voting.waitForDeployment();
    const votingAddress = await voting.getAddress();
    console.log("✅ Voting contract deployed to:", votingAddress);
    console.log("   Transaction hash:", voting.deploymentTransaction().hash);
    console.log("-------------------------------------------");


    // 3. Link VotingAdmin back to Voting contract by calling setVotingContract
    console.log("Linking VotingAdmin to Voting contract by calling setVotingContract...");
    // Ensure the deployer (signer) has admin rights in VotingAdmin (true if deployer is admin1)
    const tx = await votingAdmin.connect(deployer).setVotingContract(votingAddress);
    await tx.wait(); // Wait for the transaction to be mined
    console.log("✅ Successfully called setVotingContract on VotingAdmin.");
    console.log("   Transaction hash:", tx.hash);
    console.log("-------------------------------------------");


    console.log("🎉 Deployment and linking complete!");
    console.log("VotingAdmin Address:", votingAdminAddress);
    console.log("Voting Address:", votingAddress);
    
    // 4. Save contract addresses to a file for Django to use
    // Create directory if it doesn't exist
    const deploymentsDir = path.join(__dirname, "../deployment_logs");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }
    
    // Save contract addresses with timestamp for tracking multiple deployments
    const deploymentInfo = {
        timestamp: new Date().toISOString(),
        network: hre.network.name,
        chainId: await hre.ethers.provider.getNetwork().then(n => n.chainId),
        contracts: {
            VotingAdmin: votingAdminAddress,
            Voting: votingAddress
        }
    };
    
    // Save to JSON file
    const deploymentFile = path.join(deploymentsDir, `deployment_${Date.now()}.json`);
    fs.writeFileSync(deploymentFile, JSON.stringify(deploymentInfo, null, 2));
    console.log(`✅ Deployment info saved to: ${deploymentFile}`);
    
    // Create a latest.json that will always have the most recent deployment info
    const latestFile = path.join(deploymentsDir, "latest.json");
    fs.writeFileSync(latestFile, JSON.stringify(deploymentInfo, null, 2));
    console.log(`✅ Latest deployment info saved to: ${latestFile}`);
    
    // Also create a .env.contracts file that can be used to update Django settings
    const envContents = `
VOTING_CONTRACT_ADDRESS=${votingAddress}
ADMIN_CONTRACT_ADDRESS=${votingAdminAddress}
`.trim();
    fs.writeFileSync(path.join(__dirname, "../.env.contracts"), envContents);
    console.log(`✅ Contract .env file created for Django integration`);

  } catch (error) {
    console.error("❌ DEPLOYMENT FAILED:", error);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});