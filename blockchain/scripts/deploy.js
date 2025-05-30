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
        chainId: Number(await hre.ethers.provider.getNetwork().then(n => n.chainId)),
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

    // --- NEW: Add Allowed Voters ---
    console.log("-------------------------------------------");
    console.log("Adding allowed voters to the Voting contract...");

    const allowedVoterAddresses = [
      "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
      "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
      "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
      "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
      "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
      "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
      "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
      "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
      "0xBcd4042DE499D14e55001CcbB24a551F3b954096",
      "0x71bE63f3384f5fb98995898A86B02Fb2426c5788",
      "0xFABB0ac9d68B0B445fB7357272Ff202C5651694a",
      "0x1CBd3b2770909D4e10f157cABC84C7264073C9Ec",
      "0xdF3e18d64BC6A983f673Ab319CCaE4f1a57C7097",
      "0xcd3B766CCDd6AE721141F452C550Ca635964ce71",
      "0x2546BcD3c84621e976D8185a91A922aE77ECEc30",
      "0xbDA5747bFD65F08deb54cb465eB87D40e51B197E",
      "0xdD2FD4581271e230360230F9337D5c0430Bf44C0", // This is also admin2
      "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199"  // This is also admin3
    ];

    // The deployer is admin1 and will call addVoter
    // Ensure the 'voting' contract instance is connected to the deployer (admin1)
    const votingContractAsAdmin = voting.connect(deployer);

    for (const voterAddress of allowedVoterAddresses) {
      try {
        console.log(`Attempting to add voter: ${voterAddress}`);
        // Check if voter is already allowed, to avoid unnecessary transactions/errors
        const isAllowed = await votingContractAsAdmin.isVoterAllowed(voterAddress);
        if (isAllowed) {
          console.log(`   Voter ${voterAddress} is already on the allowed list.`);
        } else {
          const addVoterTx = await votingContractAsAdmin.addVoter(voterAddress, { gasLimit: 100000 }); // Add gas limit
          await addVoterTx.wait();
          console.log(`   ✅ Voter ${voterAddress} added to allowed list. Tx: ${addVoterTx.hash}`);
        }
      } catch (error) {
        console.error(`   ❌ Failed to add voter ${voterAddress}:`, error.message);
        // Decide if you want to stop the script or continue with other voters
        // For now, it will log the error and continue
      }
    }
    console.log("-------------------------------------------");
    console.log("Finished adding allowed voters.");


    const ADMIN_CONTRACT_ABI = JSON.parse('{{ admin_contract_abi|escapejs }}');

  } catch (error) {
    console.error("❌ DEPLOYMENT FAILED:", error);
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});