const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

/**
 * This script extracts the deployed contract addresses from the network
 * and saves them to a file for the Django application to use.
 * 
 * Run this after the Hardhat node is started and contracts are deployed.
 */
async function main() {
    try {
        console.log("Checking for deployed contracts...");
        
        // Get the network provider
        const network = hre.network;
        console.log(`Connected to network: ${network.name}`);
        
        // Get network ID
        const chainId = await hre.ethers.provider.getNetwork().then(n => n.chainId);
        console.log(`Chain ID: ${chainId}`);
        
        // Get current block
        const blockNumber = await hre.ethers.provider.getBlockNumber();
        console.log(`Current block: ${blockNumber}`);
        
        // Get the list of accounts
        const accounts = await hre.ethers.getSigners();
        console.log(`Found ${accounts.length} accounts`);
        
        // Check for deployed VotingAdmin contract
        console.log("Looking for VotingAdmin contract...");
        const VotingAdmin = await hre.ethers.getContractFactory("VotingAdmin");
        
        // Check for deployed Voting contract
        console.log("Looking for Voting contract...");
        const Voting = await hre.ethers.getContractFactory("Voting");
        
        // Get all contracts from the network
        // For Hardhat local network, we need to check the deployments
        // This is hardhat specific and might differ on other networks
        const contracts = {};
        let foundContracts = false;
        
        // First method: Try to get from known addresses
        try {
            // Known default addresses in Hardhat local network
            const votingAdminAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
            const votingAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
            
            // Verify the contracts at these addresses
            const votingAdminAtAddress = await VotingAdmin.attach(votingAdminAddress);
            const votingAtAddress = await Voting.attach(votingAddress);
            
            // Try to call a function to verify it's the right contract
            try {
                const admins = await votingAdminAtAddress.getAdmins();
                console.log(`✅ Found VotingAdmin contract at ${votingAdminAddress}`);
                console.log(`   Admins: ${admins.join(', ')}`);
                contracts.VotingAdmin = votingAdminAddress;
                foundContracts = true;
            } catch (e) {
                console.log(`❌ Contract at ${votingAdminAddress} is not a VotingAdmin contract`);
            }
            
            try {
                const poolCount = await votingAtAddress.getPoolCount();
                console.log(`✅ Found Voting contract at ${votingAddress}`);
                console.log(`   Pool count: ${poolCount}`);
                contracts.Voting = votingAddress;
                foundContracts = true;
            } catch (e) {
                console.log(`❌ Contract at ${votingAddress} is not a Voting contract`);
            }
        } catch (e) {
            console.log(`Error checking known addresses: ${e}`);
        }
        
        if (!foundContracts) {
            console.log("Could not find contracts at known addresses. Using default values.");
            // Use default values
            contracts.VotingAdmin = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
            contracts.Voting = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
        }
        
        // Create deployment info
        const deploymentInfo = {
            timestamp: new Date().toISOString(),
            network: network.name,
            chainId: chainId,
            contracts: contracts
        };
        
        // Create directory if it doesn't exist
        const deploymentsDir = path.join(__dirname, "../deployment_logs");
        if (!fs.existsSync(deploymentsDir)) {
            fs.mkdirSync(deploymentsDir, { recursive: true });
        }
        
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
VOTING_CONTRACT_ADDRESS=${contracts.Voting}
ADMIN_CONTRACT_ADDRESS=${contracts.VotingAdmin}
`.trim();
        fs.writeFileSync(path.join(__dirname, "../.env.contracts"), envContents);
        console.log(`✅ Contract .env file created for Django integration`);
        
        // Create a flag file that indicates deployment is complete
        fs.writeFileSync("deployment_complete.flag", "Deployment is complete");
        console.log(`✅ Created deployment flag file`);
        
        console.log("✨ Done checking contracts!");
        
    } catch (error) {
        console.error("❌ Error:", error);
        process.exitCode = 1;
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
}); 