const hre = require("hardhat");
require('dotenv').config({ path: require('path').resolve(__dirname, './.env') });

async function main() {
    const ADMIN_CONTRACT_ADDRESS = process.env.ADMIN_CONTRACT_ADDRESS_OVERRIDE;

    if (!ADMIN_CONTRACT_ADDRESS) {
        console.error("Please provide the admin contract address via ADMIN_CONTRACT_ADDRESS_OVERRIDE environment variable.");
        console.log("Example: export ADMIN_CONTRACT_ADDRESS_OVERRIDE=0x... (Linux/Mac)");
        console.log("Example: $env:ADMIN_CONTRACT_ADDRESS_OVERRIDE='0x...' (PowerShell)");
        process.exit(1);
    }

    console.log(`Checking admins for contract at: ${ADMIN_CONTRACT_ADDRESS}`);

    try {
        const VotingAdmin = await hre.ethers.getContractAt("VotingAdmin", ADMIN_CONTRACT_ADDRESS);
        
        console.log("Fetching admins from the contract...");
        const admins = await VotingAdmin.getAdmins();
        
        console.log("-----------------------------------------");
        console.log("✅ Admins registered in the contract:");
        console.log(`1: ${admins[0]}`);
        console.log(`2: ${admins[1]}`);
        console.log(`3: ${admins[2]}`);
        console.log("-----------------------------------------");

    } catch (error) {
        console.error("❌ An error occurred while fetching admins:");
        console.error(error);
        process.exit(1);
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
}); 