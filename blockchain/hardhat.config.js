require("@nomicfoundation/hardhat-toolbox");
const path = require('path');
require('dotenv').config();

// Check for required environment variables
if (!process.env.PRIVATE_KEY) {
    console.error("Fatal: PRIVATE_KEY environment variable is not set.");
    process.exit(1);
}

// Optional: Check for node URL or specific provider IDs
if (!process.env.POLYGON_RPC_URL) {
    console.warn("Warning: No POLYGON_RPC_URL environment variable is set. Using default local network.");
}

// --- Debugging ---
console.log("--- Hardhat Config Debug ---");
console.log("POLYGON_RPC_URL:", process.env.POLYGON_RPC_URL ? "Loaded" : "NOT LOADED");
console.log("PRIVATE_KEY:", process.env.PRIVATE_KEY ? "Loaded" : "NOT LOADED");
console.log("--------------------------");
// --- End Debugging ---

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.24",
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    hardhat: {
      // Default network when you run `npx hardhat node`
      chainId: 1337 
    },
    polygon: {
      url: process.env.POLYGON_RPC_URL || "",
      accounts: [`0x${process.env.PRIVATE_KEY}`],
      gasPrice: 80000000000, // 80 Gwei
    },
    amoy: {
      url: process.env.AMOY_RPC_URL || "",
      accounts: [`0x${process.env.PRIVATE_KEY}`]
    }
  },
  paths: {
    // ... existing code ...
  },
};
