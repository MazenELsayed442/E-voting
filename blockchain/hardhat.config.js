require("@nomicfoundation/hardhat-toolbox");
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, './.env') });

// --- Debugging ---
console.log("--- Hardhat Config Debug ---");
console.log("INFURA_PROJECT_ID:", process.env.INFURA_PROJECT_ID ? "Loaded" : "NOT LOADED");
console.log("PRIVATE_KEY:", process.env.PRIVATE_KEY ? "Loaded" : "NOT LOADED");
console.log("--------------------------");
// --- End Debugging ---

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28",
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    hardhat: {
      // Default network when you run `npx hardhat node`
    },
    polygon: {
      url: `https://polygon-mainnet.infura.io/v3/${process.env.INFURA_PROJECT_ID}`,
      accounts: [process.env.PRIVATE_KEY]
    }
  },
};
