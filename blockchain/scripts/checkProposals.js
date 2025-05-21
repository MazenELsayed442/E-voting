// scripts/listActiveProposals.js
// command to run the script : npx hardhat run blockchain/scripts/checkProposals.js --network localhost
const hre = require("hardhat");

// !!! IMPORTANT: Replace with your actual contract name and address !!!
// CONTRACT_NAME should be the name of your contract as compiled (e.g., "AdminContract", "ProposalManager")
const CONTRACT_NAME = "VotingAdmin"; 
const CONTRACT_ADDRESS = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

async function main() {
    console.log("Attempting to check for active 'Cancel Pool' proposals...");
    console.log(`Contract Name: ${CONTRACT_NAME}`);
    console.log(`Contract Address: ${CONTRACT_ADDRESS}`);
    console.log(`Network: ${hre.network.name}`);

    const [deployer] = await hre.ethers.getSigners();
    console.log("Using account to query:", deployer.address);

    let contract;
    try {
    // Get the contract factory and attach to the deployed instance
        // Make sure CONTRACT_NAME matches the compiled contract artifact name (e.g., from artifacts/contracts/YourContract.sol/YourContract.json)
        const ContractFactory = await hre.ethers.getContractFactory(CONTRACT_NAME);
        contract = ContractFactory.attach(CONTRACT_ADDRESS);
        console.log(`Successfully attached to contract at ${contract.address}`);
    } catch (error) {
        console.error(`\\n🛑 ERROR: Failed to connect to contract '${CONTRACT_NAME}' at address '${CONTRACT_ADDRESS}'.`);
        console.error("Reason:", error.message);
        console.error("Please ensure that:");
        console.error("1. CONTRACT_NAME is correct and the contract is compiled (check your 'artifacts' folder).");
        console.error("2. CONTRACT_ADDRESS is correct and the contract is deployed to the network '${hre.network.name}'.");
        console.error("3. Your Hardhat network is running.");
        return;
    }

    let activeCancelPoolProposalsFound = false;
    let totalProposalsInspected = 0;
    let activeCancelPoolProposalsCount = 0;

    try {
        console.log("\\nAttempting to get proposal count using 'nextProposalId()'...");
        const nextIdBigNum = await contract.nextProposalId();
        const proposalCount = Number(nextIdBigNum); // Convert BigNumber to Number
        console.log(`Total proposals reported by contract (nextProposalId): ${proposalCount}`);
        
        if (proposalCount === 0) {
            console.log("No proposals found in the contract (nextProposalId is 0).");
        }

        for (let i = 0; i < proposalCount; i++) {
            totalProposalsInspected++;
            console.log(`\\nFetching proposal with ID ${i} using 'proposals(${i})'...`);
            const proposal = await contract.proposals(i);
            
            // ProposalType enum: CancelPool is 0, ReplaceAdmin is 1
            const PROPOSAL_TYPE_CANCEL_POOL = 0; 

            // Check if it's a "Cancel Pool" type and if it's not executed
            // Accessing struct fields: proposal.pType, proposal.executed, proposal.id
            // Make sure to convert BigNumber pType to Number for comparison if necessary,
            // or compare BigNumber to BigNumber. toString() is safer for direct comparison with string "0".
            const isCancelPoolType = Number(proposal.pType) === PROPOSAL_TYPE_CANCEL_POOL;
            const isActive = proposal.executed === false;

            console.log(`  Proposal ID: ${proposal.id.toString()}`);
            console.log(`  Type (Raw): ${proposal.pType.toString()} (CancelPool is ${PROPOSAL_TYPE_CANCEL_POOL})`);
            console.log(`  Is Cancel Pool Type: ${isCancelPoolType}`);
            console.log(`  Executed: ${proposal.executed}`);
            console.log(`  Is Active: ${isActive}`);
            console.log(`  Proposer: ${proposal.proposer}`);
            console.log(`  Approval Count: ${proposal.approvalCount.toString()}`);

            if (isCancelPoolType && isActive) {
                activeCancelPoolProposalsFound = true;
                activeCancelPoolProposalsCount++;
                console.log("  >>> FOUND an active 'Cancel Pool' proposal! <<<");
                // You can log more details from the proposal struct if needed
                // e.g., console.log(\`     Data: \${proposal.data}\`);
            } else {
                console.log("  --- Not an active 'Cancel Pool' proposal or already executed. ---");
            }
        }

        console.log("\\n--- Verification Summary ---");
        if (activeCancelPoolProposalsFound) {
            console.log(`SUCCESS: Found ${activeCancelPoolProposalsCount} active 'Cancel Pool' proposal(s) on the blockchain.`);
            console.log("This suggests that 'Cancel Pool' proposals are indeed on the network and awaiting further action.");
        } else {
            console.log("INFO: No active 'Cancel Pool' proposals were found matching the criteria.");
            if (totalProposalsInspected > 0) {
                console.log(`   (${totalProposalsInspected} total proposals were inspected from the contract).`);
            } else {
                console.log("   (No proposals were found or fetched from the contract to inspect).");
            }
            console.log("   This could mean:");
            console.log("   1. No 'Cancel Pool' proposals have been submitted to the contract.");
            console.log("   2. Submitted 'Cancel Pool' proposals have already been processed (e.g., executed).");
            console.log("   3. The proposal fetching or checking logic in this script has an issue (review logs above).");
        }

    } catch (error) {
        console.error("\\n--- 🛑 SCRIPT EXECUTION ERROR ---");
        console.error("An error occurred while trying to check proposals:", error.message);
        
        // Attempt to decode revert reason
        if (error.data && typeof error.data === 'string' && error.data.startsWith('0x')) {
            try {
                if (error.data.startsWith('0x08c379a0')) { // Standard Error(string) selector
                    const reason = hre.ethers.utils.defaultAbiCoder.decode(['string'], '0x' + error.data.substring(10))[0];
                    console.error("Revert Reason (decoded from error.data):", reason);
                } else {
                    const simpleReason = hre.ethers.utils.toUtf8String(error.data);
                    if (simpleReason.length > 0 && simpleReason.replace(/\\0/g, '').trim() !== '') {
                        console.error("Potential Revert Reason (raw error.data to UTF-8):", simpleReason);
                    } else {
                        console.error("Raw Revert Data (hex):", error.data);
                    }
                }
            } catch (decodeError) {
                console.error("Could not decode revert reason from error.data. Raw data:", error.data);
            }
        } else if (error.reason) {
             console.error("Revert Reason (from error object directly):", error.reason);
        }
        
        console.error("\\nPossible issues to check:");
        console.error(`  - Is the CONTRACT_ADDRESS '${CONTRACT_ADDRESS}' correct and the contract deployed on the '${hre.network.name}' network?`);
        console.error(`  - Does the CONTRACT_NAME '${CONTRACT_NAME}' match your compiled contract artifact?`);
        console.error("  - Are you trying to access a proposal ID that does not exist (e.g., loop bounds)?");
        console.error("  - Is your Hardhat node running?");
        if (error.stack) {
            // console.error("Stack trace:", error.stack); // Usually too verbose, but can be helpful
        }
    }
}

// Standard Hardhat script execution pattern
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("\\n--- FATAL SCRIPT ERROR---");
        console.error(error);
        process.exit(1);
    });