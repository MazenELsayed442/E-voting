Context: this project is django decentralized voting system. We use blockchain in hardhat  and each user has a wallet that he creates on metamask  and uses it on our system. i already have login setp up, different for admin from normal voters. There are only 3 admins in the system. 2 admins are required to cancel a pool or replace another admin.

# Project Context: E-Voting dApp

This project is a decentralized voting system built with Django and a Hardhat/Solidity blockchain backend.

## Core Architecture:
- **Frameworks:** Django (Python) for the web application, Hardhat (JavaScript/Solidity) for the blockchain.
- **Deployment:** Hosted on Supabase for free with a PostgreSQL database. We use supabase with Render free hosting instead of render's database.
- **Blockchain Interaction:** Users interact with the smart contracts via MetaMask for all on-chain actions (voting, admin tasks). The server **never** handles private keys.
- **Configuration:** The application is configured for production using environment variables (e.g., contract addresses, node URL), not hardcoded values. ABI files are stored in `voting/abi/`.

in this project we are using the free choices as much as possible unless necessary then tell me.