// MetaMask QR Bridge
// This script helps connect MetaMask mobile with web applications via QR codes

/**
 * Process a QR code from the web application and connect MetaMask
 * @param {string} qrData - The data from the QR code
 * @returns {Promise}
 */
async function processMetaMaskQrCode(qrData) {
    try {
        // Parse the QR data
        const data = JSON.parse(qrData);
        
        if (data.action !== 'connect_wallet') {
            throw new Error('Invalid QR code action');
        }
        
        // Get the callback URL and session ID
        const callbackUrl = data.callback_url;
        const sessionId = data.session_id;
        
        // Request MetaMask connection
        if (!window.ethereum) {
            throw new Error('MetaMask not detected');
        }
        
        // Request account access
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const walletAddress = accounts[0];
        
        // Send the wallet address back to the web application
        const response = await fetch(callbackUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: 'connect_wallet',
                session_id: sessionId,
                wallet_address: walletAddress
            })
        });
        
        const responseData = await response.json();
        
        if (responseData.success) {
            return {
                success: true,
                wallet_address: walletAddress
            };
        } else {
            throw new Error(responseData.error || 'Failed to connect wallet');
        }
    } catch (error) {
        console.error('Error processing MetaMask QR code:', error);
        return {
            success: false,
            error: error.message || 'Unknown error'
        };
    }
} 