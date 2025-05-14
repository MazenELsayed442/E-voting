@echo off
echo Starting Hardhat node and deploying contracts...

REM Remove old deployment flag if it exists
if exist deployment_complete.flag (
    del /f deployment_complete.flag
    echo Removed old deployment flag.
)

REM Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo Node.js is not installed or not in PATH. Please install Node.js first.
    exit /b 1
)

REM Check if required packages are installed
if not exist node_modules (
    echo Installing dependencies...
    call npm install
)

REM Start the Hardhat node in background
start "Hardhat Node" cmd /c "npx hardhat node"
echo Hardhat node starting...

REM Wait for the node to start
timeout /t 5 /nobreak

REM Deploy contracts
echo Deploying contracts...
call npx hardhat run --network localhost scripts/deploy.js

REM Create deployment flag file
echo Deployment complete > deployment_complete.flag
echo Contracts deployed successfully.
echo Created deployment flag file.

echo.
echo ========================================================================
echo Hardhat node is running in a separate window. To stop it, close that window.
echo To access the blockchain, use MetaMask with:
echo Network Name: Hardhat Local
echo RPC URL: http://127.0.0.1:8545
echo Chain ID: 31337
echo Currency Symbol: ETH
echo ========================================================================

echo.
echo Press any key to close this window...
pause >nul 