@echo off
echo Running Hardhat script to create a new voting pool...
echo Make sure you are in your Hardhat project directory.
echo Target network: localhost (Timestamp manipulation requires localhost/hardhat)
echo Script file: scripts/createPool.js
echo.

:: Ensure Hardhat node is running on localhost!
:: Use 'call' to ensure the batch script waits for npx to finish
:: before proceeding to the next line.
call npx hardhat run scripts/createPool.js --network localhost

echo.
echo Script execution finished.
:: Pause the script and wait for user input before closing
pause
