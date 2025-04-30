@echo off
echo Running Hardhat script to check votes...
echo Make sure you are in your Hardhat project directory.
echo Target network: localhost
echo Script file: scripts/checkVotes.js
echo.

:: Use 'call' to ensure the batch script waits for npx to finish
:: before proceeding to the next line.
call npx hardhat run scripts/checkVotes.js --network localhost

echo.
echo Script execution finished.
:: Pause the script and wait for user input before closing
:: This version WILL display the "Press any key to continue . . ." message
pause
