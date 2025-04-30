@echo off
:: This batch file compiles the Hardhat project in the current directory.

echo Running Hardhat compilation...
npx hardhat compile

echo.
echo Compilation finished. Press any key to exit.
pause > nul
