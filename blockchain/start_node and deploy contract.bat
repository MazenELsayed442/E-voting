@echo off
REM Batch script to start Hardhat node, wait for it to listen on port 8545,
REM and then run the deployment script in another window.

SETLOCAL ENABLEDELAYEDEXPANSION

REM Configuration
SET HARDHAT_PORT=8545
SET MAX_WAIT_SECONDS=200
SET CHECK_INTERVAL_SECONDS=2

echo Starting Hardhat node in a new window...

REM Start the Hardhat node in a new command prompt window.
START "Hardhat Node" cmd /k "npx hardhat node"

echo Waiting for Hardhat node to listen on port %HARDHAT_PORT%...

SET /A WAIT_COUNT=0
SET NODE_READY=0

:WAIT_LOOP
REM Check if the port is listening
netstat -ano | findstr "LISTENING" | findstr ":%HARDHAT_PORT%" > NUL
IF %ERRORLEVEL% EQU 0 (
    echo Hardhat node is listening on port %HARDHAT_PORT%.
    SET NODE_READY=1
    GOTO :NODE_STARTED
)

REM Increment wait counter and check against max wait time
SET /A WAIT_COUNT+=%CHECK_INTERVAL_SECONDS%
IF !WAIT_COUNT! GEQ %MAX_WAIT_SECONDS% (
    echo Timed out waiting for Hardhat node after %MAX_WAIT_SECONDS% seconds.
    GOTO :WAIT_FAILED
)

REM Wait before checking again
echo Still waiting... (%WAIT_COUNT%/%MAX_WAIT_SECONDS% seconds)
timeout /t %CHECK_INTERVAL_SECONDS% /nobreak > NUL
GOTO :WAIT_LOOP

:NODE_STARTED
IF %NODE_READY% EQU 1 (
    echo Starting deployment script in a new window...

    REM Run the deployment script in a second new command prompt window.
    REM Use /c if you want the window to close automatically after deployment.
    START "Deployment Script" cmd /k "npx hardhat run --network localhost scripts/deploy.js"

    echo Both processes initiated in separate windows.
    echo The 'Hardhat Node' window needs to remain open.
)

:WAIT_FAILED
IF %NODE_READY% EQU 0 (
    echo Failed to detect Hardhat node starting. Please check the 'Hardhat Node' window for errors.
)

echo Script finished initiating processes.
ENDLOCAL
pause
