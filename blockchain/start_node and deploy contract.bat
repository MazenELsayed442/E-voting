@echo off
REM Batch script to start Hardhat node, wait for it to listen on port 8545,
REM and then run the deployment script in another window.
REM This version is modified to create flag files for synchronization.

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

    REM --- Start of modification as per run_all.bat instructions ---
    echo Ensuring no old deployment flag exists...
    IF EXIST deployment_complete.flag DEL deployment_complete.flag /Q
    IF EXIST deployment_failed.flag DEL deployment_failed.flag /Q
    echo.

    echo Starting deployment script...
    echo This will create 'deployment_complete.flag' on success or 'deployment_failed.flag' on failure.
    REM Use /c to close window automatically and create flag file upon completion or failure.
    START "Deployment Script" cmd /c "npx hardhat run --network localhost scripts/deploy.js && (echo Deployment successful > deployment_complete.flag) || (echo Deployment FAILED > deployment_failed.flag)"
    REM --- End of modification ---

    echo Both processes initiated. The 'Hardhat Node' window needs to remain open.
    echo The 'Deployment Script' window will create a flag file and then close.
)

GOTO :SCRIPT_END_CHECK

:WAIT_FAILED
IF %NODE_READY% EQU 0 (
    echo Failed to detect Hardhat node starting. Please check the 'Hardhat Node' window for errors.
    REM Optionally, create a failure flag here if the node itself fails to start,
    REM which run_all.bat could also check for.
    REM echo Hardhat node failed to start > node_start_failed.flag
)

:SCRIPT_END_CHECK
echo Script finished initiating processes.

REM The original 'pause' is now commented out for better automation with run_all.bat
REM If you want this window to pause before run_all.bat checks the flag, uncomment it.
pause

ENDLOCAL
