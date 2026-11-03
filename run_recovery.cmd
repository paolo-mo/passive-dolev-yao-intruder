@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  Run run_test.py on a fixed list of protocols, accumulating
::  rows into a single CSV.  Each protocol writes its own log
::  file thanks to --log-suffix.
:: ============================================================

:: Protocols to run, space-separated.
set PROTOCOLS=From_A_Mutual

:: ----- Configuration -----------------------------------------
set SESSIONS=3
set PROVIDER=jdk
set LOG_SUFFIX=recovery
set CSV=all_protocols_timing-%PROVIDER%-%SESSIONS%s-%LOG_SUFFIX%.csv

:: ----- Sanity checks -----------------------------------------
if not exist run_test.py (
    echo [ERROR] run_test.py not found in the current directory.
    echo         Change to the directory containing run_test.py first.
    exit /b 1
)

:: Delete the CSV before the run so the header is written fresh.
:: remove this line if you want to append to an existing CSV.
if exist %CSV% (
    echo removing existing CSV: %CSV%
    del /q %CSV%
)

:: ----- Loop --------------------------------------------------
set COUNT=0
set FAILED=

for %%P in (%PROTOCOLS%) do (
    set /a COUNT+=1
    echo.
    echo ============================================================
    echo [!COUNT!] Running %%P
    echo ============================================================
    python run_test.py %%P ^
        --sessions %SESSIONS% ^
        --provider %PROVIDER% ^
        --csv %CSV% ^
        --log-suffix %LOG_SUFFIX%
    if errorlevel 1 (
        echo [WARN] %%P exited with a non-zero code.
        set FAILED=!FAILED! %%P
    )
)

:: ----- Summary ----------------------------------------------
echo.
echo ============================================================
echo  Completed %COUNT% protocol(s).
if defined FAILED (
    echo  Non-zero exits:!FAILED!
) else (
    echo  All protocols completed successfully.
)
echo  CSV: %CSV%
echo  Logs: objcheck_*-%PROVIDER%-%SESSIONS%s-%LOG_SUFFIX%.log
echo ============================================================

endlocal