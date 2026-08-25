@echo off
setlocal EnableDelayedExpansion

set HOST_IP=10.0.0.57
set HOST_PORT=9998
set LOG_FILE=C:\drv\m2_log.txt

echo === STARTING MILESTONE 2 KERNEL POLICY ENFORCEMENT VERIFICATION === > %LOG_FILE%
echo Date: %DATE% %TIME% >> %LOG_FILE%

echo === [0] Configuring DbgPrint output mask in registry === >> %LOG_FILE%
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print" /v DEFAULT /t REG_DWORD /d 0xFFFFFFFF /f >> %LOG_FILE% 2>&1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print" /v IHVDRIVER /t REG_DWORD /d 0xFFFFFFFF /f >> %LOG_FILE% 2>&1

echo === [1] Importing test certificate into Root and TrustedPublisher stores === >> %LOG_FILE%
certutil.exe -f -addstore Root C:\drv\testcert.cer >> %LOG_FILE% 2>&1
certutil.exe -f -addstore TrustedPublisher C:\drv\testcert.cer >> %LOG_FILE% 2>&1

echo === [2] Capturing baseline WFP state (before driver load) === >> %LOG_FILE%
netsh.exe wfp show state file=C:\drv\wfp_m2_baseline.xml >> %LOG_FILE% 2>&1

echo === [3] Creating kernel service 'wfpsentinel' === >> %LOG_FILE%
sc.exe create wfpsentinel type= kernel binPath= C:\drv\wfpsentinel.sys >> %LOG_FILE% 2>&1

echo === [4] Starting kernel service 'wfpsentinel' === >> %LOG_FILE%
sc.exe start wfpsentinel >> %LOG_FILE% 2>&1

echo === [5] Verifying service status and driver presence === >> %LOG_FILE%
sc.exe query wfpsentinel >> %LOG_FILE% 2>&1
driverquery.exe /v /fo table | findstr.exe /i "wfpsentinel" >> %LOG_FILE% 2>&1

echo === [6] Capturing loaded WFP state (with active enforcement filter) === >> %LOG_FILE%
netsh.exe wfp show state file=C:\drv\wfp_m2_loaded.xml >> %LOG_FILE% 2>&1

echo === [7] Initial Kernel Statistics === >> %LOG_FILE%
C:\drv\wfpsentinel_ctl.exe stats >> %LOG_FILE% 2>&1

echo === [8] Step 1: Baseline Connection Test (Expected: ALLOW) === >> %LOG_FILE%
echo [*] Sending outbound HTTP request to http://%HOST_IP%:%HOST_PORT%/m2-baseline... >> %LOG_FILE%
curl.exe -v http://%HOST_IP%:%HOST_PORT%/m2-baseline >> %LOG_FILE% 2>&1
echo [Result Code: %ERRORLEVEL%] >> %LOG_FILE%

echo === [9] Step 2: Dynamically Pushing Kernel Block Rule via IOCTL === >> %LOG_FILE%
echo [*] Adding rule to block %HOST_IP%:%HOST_PORT% (TCP)... >> %LOG_FILE%
C:\drv\wfpsentinel_ctl.exe block %HOST_IP% %HOST_PORT% tcp >> %LOG_FILE% 2>&1
C:\drv\wfpsentinel_ctl.exe stats >> %LOG_FILE% 2>&1

echo === [10] Step 3: Blocked Connection Test (Expected: BLOCKED BY KERNEL) === >> %LOG_FILE%
echo [*] Sending outbound HTTP request to http://%HOST_IP%:%HOST_PORT%/m2-blocked (should fail/timeout)... >> %LOG_FILE%
curl.exe -v --connect-timeout 3 http://%HOST_IP%:%HOST_PORT%/m2-blocked >> %LOG_FILE% 2>&1
echo [Result Code: %ERRORLEVEL%] (Non-zero indicates connection blocked) >> %LOG_FILE%

echo === [11] Step 4: Selective Enforcement Test (Expected: ALLOW) === >> %LOG_FILE%
echo [*] Testing ICMP ping to %HOST_IP% to verify non-targeted traffic is permitted... >> %LOG_FILE%
ping.exe -n 2 %HOST_IP% >> %LOG_FILE% 2>&1

echo === [12] Kernel Statistics after Block Attempt === >> %LOG_FILE%
C:\drv\wfpsentinel_ctl.exe stats >> %LOG_FILE% 2>&1

echo === [13] Step 5: Dynamically Clearing Kernel Block Rules via IOCTL === >> %LOG_FILE%
C:\drv\wfpsentinel_ctl.exe clear >> %LOG_FILE% 2>&1
C:\drv\wfpsentinel_ctl.exe stats >> %LOG_FILE% 2>&1

echo === [14] Step 6: Unblocked Connection Test (Expected: ALLOW AGAIN) === >> %LOG_FILE%
echo [*] Sending outbound HTTP request to http://%HOST_IP%:%HOST_PORT%/m2-unblocked... >> %LOG_FILE%
curl.exe -v http://%HOST_IP%:%HOST_PORT%/m2-unblocked >> %LOG_FILE% 2>&1
echo [Result Code: %ERRORLEVEL%] >> %LOG_FILE%

echo === [15] Final Kernel Statistics === >> %LOG_FILE%
C:\drv\wfpsentinel_ctl.exe stats >> %LOG_FILE% 2>&1

echo === [16] Stopping kernel service 'wfpsentinel' === >> %LOG_FILE%
sc.exe stop wfpsentinel >> %LOG_FILE% 2>&1

echo === [17] Deleting kernel service 'wfpsentinel' === >> %LOG_FILE%
sc.exe delete wfpsentinel >> %LOG_FILE% 2>&1

echo === [18] Capturing post-unload WFP state (zero-leak verification) === >> %LOG_FILE%
netsh.exe wfp show state file=C:\drv\wfp_m2_post_unload.xml >> %LOG_FILE% 2>&1

echo === [19] Posting Milestone 2 evidence files back to Linux host === >> %LOG_FILE%
curl.exe -X POST --data-binary @C:\drv\m2_log.txt http://%HOST_IP%:%HOST_PORT%/evidence/m2_log.txt
curl.exe -X POST --data-binary @C:\drv\wfp_m2_baseline.xml http://%HOST_IP%:%HOST_PORT%/evidence/wfp_m2_baseline.xml
curl.exe -X POST --data-binary @C:\drv\wfp_m2_loaded.xml http://%HOST_IP%:%HOST_PORT%/evidence/wfp_m2_loaded.xml
curl.exe -X POST --data-binary @C:\drv\wfp_m2_post_unload.xml http://%HOST_IP%:%HOST_PORT%/evidence/wfp_m2_post_unload.xml

echo === MILESTONE 2 EXECUTION COMPLETE === >> %LOG_FILE%
