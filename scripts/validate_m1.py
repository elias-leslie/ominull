import os

ev_dir = "/srv/workspaces/projects/ominull/evidence/m1-callout"
loaded_path = os.path.join(ev_dir, "wfp_loaded.xml")
post_path = os.path.join(ev_dir, "wfp_post_unload.xml")
baseline_path = os.path.join(ev_dir, "wfp_baseline.xml")
log_path = os.path.join(ev_dir, "m1_log.txt")

with open(loaded_path, "r", encoding="utf-8", errors="replace") as f:
    loaded_content = f.read()

with open(post_path, "r", encoding="utf-8", errors="replace") as f:
    post_content = f.read()

with open(baseline_path, "r", encoding="utf-8", errors="replace") as f:
    baseline_content = f.read()

with open(log_path, "r", encoding="utf-8", errors="replace") as f:
    log_content = f.read()

print("================================================================")
print("       OMINULL MILESTONE 1 VERIFICATION REPORT")
print("================================================================")

# 1. Driver Service & Presence Verification
has_create_ok = "[SC] CreateService SUCCESS" in log_content
has_start_running = "STATE              : 4  RUNNING" in log_content
has_driverquery_ok = "ominull" in log_content and "Running" in log_content
has_stop_ok = "STATE              : 1  STOPPED" in log_content
has_delete_ok = "[SC] DeleteService SUCCESS" in log_content

print(f"[1] Service Creation:           {'PASS' if has_create_ok else 'FAIL'}")
print(f"[2] Service Start (RUNNING):     {'PASS' if has_start_running else 'FAIL'}")
print(f"[3] Driver Presence (Kernel):    {'PASS' if has_driverquery_ok else 'FAIL'}")
print(f"[4] Service Stop (STOPPED):      {'PASS' if has_stop_ok else 'FAIL'}")
print(f"[5] Service Deletion:            {'PASS' if has_delete_ok else 'FAIL'}")

# 2. WFP Engine Objects Verification
sublayer_in_loaded = "OminullSubLayer" in loaded_content
callout_in_loaded = "OminullAleConnectCallout" in loaded_content
filter_in_loaded = "OminullAleConnectFilter" in loaded_content

print("\n[6] WFP Loaded Objects:")
print(f"    - Sublayer Added:            {'PASS' if sublayer_in_loaded else 'FAIL'}")
print(f"    - Callout Registered/Added:  {'PASS' if callout_in_loaded else 'FAIL'}")
print(f"    - Filter Added:              {'PASS' if filter_in_loaded else 'FAIL'}")

# 3. Post-Unload Zero Leak Verification
sublayer_in_post = "OminullSubLayer" in post_content
callout_in_post = "OminullAleConnectCallout" in post_content
filter_in_post = "OminullAleConnectFilter" in post_content

print("\n[7] Zero-Leak Verification (Post-Unload):")
print(f"    - Sublayer Leaked:           {'NO (CLEAN)' if not sublayer_in_post else 'LEAKED'}")
print(f"    - Callout Leaked:            {'NO (CLEAN)' if not callout_in_post else 'LEAKED'}")
print(f"    - Filter Leaked:             {'NO (CLEAN)' if not filter_in_post else 'LEAKED'}")

# 4. Outbound Traffic Classification Verification
traffic_1_ok = "Ominull Test Server: OK" in log_content
ping_ok = "Reply from 10.0.0.57" in log_content

print("\n[8] Outbound Network Telemetry / ALE Traffic:")
print(f"    - HTTP /traffic-1 Permitted: {'PASS' if traffic_1_ok else 'FAIL'}")
print(f"    - ICMP Echo Permitted:       {'PASS' if ping_ok else 'FAIL'}")

all_pass = (
    has_create_ok and has_start_running and has_driverquery_ok and
    has_stop_ok and has_delete_ok and
    sublayer_in_loaded and callout_in_loaded and filter_in_loaded and
    not sublayer_in_post and not callout_in_post and not filter_in_post and
    traffic_1_ok and ping_ok
)

print("\n================================================================")
if all_pass:
    print(" >>> FINAL RESULT: MILESTONE 1 VERIFICATION PROVEN PASS <<<")
else:
    print(" >>> FINAL RESULT: VERIFICATION FAILED <<<")
print("================================================================")
