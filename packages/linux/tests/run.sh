#!/usr/bin/env bash
# Unit checks for the Linux maintenance packages, run under /bin/sh (dash where it is the
# system shell). Each run uses a copy of the package with its fixed paths moved into a temp
# folder and stand-in commands (loginctl, shutdown, sleep, needs-restarting) first in PATH,
# so nothing on this machine is touched.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pkgdir="$(dirname "$here")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
passed=0; failed=0
check() { if eval "$2"; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL $1"; fi; }

for f in "$pkgdir"/*.sh; do
	n=$(basename "$f")
	check "$n parses under sh" "sh -n '$f'"
	check "$n header is one JSON line" "head -1 '$f' | sed 's/^# ominull-package: //' | python3 -c 'import json,sys; json.load(sys.stdin)'"
	if command -v checkbashisms >/dev/null 2>&1; then check "$n has no bashisms" "checkbashisms '$f' >/dev/null 2>&1"; fi
done

# ---------------------------------------------------------------- reboot.sh
stub="$tmp/bin"; mkdir -p "$stub" "$tmp/state" "$tmp/ps/BAT0"
sed -e "s|^PATH=/usr/bin:/bin:/usr/sbin:/sbin|PATH=$stub:/usr/bin:/bin:/usr/sbin:/sbin|" \
	-e "s|/var/lib/ominull-maintenance|$tmp/state|" -e "s|/var/run/reboot-required|$tmp/reboot-required|" \
	-e "s|/run/systemd/shutdown/scheduled|$tmp/scheduled|" -e "s|/sys/class/power_supply|$tmp/ps|" \
	"$pkgdir/reboot.sh" >"$tmp/reboot.sh"
echo Battery >"$tmp/ps/BAT0/type"; echo Charging >"$tmp/ps/BAT0/status"
cat >"$stub/shutdown" <<SH
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/shutdown.log"
exit \${STUB_SHUTDOWN_CODE:-0}
SH
cat >"$stub/loginctl" <<SH
#!/bin/sh
[ -e "$tmp/someone" ] || exit 0
case "\$1" in
list-sessions) echo "2 1000 nadia seat0 tty2" ;;
show-session) printf 'Active=yes\nRemote=no\nClass=user\nIdleHint=no\nIdleSinceHint=0\n' ;;
esac
SH
cat >"$stub/sleep" <<SH
#!/bin/sh
n=\$(cat "$tmp/slept" 2>/dev/null || echo 0); echo \$((n + 1)) >"$tmp/slept"
[ \$((n + 1)) -ge 2 ] && rm -f "$tmp/someone"
exit 0
SH
chmod +x "$stub"/*
run() { env -i OMINULL_PARAM_MODE="$1" "${@:2}" sh "$tmp/reboot.sh"; }
field() { python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(eval(sys.argv[1]))' "$1"; }
reset() { rm -f "$tmp/reboot-required" "$tmp/someone" "$tmp/slept" "$tmp/shutdown.log" "$tmp/scheduled" "$tmp/state/reboot.at"; echo Charging >"$tmp/ps/BAT0/status"; }

reset
o=$(run audit); check "rb: audit, nothing pending is ok" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
touch "$tmp/reboot-required"
o=$(run audit); check "rb: audit, pending is drift" '[ "$(echo "$o" | field "d[\"state\"]")" = drift ] && [ "$(echo "$o" | field "d[\"detail\"][\"pending_reboot\"]")" = True ]'
rm -f "$tmp/reboot-required"
o=$(run enforce); check "rb: only_if_needed and nothing pending: no restart" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ] && [ ! -e "$tmp/shutdown.log" ]'
touch "$tmp/reboot-required" "$tmp/someone"
o=$(run enforce); check "rb: someone at the machine skips" '[ "$(echo "$o" | field "d[\"state\"]")" = skipped ] && [ ! -e "$tmp/shutdown.log" ]'
o=$(run enforce OMINULL_PARAM_WHEN_BUSY=run); check "rb: when_busy run restarts with someone there" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ]'
check "rb: shutdown -r +10 with the warning" 'grep -q "^-r +10 OmniNull maintenance: this computer restarts in 10 minutes" "$tmp/shutdown.log"'
check "rb: marker written" '[ -s "$tmp/state/reboot.at" ]'
o=$(run enforce); check "rb: second enforce leaves the scheduled restart" '[ "$(echo "$o" | field "d[\"detail\"][\"reason\"]")" = "a restart is already scheduled" ] && [ $(wc -l <"$tmp/shutdown.log") -eq 1 ]'
o=$(run revert); check "rb: revert cancels its own restart" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ] && tail -1 "$tmp/shutdown.log" | grep -qx -- "-c" && [ ! -e "$tmp/state/reboot.at" ]'
o=$(run revert); check "rb: revert without its own restart is ok" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
reset; touch "$tmp/reboot-required" "$tmp/someone"
o=$(run enforce OMINULL_PARAM_WINDOW=00:00-23:59); check "rb: inside the window people do not count" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ] || [ "$(date +%H:%M)" = 23:59 ]'
reset; touch "$tmp/reboot-required" "$tmp/someone"
o=$(run enforce OMINULL_PARAM_WHEN_BUSY=wait); check "rb: wait restarts once nobody is there" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ] && [ "$(cat "$tmp/slept")" = 2 ]'
reset; touch "$tmp/reboot-required"; echo Discharging >"$tmp/ps/BAT0/status"
o=$(run enforce OMINULL_PARAM_WHEN_BUSY=run); check "rb: battery still counts" '[ "$(echo "$o" | field "d[\"detail\"][\"reason\"]")" = "running on battery" ]'
reset; touch "$tmp/reboot-required" "$tmp/scheduled"
o=$(run enforce); check "rb: a shutdown scheduled elsewhere is left be" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ] && [ ! -e "$tmp/shutdown.log" ]'
reset; touch "$tmp/reboot-required"
o=$(run enforce STUB_SHUTDOWN_CODE=1) || true; check "rb: a shutdown error fails" '[ "$(echo "$o" | field "d[\"state\"]")" = failed ] && [ ! -e "$tmp/state/reboot.at" ]'
reset; echo $(( $(date +%s) - 60 )) >"$tmp/state/reboot.at"
o=$(run revert); check "rb: a restart time that passed is forgotten" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ] && [ ! -e "$tmp/state/reboot.at" ]'
for bad in OMINULL_PARAM_WHEN_BUSY=sometimes OMINULL_PARAM_WINDOW=25:00-01:00 OMINULL_PARAM_WARN_MINUTES=0 OMINULL_PARAM_ONLY_IF_NEEDED=yes OMINULL_PARAM_IDLE_MINUTES=1441; do
	o=$(run enforce "$bad") && rc=0 || rc=$?
	check "rb: $bad fails" '[ $rc -eq 1 ] && [ "$(echo "$o" | field "d[\"state\"]")" = failed ]'
done
for m in audit enforce revert; do
	o=$(run $m) || true
	check "rb: $m prints one JSON line" '[ $(printf "%s\n" "$o" | wc -l) -eq 1 ] && echo "$o" | field "d[\"v\"]" >/dev/null'
done

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
