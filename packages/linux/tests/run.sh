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

# Guard: nothing here may reach the real systemd, polkit or sudo (a real systemd-run/systemctl on a workstation
# pops the owner's password dialogs). guard/bin holds look-alikes that record the call and exit 99; they come
# first in this script's PATH and, through relocate(), after the stand-ins in every package copy's PATH. The
# run fails if one was called, and the script also refuses to run the packages' real paths (see below).
guard="$tmp/guard"; mkdir -p "$guard/bin"
for c in systemd-run systemctl pkexec sudo su doas run0 machinectl; do
	printf '#!/bin/sh\necho "%s $*" >>"%s/hits"\nexit 99\n' "$c" "$guard" >"$guard/bin/$c"
	chmod +x "$guard/bin/$c"
done
PATH="$guard/bin:$PATH"; export PATH
# relocate PKG DEST STUBDIR [more sed expressions]: copy a package with its PATH line pointing at the stand-ins
# first, then the guard, then the system; fails the run if the PATH line was not found.
relocate() {
	src=$1; dest=$2; stubs=$3; shift 3
	sed -e "s|^PATH=/usr/bin:/bin:/usr/sbin:/sbin|PATH=$stubs:$guard/bin:/usr/bin:/bin:/usr/sbin:/sbin|" "$@" "$src" >"$dest"
	grep -q "^PATH=$stubs:$guard/bin:" "$dest" || { echo "FAIL $(basename "$src"): the PATH guard did not apply"; exit 1; }
}
check() { if eval "$2"; then passed=$((passed + 1)); else failed=$((failed + 1)); echo "FAIL $1"; fi; }

for f in "$pkgdir"/*.sh; do
	n=$(basename "$f")
	check "$n parses under sh" "sh -n '$f'"
	check "$n header is one JSON line" "head -1 '$f' | sed 's/^# ominull-package: //' | python3 -c 'import json,sys; json.load(sys.stdin)'"
	if command -v checkbashisms >/dev/null 2>&1; then check "$n has no bashisms" "checkbashisms '$f' >/dev/null 2>&1"; fi
done

# ---------------------------------------------------------------- reboot.sh
stub="$tmp/bin"; mkdir -p "$stub" "$tmp/state" "$tmp/ps/BAT0"
relocate "$pkgdir/reboot.sh" "$tmp/reboot.sh" "$stub" \
	-e "s|/var/lib/ominull-maintenance|$tmp/state|" -e "s|/var/run/reboot-required|$tmp/reboot-required|" \
	-e "s|/run/systemd/shutdown/scheduled|$tmp/scheduled|" -e "s|/sys/class/power_supply|$tmp/ps|"
echo Battery >"$tmp/ps/BAT0/type"; echo Charging >"$tmp/ps/BAT0/status"
cat >"$stub/date" <<'SH'
#!/bin/sh
# STUB_HM / STUB_UHM pin the clock for window checks; anything else is the real date.
if [ "$*" = "+%H:%M" ] && [ -n "${STUB_HM:-}" ]; then echo "$STUB_HM"; exit 0; fi
if [ "$*" = "-u +%H:%M" ] && [ -n "${STUB_UHM:-}" ]; then echo "$STUB_UHM"; exit 0; fi
exec /bin/date "$@"
SH
chmod +x "$stub/date"
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
for w in "01:00-02:00,13:00-14:00 13:30" "22:00-01:00 00:30" "03:00-04:00Z U03:30"; do
	set -- $w
	reset; touch "$tmp/reboot-required" "$tmp/someone"
	case "$2" in U*) o=$(run enforce OMINULL_PARAM_WINDOW="$1" STUB_HM=12:00 STUB_UHM="${2#U}") ;; *) o=$(run enforce OMINULL_PARAM_WINDOW="$1" STUB_HM="$2") ;; esac
	check "rb: window $1 at $2 counts as inside" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ]'
done
for w in "01:00-02:00,13:00-14:00 12:00" "03:00-04:00Z U12:00"; do
	set -- $w
	reset; touch "$tmp/reboot-required" "$tmp/someone"
	case "$2" in U*) o=$(run enforce OMINULL_PARAM_WINDOW="$1" STUB_HM=03:30 STUB_UHM="${2#U}") ;; *) o=$(run enforce OMINULL_PARAM_WINDOW="$1" STUB_HM="$2") ;; esac
	check "rb: window $1 at $2 is outside" '[ "$(echo "$o" | field "d[\"state\"]")" != fixed ]'
done
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
for bad in OMINULL_PARAM_WHEN_BUSY=sometimes OMINULL_PARAM_WINDOW=25:00-01:00 OMINULL_PARAM_WINDOW=01:00-02:00, OMINULL_PARAM_WINDOW=01:00-02:00,03:00-04:00,05:00-06:00,07:00-08:00,09:00-10:00 OMINULL_PARAM_WARN_MINUTES=0 OMINULL_PARAM_ONLY_IF_NEEDED=yes OMINULL_PARAM_IDLE_MINUTES=1441; do
	o=$(run enforce "$bad") && rc=0 || rc=$?
	check "rb: $bad fails" '[ $rc -eq 1 ] && [ "$(echo "$o" | field "d[\"state\"]")" = failed ]'
done
for m in audit enforce revert; do
	o=$(run $m) || true
	check "rb: $m prints one JSON line" '[ $(printf "%s\n" "$o" | wc -l) -eq 1 ] && echo "$o" | field "d[\"v\"]" >/dev/null'
done


# ---------------------------------------------------------------- cleanup.sh
sk="$tmp/cl"; mkdir -p "$sk/bin" "$sk/journal" "$sk/apt"
relocate "$pkgdir/cleanup.sh" "$sk/pkg.sh" "$sk/bin" -e "s|^JOURNAL_DIR=.*|JOURNAL_DIR=$sk/journal|" -e "s|^APT_DIR=.*|APT_DIR=$sk/apt|"
cat >"$sk/bin/journalctl" <<SH
#!/bin/sh
[ -e "$sk/jfail" ] && exit 1
echo "\$*" >>"$sk/ctl.log"
case "\$1" in --vacuum-size=*M) n=\${1#--vacuum-size=}; n=\${n%M}; truncate -s \$((n * 1048576)) "$sk/journal/system.journal" ;; esac
SH
cat >"$sk/bin/apt-get" <<SH
#!/bin/sh
[ -e "$sk/afail" ] && exit 100
echo "apt-get \$*" >>"$sk/ctl.log"; rm -f "$sk/apt"/*.deb
SH
cat >"$sk/bin/snap" <<SH
#!/bin/sh
case "\$1" in
list) cat "$sk/snaps" ;;
remove) echo "snap \$*" >>"$sk/ctl.log" ;;
esac
SH
chmod +x "$sk/bin"/*
cl() { env -i OMINULL_PARAM_MODE="$1" "${@:2}" sh "$sk/pkg.sh"; }
cl_reset() { rm -f "$sk/ctl.log" "$sk/jfail" "$sk/afail" "$sk/apt"/* "$sk/journal"/*
	truncate -s 1000M "$sk/journal/system.journal"; truncate -s 20M "$sk/apt/a.deb"
	printf '%s\n' "Name  Version  Rev  Tracking  Publisher  Notes" "core22  20240111  1380  latest/stable  canonical  base" \
		"core22  20230801  1033  latest/stable  canonical  base,disabled" "firefox  120.0  3400  latest/stable  mozilla  disabled" "bad.name  1  7  x  y  disabled" >"$sk/snaps"; }
cl_reset
o=$(cl audit); check "cl: audit finds a disabled snap revision" '[ "$(echo "$o" | field "d[\"state\"]")" = drift ] && [ "$(echo "$o" | field "d[\"detail\"][\"snap_disabled_revisions\"]")" = 2 ]'
check "cl: audit changes nothing" '[ ! -e "$sk/ctl.log" ]'
o=$(cl audit OMINULL_PARAM_SNAP_REVISIONS=false); check "cl: snap_revisions off ignores snaps" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
truncate -s 3000M "$sk/journal/system.journal"
o=$(cl audit OMINULL_PARAM_SNAP_REVISIONS=false); check "cl: a journal over the cap is drift" '[ "$(echo "$o" | field "d[\"state\"]")" = drift ] && echo "$o" | grep -q "journal is over"'
truncate -s 2200M "$sk/journal/system.journal"
o=$(cl audit OMINULL_PARAM_SNAP_REVISIONS=false); check "cl: the journal gets a 10% allowance" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
truncate -s 40M "$sk/apt/a.deb"
o=$(cl audit OMINULL_PARAM_SNAP_REVISIONS=false OMINULL_PARAM_APT_CACHE_MAX_MB=10); check "cl: an apt cache over its limit is drift" '[ "$(echo "$o" | field "d[\"state\"]")" = drift ]'
cl_reset; truncate -s 3000M "$sk/journal/system.journal"
o=$(cl enforce); check "cl: enforce trims the journal and removes old snap revisions" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ] && grep -qx -- "--vacuum-size=2048M" "$sk/ctl.log" && grep -qx "snap remove core22 --revision=1033" "$sk/ctl.log" && grep -qx "snap remove firefox --revision=3400" "$sk/ctl.log" && [ $(grep -c "^snap " "$sk/ctl.log") -eq 2 ]'
check "cl: the apt cache under its limit is left" '! grep -q "^apt-get" "$sk/ctl.log" && [ -e "$sk/apt/a.deb" ]'
cl_reset; truncate -s 300M "$sk/apt/a.deb"
o=$(cl enforce OMINULL_PARAM_SNAP_REVISIONS=false OMINULL_PARAM_APT_CACHE_MAX_MB=100); check "cl: enforce empties a big apt cache, leaves the journal under its cap" '[ "$(echo "$o" | field "d[\"state\"]")" = fixed ] && grep -qx "apt-get clean" "$sk/ctl.log" && ! grep -q vacuum "$sk/ctl.log"'
o=$(cl enforce OMINULL_PARAM_SNAP_REVISIONS=false); check "cl: a second enforce changes nothing" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
cl_reset; truncate -s 300M "$sk/apt/a.deb"; touch "$sk/afail"
o=$(cl enforce OMINULL_PARAM_SNAP_REVISIONS=false) && rc=0 || rc=$?; check "cl: apt busy fails the run" '[ $rc -eq 1 ] && [ "$(echo "$o" | field "d[\"state\"]")" = failed ]'
o=$(cl revert); check "cl: revert is na" '[ "$(echo "$o" | field "d[\"state\"]")" = na ]'
for bad in OMINULL_PARAM_JOURNAL_MAX_MB=99 OMINULL_PARAM_JOURNAL_MAX_MB=102401 OMINULL_PARAM_JOURNAL_MAX_MB=x OMINULL_PARAM_JOURNAL_MAX_MB=0100 OMINULL_PARAM_APT_CACHE_MAX_MB=10241 OMINULL_PARAM_APT_CACHE_MAX_MB=-1 OMINULL_PARAM_SNAP_REVISIONS=yes; do
	o=$(cl enforce "$bad") && rc=0 || rc=$?
	check "cl: $bad fails" '[ $rc -eq 1 ] && [ "$(echo "$o" | field "d[\"state\"]")" = failed ]'
done
for m in audit enforce revert; do
	cl_reset; o=$(cl $m) || true
	check "cl: $m prints one JSON line" '[ $(printf "%s\n" "$o" | wc -l) -eq 1 ] && echo "$o" | field "d[\"v\"]" >/dev/null'
done

# ---------------------------------------------------------------- maintenance-mode.sh
sm="$tmp/mm"; mkdir -p "$sm/bin"
relocate "$pkgdir/maintenance-mode.sh" "$sm/pkg.sh" "$sm/bin" -e "s|/var/lib/ominull-maintenance|$sm/state|"
printf '#!/bin/sh\nexit 0\n' >"$sm/bin/systemd-inhibit"
printf '#!/bin/sh\n[ "$1" = is-active ] && exit 3\nexit 0\n' >"$sm/bin/systemctl"
chmod +x "$sm/bin"/*
mm() { env -i OMINULL_PARAM_MODE="$1" "${@:2}" sh "$sm/pkg.sh"; }
o=$(mm audit); check "mm: audit with no lock held is ok and off" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ] && [ "$(echo "$o" | field "d[\"detail\"][\"maintenance_mode\"][\"on\"]")" = False ]'
o=$(mm revert); check "mm: revert with nothing held is ok" '[ "$(echo "$o" | field "d[\"state\"]")" = ok ]'
o=$(mm enforce OMINULL_PARAM_HOURS=25) && rc=0 || rc=$?; check "mm: hours out of range fails before anything starts" '[ $rc -eq 1 ] && [ "$(echo "$o" | field "d[\"state\"]")" = failed ]'

# ---------------------------------------------------------------- security-baseline.sh
sb="$tmp/sb"; mkdir -p "$sb/bin" "$sb/journal"; touch "$sb/journal/x"
relocate "$pkgdir/security-baseline.sh" "$sb/pkg.sh" "$sb/bin" -e "s|/etc/passwd|$sb/passwd|g" -e "s|/etc/shadow|$sb/shadow|g" -e "s|/var/log/journal|$sb/journal|g" -e "s|/etc/ssh/|$sb/ssh/|g"
mkdir -p "$sb/ssh/sshd_config.d"; echo "Port 22" >"$sb/ssh/sshd_config"
printf '#!/bin/sh\ncase "$1" in -V) echo "OpenSSH_${SB_VER:-9.6}p1 Ubuntu" >&2 ;; -T) printf "port 22\\npasswordauthentication %%s\\nkbdinteractiveauthentication no\\n" "${SB_PW:-no}" ;; esac\n' >"$sb/bin/sshd"
printf '#!/bin/sh\necho "LISTEN 0 128 ${SB_LISTEN:-10.0.0.5:22} 0.0.0.0:*"\n' >"$sb/bin/ss"
printf '#!/bin/sh\n[ -z "${SB_NOIP:-}" ] || exit 1\necho "1: lo inet 8.8.8.8/32 scope global"\n' >"$sb/bin/ip"
printf '#!/bin/sh\necho "$(( $(/usr/bin/date +%%s) - ${SB_JOURNAL:-40} * 86400 )).000 host unit: line"\n' >"$sb/bin/journalctl"
printf '#!/bin/sh\necho "${SB_VIRT:-none}"\n' >"$sb/bin/systemd-detect-virt"
printf '#!/bin/sh\necho /\n' >"$sb/bin/findmnt"
printf '#!/bin/sh\n[ -n "${SB_NOSNAP:-}" ] || echo "ID 5 gen 9 cgen 9 top level 5 otime $(/usr/bin/date "+%%F %%T") path snap"\n' >"$sb/bin/btrfs"
chmod +x "$sb"/bin/*
printf 'root:x:0:0::/root:/bin/sh\nme:x:1000:1000::/home/me:/bin/sh\n' >"$sb/passwd"
printf 'root:!:1::::::\nme:$6$x:1::::::\n' >"$sb/shadow"
sb_run() { env "$@" sh "$sb/pkg.sh" 2>/dev/null; }
sb_state() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(next((c["state"] for c in d["detail"]["controls"] if c["id"]==sys.argv[2]),"missing"))' "$1" "$2"; }
out=$(sb_run A=1)
check "sb: a clean machine is ok" 'echo "$out" | grep -q "^{\"v\":1,\"state\":\"ok\""'
for c in ssh.protocol_1_off ssh.password_auth_off ssh.trusted_networks accounts.least_privilege logs.journal_retention backups.read_only_recent; do
	check "sb: $c passes" '[ "$(sb_state "$out" '"$c"')" = pass ]'
done
out=$(sb_run SB_PW=yes)
check "sb: password login fails and drifts" '[ "$(sb_state "$out" ssh.password_auth_off)" = fail ] && echo "$out" | grep -q "\"state\":\"drift\""'
printf 'Match User deploy\n\tPasswordAuthentication yes\n' >"$sb/ssh/sshd_config.d/x.conf"; out=$(sb_run A=1); rm "$sb/ssh/sshd_config.d/x.conf"
check "sb: password login back on in a Match block fails" '[ "$(sb_state "$out" ssh.password_auth_off)" = fail ] && echo "$out" | grep -q "Match block"'
out=$(sb_run SB_VER=7.5)
check "sb: OpenSSH before 7.6 fails" '[ "$(sb_state "$out" ssh.protocol_1_off)" = fail ]'
out=$(sb_run SB_LISTEN=8.8.8.8:22)
check "sb: SSH on a public address fails" '[ "$(sb_state "$out" ssh.trusted_networks)" = fail ]'
out=$(sb_run SB_LISTEN=0.0.0.0:22)
check "sb: SSH on all addresses with a public one fails" '[ "$(sb_state "$out" ssh.trusted_networks)" = fail ]'
out=$(sb_run SB_LISTEN=0.0.0.0:22 SB_NOIP=1)
check "sb: addresses that cannot be read fail" '[ "$(sb_state "$out" ssh.trusted_networks)" = fail ] && echo "$out" | grep -q "check failed"'
out=$(sb_run SB_LISTEN=10.0.0.5:2222)
check "sb: SSH not listening does not apply" '[ "$(sb_state "$out" ssh.trusted_networks)" = na ]'
out=$(sb_run SB_JOURNAL=14)
check "sb: a short journal fails" '[ "$(sb_state "$out" logs.journal_retention)" = fail ] && echo "$out" | grep -q "reaches back 14 days"'
out=$(sb_run SB_JOURNAL=14 OMINULL_PARAM_JOURNAL_MIN_DAYS=7)
check "sb: the journal target is a parameter" '[ "$(sb_state "$out" logs.journal_retention)" = pass ]'
rm "$sb/journal/x"; out=$(sb_run A=1); touch "$sb/journal/x"
check "sb: a journal in memory only fails" '[ "$(sb_state "$out" logs.journal_retention)" = fail ]'
out=$(sb_run SB_VIRT=lxc)
check "sb: a guest does not answer for its backups" '[ "$(sb_state "$out" backups.read_only_recent)" = na ]'
out=$(sb_run SB_NOSNAP=1)
check "sb: no read-only snapshot fails" '[ "$(sb_state "$out" backups.read_only_recent)" = fail ]'
cp "$sb/passwd" "$sb/passwd.ok"; echo 'toor:x:0:0::/root:/bin/sh' >>"$sb/passwd"; out=$(sb_run A=1); cp "$sb/passwd.ok" "$sb/passwd"
check "sb: a second user id 0 fails" '[ "$(sb_state "$out" accounts.least_privilege)" = fail ] && echo "$out" | grep -q toor'
cp "$sb/shadow" "$sb/shadow.ok"; echo 'nopw::1::::::' >>"$sb/shadow"; out=$(sb_run A=1); cp "$sb/shadow.ok" "$sb/shadow"
check "sb: an empty password fails" '[ "$(sb_state "$out" accounts.least_privilege)" = fail ] && echo "$out" | grep -q nopw'
out=$(sb_run OMINULL_PARAM_MODE=enforce)
check "sb: enforce changes nothing and answers na" 'echo "$out" | grep -q "\"state\":\"na\"" && echo "$out" | grep -q "\"controls\":\[\]"'
if sb_run OMINULL_PARAM_JOURNAL_MIN_DAYS=0x >"$sb/bad"; then rc=0; else rc=$?; fi
check "sb: a bad parameter fails the run" '[ "$rc" = 1 ] && grep -q "\"state\":\"failed\"" "$sb/bad"'

# ---------------------------------------------------------------- manifest and guard
man=$(python3 -I "$pkgdir/../../scripts/package-manifest.py" "$pkgdir")
check "manifest lists every Linux package with the sha256 of its file" 'for f in "$pkgdir"/*.sh; do n=$(basename "$f"); s=$(sha256sum "$f" | cut -d" " -f1); echo "$man" | grep -q "\"sha256\": \"$s\"" || exit 1; done'
check "manifest carries parameter defaults as the environment values" 'echo "$man" | python3 -c "import json,sys; m={e[\"name\"]:e for e in json.load(sys.stdin)}; assert m[\"linux-cleanup\"][\"params\"][\"journal_max_mb\"]==\"2048\"; assert m[\"linux-cleanup\"][\"params\"][\"snap_revisions\"]==\"true\""'
check "the guard stops a real systemd-run and records it" '(systemd-run --unit=x true >/dev/null 2>&1; [ $? -eq 99 ] && [ -s "$guard/hits" ]) && rm -f "$guard/hits"'

check "no test reached a real systemd-run, systemctl, pkexec or sudo" '[ ! -e "$guard/hits" ] || { cat "$guard/hits" >&2; false; }'
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
