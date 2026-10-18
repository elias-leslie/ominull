# ominull-package: {"name":"linux-reboot","title":"Restart","description":"Restarts the computer after a warning to logged-in users, by default only when the system says a restart is needed; revert cancels a restart this package scheduled.","category":"maintenance","risk":"careful","reboot":true,"timeout":3600,"interval":"weekly","params":[{"name":"only_if_needed","type":"bool","default":true,"description":"Restart only when the system says a restart is needed"},{"name":"warn_minutes","type":"int","default":10,"min":1,"max":60,"description":"Minutes the warning gives people to save their work before the restart"},{"name":"idle_minutes","type":"int","default":15,"min":1,"max":1440,"description":"Enforce waits if someone used the computer within this many minutes"}],"platform":"linux","role":"reboot"}
# Runs as root under /bin/sh with a cleared environment. Stdout: one JSON result line.
# audit: a needed restart is drift. enforce: shutdown -r +N with a warning to logged-in users,
# after the preflight (someone at the machine, on battery) unless the run options say otherwise;
# a marker records the restart time. revert: cancel a restart this package scheduled.
# Run options: when_busy skip (default) | wait (up to half the timeout) | run (people do not
# count); window: 1-4 HH:MM-HH:MM ranges, comma separated, in machine time or in UTC with a trailing Z (a range may
# cross midnight), inside which people do not count.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
STATE_DIR=/var/lib/ominull-maintenance
MARK="$STATE_DIR/reboot.at"
TIMEOUT=3600

result() { # state changed-json [reason] [extra json fields, each starting with a comma]
	reason=""
	[ -n "${3:-}" ] && reason=",\"reason\":\"$3\""
	printf '{"v":1,"state":"%s","reboot":false,"changed":%s,"detail":{"mode":"%s","pending_reboot":%s%s%s}}\n' "$1" "$2" "$MODE" "${PENDING:-false}" "$reason" "${4:-}"
	[ "$1" = failed ] && exit 1
	exit 0
}

MODE=${OMINULL_PARAM_MODE:-${mode:-audit}}
case "$MODE" in audit | enforce | revert) ;; *) MODE=audit ;; esac
ONLY=${OMINULL_PARAM_ONLY_IF_NEEDED:-true}
case "$ONLY" in true | false) ;; *) result failed '[]' "only_if_needed must be true or false" ;; esac
WARN=${OMINULL_PARAM_WARN_MINUTES:-10}
case "$WARN" in [1-9] | [1-5][0-9] | 60) ;; *) result failed '[]' "warn_minutes must be a whole number from 1 to 60" ;; esac
IDLE=${OMINULL_PARAM_IDLE_MINUTES:-15}
case "$IDLE" in [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | 1[0-3][0-9][0-9] | 14[0-3][0-9] | 1440) ;; *) result failed '[]' "idle_minutes must be a whole number from 1 to 1440" ;; esac
BUSY=${OMINULL_PARAM_WHEN_BUSY:-skip}
case "$BUSY" in skip | wait | run) ;; *) result failed '[]' "when_busy must be skip, wait or run" ;; esac
WINDOW=${OMINULL_PARAM_WINDOW:-}
HM='([01][0-9]|2[0-3]):[0-5][0-9]'
if [ -n "$WINDOW" ] && ! printf '%s' "$WINDOW" | grep -Eq "^$HM-$HM(,$HM-$HM){0,3}Z?\$"; then
	result failed '[]' "window must be 1-4 HH:MM-HH:MM ranges (comma separated, Z for UTC)"
fi

# Debian/Ubuntu leave /var/run/reboot-required; Fedora/RHEL answer needs-restarting -r (exit 1).
pending() {
	[ -e /var/run/reboot-required ] && return 0
	if command -v needs-restarting >/dev/null 2>&1; then
		needs-restarting -r >/dev/null 2>&1
		[ $? -eq 1 ] && return 0
	fi
	return 1
}

# Minutes since midnight of "HH:MM".
mins() {
	h=${1%%:*}; m=${1##*:}
	echo $((${h#0} * 60 + ${m#0}))
}
in_window() {
	[ -n "$WINDOW" ] || return 1
	w=$WINDOW
	case "$w" in
	*Z) w=${w%Z}; n=$(mins "$(date -u +%H:%M)") ;;
	*) n=$(mins "$(date +%H:%M)") ;;
	esac
	for r in $(printf '%s' "$w" | tr ',' ' '); do
		s=$(mins "${r%%-*}"); e=$(mins "${r##*-}")
		if [ "$s" -le "$e" ]; then
			[ "$n" -ge "$s" ] && [ "$n" -lt "$e" ] && return 0
		else
			{ [ "$n" -ge "$s" ] || [ "$n" -lt "$e" ]; } && return 0
		fi
	done
	return 1
}

# A local (not remote) user session that is active and not idle for IDLE minutes.
someone_here() {
	command -v loginctl >/dev/null 2>&1 || return 1
	now=$(date +%s)
	for id in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
		props=$(loginctl show-session "$id" -p Active -p Remote -p Class -p IdleHint -p IdleSinceHint 2>/dev/null)
		case "$props" in *Active=yes*) ;; *) continue ;; esac
		case "$props" in *Remote=yes*) continue ;; esac
		case "$props" in *Class=user*) ;; *) continue ;; esac
		case "$props" in *IdleHint=yes*)
			since=$(printf '%s\n' "$props" | sed -n 's/^IdleSinceHint=\([0-9]*\)$/\1/p')
			[ -n "$since" ] && [ $((now - since / 1000000)) -ge $((IDLE * 60)) ] && continue ;;
		esac
		return 0
	done
	return 1
}

on_battery() {
	for d in /sys/class/power_supply/*; do
		[ -r "$d/type" ] && [ "$(cat "$d/type")" = Battery ] && [ "$(cat "$d/status" 2>/dev/null)" = Discharging ] && return 0
	done
	return 1
}

preflight() { # prints the reason not to restart now, if any
	until=$(($(date +%s) + TIMEOUT / 2))
	while [ "$BUSY" != run ] && ! in_window && someone_here; do
		if [ "$BUSY" != wait ] || [ $(($(date +%s) + 60)) -gt "$until" ]; then echo "someone is using the computer"; return; fi
		sleep 60
	done
	on_battery && echo "running on battery"
}

PENDING=false
pending && PENDING=true
now=$(date +%s)
marker=""
if [ -r "$MARK" ]; then
	marker=$(sed -n '1{/^[0-9]*$/p}' "$MARK")
	if [ -z "$marker" ] || [ "$marker" -le "$now" ]; then rm -f "$MARK"; marker=""; fi
fi

case "$MODE" in
audit)
	if [ "$PENDING" = true ]; then result drift '[]' "the system is waiting for a restart"; fi
	result ok '[]'
	;;
revert)
	[ -n "$marker" ] || result ok '[]' "no restart from this package is waiting"
	rm -f "$MARK"
	shutdown -c >/dev/null 2>&1 || result failed '[]' "shutdown -c could not cancel the restart"
	result fixed '["cancelled the scheduled restart"]'
	;;
enforce)
	[ -n "$marker" ] && result ok '[]' "a restart is already scheduled" ",\"restart_in_seconds\":$((marker - now))"
	[ -e /run/systemd/shutdown/scheduled ] && result ok '[]' "a restart or shutdown is already scheduled"
	if [ "$ONLY" = true ] && [ "$PENDING" != true ]; then result ok '[]' "the system is not waiting for a restart"; fi
	why=$(preflight)
	[ -n "$why" ] && result skipped '[]' "$why"
	msg="OmniNull maintenance: this computer restarts in $WARN minutes to finish updates and upkeep. Save your work now."
	shutdown -r "+$WARN" "$msg" >/dev/null 2>&1 || result failed '[]' "shutdown -r could not schedule the restart"
	mkdir -p "$STATE_DIR" && printf '%s\n' $((now + WARN * 60)) >"$MARK"
	result fixed "[\"restart in $WARN min, warning sent to logged-in users\"]" "" ",\"restart_in_seconds\":$((WARN * 60))"
	;;
esac
