# ominull-package: {"name":"linux-maintenance-mode","title":"Maintenance mode","description":"Keeps the computer awake while maintenance runs: sleep and idle actions are held off until the end time, then let go by themselves.","category":"maintenance","risk":"safe","reboot":false,"timeout":60,"interval":"daily","params":[{"name":"hours","type":"int","default":6,"min":1,"max":24,"description":"How long maintenance mode lasts before sleep is allowed again"}],"platform":"linux","role":"maintenance_mode"}
# Runs as root under /bin/sh with a cleared environment. Stdout: one JSON result line.
# enforce: a transient systemd unit holds a sleep:idle inhibitor lock and stops itself after
# the chosen hours (RuntimeMaxSec), so nothing has to put settings back and it cannot stick.
# Enforce again starts it afresh with the new end. revert: stop it now. audit: report.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
UNIT=ominull-maintenance-mode
STATE_DIR=/var/lib/ominull-maintenance
UNTIL_FILE="$STATE_DIR/maintenance-mode.until"

result() { # state on until changed-json [reason]
	reason=""
	[ -n "${5:-}" ] && reason=",\"reason\":\"$5\""
	if [ "$2" = true ]; then mm="{\"on\":true,\"until\":\"$3\"}"; else mm='{"on":false}'; fi
	printf '{"v":1,"state":"%s","reboot":false,"changed":%s,"detail":{"mode":"%s","maintenance_mode":%s%s}}\n' "$1" "$4" "$MODE" "$mm" "$reason"
	[ "$1" = failed ] && exit 1
	exit 0
}

MODE=${OMINULL_PARAM_MODE:-${mode:-audit}}
case "$MODE" in audit | enforce | revert) ;; *) MODE=audit ;; esac
HOURS=${OMINULL_PARAM_HOURS:-6}
case "$HOURS" in [1-9] | 1[0-9] | 2[0-4]) ;; *) result failed false "" '[]' "hours must be a whole number from 1 to 24" ;; esac

if ! command -v systemd-run >/dev/null 2>&1 || ! command -v systemd-inhibit >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
	result na false "" '[]' "this machine does not run systemd, so there is no sleep lock to hold"
fi

active() { systemctl is-active --quiet "$UNIT"; }
until_text() { [ -r "$UNTIL_FILE" ] && sed -n '1{/^[0-9TZ:-]*$/p}' "$UNTIL_FILE"; }

case "$MODE" in
audit)
	if active; then result ok true "$(until_text)" '[]'; else result ok false "" '[]'; fi
	;;
revert)
	if active; then
		systemctl stop "$UNIT" >/dev/null 2>&1 || result failed true "$(until_text)" '[]' "the sleep lock could not be stopped"
		rm -f "$UNTIL_FILE"
		result fixed false "" '["sleep allowed again"]'
	fi
	rm -f "$UNTIL_FILE"
	result ok false "" '[]'
	;;
enforce)
	was=""
	if active; then
		was=extended
		systemctl stop "$UNIT" >/dev/null 2>&1 || result failed true "$(until_text)" '[]' "the running sleep lock could not be replaced"
	fi
	systemctl reset-failed "$UNIT" >/dev/null 2>&1
	until=$(date -u -d "+$HOURS hours" +%Y-%m-%dT%H:%M:%SZ) || result failed false "" '[]' "the end time could not be worked out"
	if ! systemd-run --unit="$UNIT" --description="OmniNull maintenance mode until $until" --property=RuntimeMaxSec="${HOURS}h" --collect \
		systemd-inhibit --what=sleep:idle --who=OmniNull --why="Maintenance mode until $until" --mode=block sleep infinity >/dev/null 2>&1; then
		result failed false "" '[]' "systemd-run could not start the sleep lock"
	fi
	mkdir -p "$STATE_DIR" && printf '%s\n' "$until" >"$UNTIL_FILE"
	n=0
	while [ $n -lt 20 ] && ! active; do sleep 0.2; n=$((n + 1)); done
	active || result failed false "" '[]' "the sleep lock stopped right after starting"
	if [ -n "$was" ]; then result fixed true "$until" "[\"extended to $until\"]"; fi
	result fixed true "$until" "[\"sleep and idle actions held off until $until\"]"
	;;
esac
