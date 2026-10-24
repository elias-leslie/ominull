# ominull-package: {"name":"linux-cleanup","title":"Cleanup (journal, apt, snap)","description":"Keeps the system journal under a size cap, empties the apt package cache once it grows and removes old disabled Snap revisions. Nothing in anyone's folders is touched.","category":"maintenance","risk":"safe","reboot":false,"timeout":900,"interval":"daily","params":[{"name":"journal_max_mb","type":"int","default":2048,"min":100,"max":102400,"description":"Size the system journal is trimmed to (oldest entries go first)"},{"name":"apt_cache_max_mb","type":"int","default":100,"min":0,"max":10240,"description":"Empty the apt package cache when its downloaded packages exceed this many MB"},{"name":"snap_revisions","type":"bool","default":true,"description":"Remove old Snap revisions that are already disabled"}],"platform":"linux"}
# Runs as root under /bin/sh with a cleared environment. Stdout: one JSON result line.
# Audit reports the journal size, the apt cache size and the disabled Snap revisions; drift when one is over
# its limit (the journal gets a 10% allowance, since the files being written sit outside the trim).
# Enforce trims the journal (journalctl --vacuum-size), runs apt-get clean and removes the disabled Snap
# revisions, at low CPU and disk priority. Deleted journal entries and caches do not come back.
# revert: nothing to put back (na).
set -u
set -f
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
JOURNAL_DIR=/var/log/journal
APT_DIR=/var/cache/apt/archives

jesc() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

result() { # state changed-json [reason] [extra json fields, each starting with a comma]
	reason=""
	[ -n "${3:-}" ] && reason=",\"reason\":\"$(jesc "$3")\""
	printf '{"v":1,"state":"%s","reboot":false,"changed":%s,"detail":{"mode":"%s"%s%s}}\n' "$1" "$2" "$MODE" "$reason" "${4:-}"
	[ "$1" = failed ] && exit 1
	exit 0
}

MODE=${OMINULL_PARAM_MODE:-${mode:-audit}}
case "$MODE" in audit | enforce | revert) ;; *) MODE=audit ;; esac
JMAX=${OMINULL_PARAM_JOURNAL_MAX_MB:-2048}
case "$JMAX" in 0* | *[!0-9]* | "") result failed '[]' "journal_max_mb must be a whole number from 100 to 102400" ;; esac
{ [ "${#JMAX}" -le 6 ] && [ "$JMAX" -ge 100 ] && [ "$JMAX" -le 102400 ]; } || result failed '[]' "journal_max_mb must be a whole number from 100 to 102400"
AMAX=${OMINULL_PARAM_APT_CACHE_MAX_MB:-100}
case "$AMAX" in *[!0-9]* | "") result failed '[]' "apt_cache_max_mb must be a whole number from 0 to 10240" ;; esac
{ [ "${#AMAX}" -le 5 ] && [ "$AMAX" -le 10240 ]; } || result failed '[]' "apt_cache_max_mb must be a whole number from 0 to 10240"
SNAPS=${OMINULL_PARAM_SNAP_REVISIONS:-true}
case "$SNAPS" in true | false) ;; *) result failed '[]' "snap_revisions must be true or false" ;; esac

[ "$MODE" = revert ] && result na '[]' "deleted cache and journal entries cannot be put back"

# Wrap a command so it yields CPU and disk to everything else.
low() { if command -v ionice >/dev/null 2>&1; then ionice -c 3 nice -n 15 "$@"; else nice -n 15 "$@"; fi; }

mb() { echo $(($1 / 1048576)); }
journal_bytes() { [ -d "$JOURNAL_DIR" ] && du -sb "$JOURNAL_DIR" 2>/dev/null | awk '{print $1}' || echo 0; }
apt_bytes() { find "$APT_DIR" -maxdepth 1 -name '*.deb' -type f -printf '%s\n' 2>/dev/null | awk '{s += $1} END {print s + 0}'; }
# "name rev" per disabled Snap revision (names and revisions only in their plain forms).
snap_disabled() {
	command -v snap >/dev/null 2>&1 || return 0
	snap list --all 2>/dev/null | awk 'NR > 1 && $NF ~ /(^|,)disabled(,|$)/ && $1 ~ /^[a-z0-9][a-z0-9-]*$/ && $3 ~ /^[0-9]+$/ {print $1, $3}'
}

jb=$(journal_bytes)
ab=$(apt_bytes)
sn=""
[ "$SNAPS" = true ] && sn=$(snap_disabled)
sn_count=0
[ -n "$sn" ] && sn_count=$(printf '%s\n' "$sn" | wc -l)
j_over=0
[ "$jb" -gt $((JMAX * 1048576 * 11 / 10)) ] && j_over=1
a_over=0
[ "$ab" -gt $((AMAX * 1048576)) ] && a_over=1
state=",\"journal_mb\":$(mb "$jb"),\"apt_cache_mb\":$(mb "$ab"),\"snap_disabled_revisions\":$sn_count"

if [ "$MODE" = audit ]; then
	why=""
	[ $j_over = 1 ] && why="$why the journal is over its cap;"
	[ $a_over = 1 ] && why="$why the apt cache is over its limit;"
	[ "$sn_count" -gt 0 ] && why="$why $sn_count old Snap revision(s) are still installed;"
	[ -n "$why" ] && result drift '[]' "$(printf '%s' "$why" | sed 's/^ //; s/;$//')" "$state"
	result ok '[]' "" "$state"
fi

changed=""
add() { [ -n "$changed" ] && changed="$changed,"; changed="$changed\"$(jesc "$1")\""; }
errs=""
if [ $j_over = 1 ]; then
	if command -v journalctl >/dev/null 2>&1; then
		if low journalctl --vacuum-size="${JMAX}M" >/dev/null 2>&1; then
			after=$(journal_bytes)
			add "journal trimmed from $(mb "$jb") MB to $(mb "$after") MB"
		else
			errs="$errs journalctl could not trim the journal;"
		fi
	fi
fi
if [ $a_over = 1 ]; then
	if low apt-get clean >/dev/null 2>&1; then
		add "apt cache emptied ($(mb "$ab") MB)"
	else
		errs="$errs apt-get clean failed (apt may be busy);"
	fi
fi
if [ "$sn_count" -gt 0 ]; then
	gone=""
	while read -r name rev; do
		[ -n "$name" ] || continue
		if low snap remove "$name" "--revision=$rev" >/dev/null 2>&1; then gone="$gone $name r$rev,"; else errs="$errs snap could not remove $name r$rev;"; fi
	done <<EOF
$sn
EOF
	[ -n "$gone" ] && add "removed old Snap revisions:$(printf '%s' "$gone" | sed 's/,$//')"
fi

after_state=",\"journal_mb\":$(mb "$(journal_bytes)"),\"apt_cache_mb\":$(mb "$(apt_bytes)")"
[ -n "$errs" ] && result failed "[$changed]" "$(printf '%s' "$errs" | sed 's/^ //; s/;$//')" "$after_state"
[ -n "$changed" ] && result fixed "[$changed]" "" "$after_state"
result ok '[]' "" "$state"
