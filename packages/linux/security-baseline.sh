# ominull-package: {"name":"linux-security-baseline","title":"Security baseline","description":"Checks SSH, accounts, how long the system journal reaches back and whether recent read-only backups exist on this machine, without changing anything. The posture packs read these results.","category":"security","risk":"safe","reboot":false,"timeout":120,"interval":"daily","platform":"linux","params":[{"name":"journal_min_days","type":"int","default":30,"min":1,"max":3650,"description":"The system journal should reach back at least this many days"},{"name":"backup_max_age_days","type":"int","default":7,"min":1,"max":365,"description":"The newest read-only snapshot should be younger than this many days"}]}
# Runs as root under /bin/sh with a cleared environment. Stdout: one JSON result line.
# Read-only: enforce and revert answer na. One control per check: pass, fail, or na (does not apply here);
# a check that could not read its answer fails and says so. Drift when any control fails.
set -u
set -f
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

jesc() { printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g'; }

result() { # state [reason]
	reason=""
	[ -n "${2:-}" ] && reason=",\"reason\":\"$(jesc "$2")\""
	printf '{"v":1,"state":"%s","reboot":false,"changed":[],"detail":{"mode":"%s"%s,"controls":[%s]}}\n' "$1" "$MODE" "$reason" "$CONTROLS"
	[ "$1" = failed ] && exit 1
	exit 0
}

CONTROLS=""
DRIFT=0
control() { # id expected actual state
	CONTROLS="$CONTROLS${CONTROLS:+,}{\"id\":\"$1\",\"expected\":\"$(jesc "$2")\",\"actual\":\"$(jesc "$3")\",\"state\":\"$4\"}"
	if [ "$4" = fail ]; then DRIFT=1; fi
}

whole() { # name value min max: fails the run on a bad parameter
	case "$2" in 0* | *[!0-9]* | "") result failed "$1 must be a whole number from $3 to $4" ;; esac
	{ [ "${#2}" -le 6 ] && [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; } || result failed "$1 must be a whole number from $3 to $4"
}

MODE=${OMINULL_PARAM_MODE:-${mode:-audit}}
case "$MODE" in audit | enforce | revert) ;; *) MODE=audit ;; esac
JOURNAL_MIN=${OMINULL_PARAM_JOURNAL_MIN_DAYS:-30}
whole journal_min_days "$JOURNAL_MIN" 1 3650
BACKUP_MAX=${OMINULL_PARAM_BACKUP_MAX_AGE_DAYS:-7}
whole backup_max_age_days "$BACKUP_MAX" 1 365
[ "$MODE" = audit ] || result na "this package only checks"

NOW=$(date +%s)

# A private, link-local or loopback address (RFC 1918, RFC 6598, RFC 4193); anything else is public.
private_addr() {
	case "$1" in
	127.* | 10.* | 192.168.* | 169.254.* | ::1 | [Ff][CcDd]* | [Ff][Ee]80*) return 0 ;;
	172.1[6-9].* | 172.2[0-9].* | 172.3[01].*) return 0 ;;
	100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7].*) return 0 ;;
	esac
	return 1
}

check_ssh() {
	expected_v="OpenSSH 7.6 or newer, which has no SSH version 1"
	expected_p="password and keyboard-interactive login off"
	expected_n="SSH listens only on private addresses"
	sshd_bin=$(command -v sshd || true)
	if [ -z "$sshd_bin" ]; then
		control ssh.protocol_1_off "$expected_v" "no SSH server installed" na
		control ssh.password_auth_off "$expected_p" "no SSH server installed" na
		control ssh.trusted_networks "$expected_n" "no SSH server installed" na
		return
	fi

	ver=$("$sshd_bin" -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | head -n 1)
	if [ -z "$ver" ]; then
		control ssh.protocol_1_off "$expected_v" "check failed: no version from sshd" fail
	else
		maj=${ver% *}
		min=${ver#* }
		if [ "$maj" -gt 7 ] || { [ "$maj" -eq 7 ] && [ "$min" -ge 6 ]; }; then st=pass; else st=fail; fi
		control ssh.protocol_1_off "$expected_v" "OpenSSH $maj.$min" "$st"
	fi

	cfg=$("$sshd_bin" -T 2>/dev/null) || cfg=""
	if [ -z "$cfg" ]; then
		control ssh.password_auth_off "$expected_p" "check failed: sshd -T gave no settings" fail
		control ssh.trusted_networks "$expected_n" "check failed: sshd -T gave no settings" fail
		return
	fi
	pw=$(printf '%s\n' "$cfg" | awk '$1 == "passwordauthentication" { print $2; exit }')
	kbd=$(printf '%s\n' "$cfg" | awk '$1 == "kbdinteractiveauthentication" || $1 == "challengeresponseauthentication" { print $2; exit }')
	if [ "$pw" = no ] && [ "$kbd" = no ]; then st=pass; else st=fail; fi
	# sshd -T shows the settings outside any Match block; a Match block can turn password login back on.
	matched=$(find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -maxdepth 1 -type f 2>/dev/null | xargs -r awk '
		tolower($1) == "match" { inside = 1; next }
		inside && (tolower($1) == "passwordauthentication" || tolower($1) == "kbdinteractiveauthentication" || tolower($1) == "challengeresponseauthentication") && tolower($2) == "yes" { n++ }
		END { print n + 0 }' 2>/dev/null)
	actual_p="password ${pw:-unknown}, keyboard-interactive ${kbd:-unknown}"
	case "$matched" in
	0) ;;
	*)
		actual_p="$actual_p, but a Match block in the SSH config turns it back on"
		st=fail
		;;
	esac
	control ssh.password_auth_off "$expected_p" "$actual_p" "$st"

	ports=$(printf '%s\n' "$cfg" | awk '$1 == "port" { print $2 }')
	listening=$(ss -H -tln 2>/dev/null) || {
		control ssh.trusted_networks "$expected_n" "check failed: ss did not answer" fail
		return
	}
	seen=0
	wild=0
	public=""
	for local_addr in $(printf '%s\n' "$listening" | awk '{ print $4 }'); do
		port=${local_addr##*:}
		addr=${local_addr%:*}
		addr=${addr#[}
		addr=${addr%]}
		addr=${addr%%\%*}
		case " $(printf '%s ' $ports)" in *" $port "*) ;; *) continue ;; esac
		seen=1
		case "$addr" in
		'*' | 0.0.0.0 | ::) wild=1 ;;
		*) private_addr "$addr" || public="$public $addr" ;;
		esac
	done
	if [ "$seen" -eq 0 ]; then
		control ssh.trusted_networks "$expected_n" "SSH is installed but not listening" na
		return
	fi
	if [ "$wild" -eq 1 ]; then
		addrs=$(ip -o addr show scope global 2>/dev/null) || {
			control ssh.trusted_networks "$expected_n" "check failed: ip did not list this machine's addresses" fail
			return
		}
		for a in $(printf '%s\n' "$addrs" | awk '{ sub(/\/.*/, "", $4); print $4 }'); do
			private_addr "$a" || public="$public $a"
		done
	fi
	if [ -n "$public" ]; then
		control ssh.trusted_networks "$expected_n" "reachable on public address:$public" fail
	else
		control ssh.trusted_networks "$expected_n" "only private addresses" pass
	fi
}

check_accounts() {
	expected="only root has user id 0; no account has an empty password"
	if [ ! -r /etc/passwd ] || [ ! -r /etc/shadow ]; then
		control accounts.least_privilege "$expected" "check failed: account files not readable" fail
		return
	fi
	extra=$(awk -F: '$3 == 0 && $1 != "root" { printf "%s ", $1 }' /etc/passwd)
	empty=$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow)
	if [ -z "$extra" ] && [ -z "$empty" ]; then
		control accounts.least_privilege "$expected" "only root; no empty passwords" pass
	else
		control accounts.least_privilege "$expected" "user id 0: ${extra:-root only}; empty password: ${empty:-none}" fail
	fi
}

check_journal() {
	expected="journal kept on disk, reaching back $JOURNAL_MIN days"
	if ! command -v journalctl >/dev/null 2>&1; then
		control logs.journal_retention "$expected" "this machine has no system journal" na
		return
	fi
	if [ -z "$(ls -A /var/log/journal 2>/dev/null)" ]; then
		control logs.journal_retention "$expected" "journal kept in memory only, lost at restart" fail
		return
	fi
	first=$(journalctl -q --no-pager -o short-unix 2>/dev/null | head -n 1)
	first=${first%%.*}
	case "$first" in
	"" | *[!0-9]*)
		control logs.journal_retention "$expected" "check failed: no journal entries read" fail
		return
		;;
	esac
	days=$(((NOW - first) / 86400))
	if [ "$days" -ge "$JOURNAL_MIN" ]; then st=pass; else st=fail; fi
	control logs.journal_retention "$expected" "reaches back $days days" "$st"
}

check_backups() {
	expected="a read-only snapshot under $BACKUP_MAX days old"
	virt=$(systemd-detect-virt 2>/dev/null || true)
	case "$virt" in
	"" | none) ;;
	*)
		control backups.read_only_recent "$expected" "a guest ($virt): its host holds its backups, out of sight from here" na
		return
		;;
	esac
	newest=0
	found=0
	for mnt in $(findmnt -n -t btrfs -o TARGET 2>/dev/null); do
		found=1
		stamp=$(btrfs subvolume list -r -s "$mnt" 2>/dev/null | sed -n 's/.* otime \([0-9-]* [0-9:]*\) .*/\1/p' | sort | tail -n 1)
		[ -n "$stamp" ] || continue
		sec=$(date -d "$stamp" +%s 2>/dev/null) || continue
		[ "$sec" -gt "$newest" ] && newest=$sec
	done
	if command -v zfs >/dev/null 2>&1; then
		sec=$(zfs list -Hp -t snapshot -o creation -s creation 2>/dev/null | tail -n 1)
		case "$sec" in
		"" | *[!0-9]*) ;;
		*)
			found=1
			[ "$sec" -gt "$newest" ] && newest=$sec
			;;
		esac
	fi
	if [ "$newest" -eq 0 ]; then
		if [ "$found" -eq 1 ]; then
			control backups.read_only_recent "$expected" "no read-only snapshots on this machine" fail
		else
			control backups.read_only_recent "$expected" "no btrfs or ZFS here, so no snapshots to read" fail
		fi
		return
	fi
	days=$(((NOW - newest) / 86400))
	if [ "$days" -lt "$BACKUP_MAX" ]; then st=pass; else st=fail; fi
	control backups.read_only_recent "$expected" "newest is $days days old" "$st"
}

check_ssh
check_accounts
check_journal
check_backups
if [ "$DRIFT" -eq 1 ]; then result drift; fi
result ok
