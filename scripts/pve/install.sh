#!/usr/bin/env bash
# Install or refresh OmniNull's forced-command keys on the Proxmox host (idempotent).
#
#   sudo scripts/pve/install.sh [--recipient age1...]
#   scripts/pve/install.sh ...      as the owner: same install
#       either way a changed authorized_keys is declared to host-steward (aico declare --host pve --what keys)
#
# Layout:  PVE host     /usr/local/sbin/ominull-backup-dispatch    (scripts/st_extension/pve_backup_dispatch.py)
#                       /usr/local/sbin/ominull-observe-dispatch   (scripts/st_extension/pve_observe_dispatch.py)
#                       /etc/ominull-backup/recipient              offline age recipient, public half only (--recipient)
#          workstation  <key dir>/{backup,observe}.ed25519 (no passphrase; each bound to one dispatcher, from the
#                       workstation address only), used through the aliases ominull-backup and ominull-observe
#
# The owner's PVE ssh alias runs the one install session. Only the committed dispatchers (git HEAD) are installed.
# The same session retires the old hub-install key: its authorized_keys lines (" ominull-hub-install" and
# " ominull-hub-install-extra"), /usr/local/sbin/ominull-hub-install, /etc/ominull-hub-install and
# /var/lib/ominull-hub-install. The hub now deploys through scripts/deploy-hub.sh.
# The backup dispatcher refuses every backup under its key until a recipient is installed: set backup_ssh_alias in
# scripts/st_extension/production.local.json only after this ran with --recipient.
set -euo pipefail
recipient=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --recipient) recipient="${2:?--recipient needs the age1... public key}"; shift 2 ;;
    *) echo "usage: install.sh [--recipient age1...]" >&2; exit 2 ;;
  esac
done
[ -z "$recipient" ] || [[ $recipient =~ ^age1[0-9a-z]{58}$ ]] || { echo "--recipient must be one age1... public key" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# Both come from the environment: no host name or address is kept in the repo.
PVE="${PVE_HOST:?set PVE_HOST to the ssh alias of the Proxmox host}"
FROM="${OMINULL_PVE_FROM:?set OMINULL_PVE_FROM to the workstation address every root key on PVE is pinned to}"
admin="${SUDO_USER:-$(id -un)}"
as_admin() { if [ "$(id -u)" = 0 ]; then sudo -u "$admin" -H "$@"; else "$@"; fi; }
# shellcheck disable=SC2016  # expanded by the admin shell
admin_home="$(as_admin sh -c 'printf %s "$HOME"')"
# shellcheck disable=SC2016  # expanded by the admin shell
KEYDIR="$(as_admin sh -c 'printf %s "${OMINULL_PVE_KEY_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/ominull/pve-keys}"')"
[[ $FROM =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "OMINULL_PVE_FROM must be one IPv4 address" >&2; exit 1; }
# One public ed25519 key with no options: anything else would add a key without restrict, from= and command=.
KEY_RE='^(ssh-ed25519 [A-Za-z0-9+/]{68})( [^[:cntrl:]]*)?$'
# Each role: its forced command on PVE and the committed file installed there.
ROLES=(backup observe)
declare -A COMMAND=([backup]=/usr/local/sbin/ominull-backup-dispatch [observe]=/usr/local/sbin/ominull-observe-dispatch)
declare -A SOURCE=([backup]=scripts/st_extension/pve_backup_dispatch.py [observe]=scripts/st_extension/pve_observe_dispatch.py)

work="$(mktemp -d)"; chmod 700 "$work"  # Root's own when run as root: nothing an agent can swap between show and install.
trap 'rm -rf "$work"' EXIT

sha256() { python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
for role in "${ROLES[@]}"; do
  if [ -n "$(as_admin git -C "$ROOT" status --porcelain -- "${SOURCE[$role]}")" ]; then
    echo "${SOURCE[$role]} has uncommitted changes; only committed dispatchers are installed" >&2; exit 1
  fi
done
head="$(as_admin git -C "$ROOT" rev-parse HEAD)"
for role in "${ROLES[@]}"; do
  as_admin git -C "$ROOT" show "$head:${SOURCE[$role]}" > "$work/$role"
  echo "Dispatcher ${COMMAND[$role]}: ${SOURCE[$role]} at $head, sha256 $(sha256 "$work/$role")"
done

as_admin install -d -m 0700 "$KEYDIR"
declare -A LINE
for role in "${ROLES[@]}"; do
  key="$KEYDIR/$role.ed25519"
  if [ ! -f "$key" ]; then
    as_admin rm -f "$key.new" "$key.new.pub"
    as_admin ssh-keygen -q -t ed25519 -N '' -C "ominull-$role" -f "$key.new"
    private="$key.new"
  else
    private="$key"
  fi
  # Derived from the private key, never read from the .pub file next to it.
  public="$(as_admin ssh-keygen -y -f "$private")"
  [[ $public =~ $KEY_RE ]] || { echo "$private does not hold exactly one ed25519 key; nothing installed" >&2; exit 1; }
  LINE[$role]="restrict,from=\"$FROM\",command=\"${COMMAND[$role]}\" ${BASH_REMATCH[1]} ominull-$role"
done
b64() { base64 -w0 < "$1"; }
# One session: ssh joins the remote arguments with spaces for the remote shell to re-split, so the files and key
# lines travel base64-encoded and the recipient carries a prefix (an empty argument would vanish and shift the rest).
as_admin ssh "$PVE" bash -s -- "$(b64 "$work/backup")" "$(b64 "$work/observe")" "r$recipient" \
  "$(printf '%s' "${LINE[backup]}" | base64 -w0)" "$(printf '%s' "${LINE[observe]}" | base64 -w0)" \
  > "$work/pve-install.out" <<'REMOTE'
set -euo pipefail
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
declare -A command=([backup]=/usr/local/sbin/ominull-backup-dispatch [observe]=/usr/local/sbin/ominull-observe-dispatch)
roles=(backup observe)
declare -A line=([backup]="$(printf '%s' "$4" | base64 -d)" [observe]="$(printf '%s' "$5" | base64 -d)")
for role in "${roles[@]}"; do
  re='^restrict,from="[0-9.]+",command="'"${command[$role]}"'" ssh-ed25519 [A-Za-z0-9+/]{68} ominull-'"$role"'$'
  [[ ${line[$role]} =~ $re ]] || { echo "refusing a malformed ominull-$role key line; nothing installed" >&2; exit 1; }
done
recipient="${3#r}"
if [ -n "$recipient" ]; then
  [[ $recipient =~ ^age1[0-9a-z]{58}$ ]] || { echo "refusing a malformed recipient; nothing installed" >&2; exit 1; }
  command -v age >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends age >/dev/null
  command -v age >/dev/null || { echo "age is not installed on $(hostname -s); nothing installed" >&2; exit 1; }
fi
i=1
for role in "${roles[@]}"; do
  printf '%s' "${!i}" | base64 -d > "$tmp"
  /usr/bin/python3 -I -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "$tmp"
  install -m 0755 -o root -g root "$tmp" "${command[$role]}"
  i=$((i + 1))
done
install -d -m 0755 -o root -g root /etc/ominull-backup
if [ -n "$recipient" ]; then
  printf '%s\n' "$recipient" > "$tmp"
  install -m 0644 -o root -g root "$tmp" /etc/ominull-backup/recipient
  echo "backup recipient installed"
elif [ ! -e /etc/ominull-backup/recipient ]; then
  echo "no backup recipient yet: the backup key refuses every backup until one is installed"
fi
# The AUTH lines name each auth file this session changed, so the change gets declared.
sig() {
  local f=$1 h t
  { [ -e "$f" ] || [ -L "$f" ]; } && [ ! -d "$f" ] || { echo MISSING; return; }
  h=$(sha256sum < "$f" 2>/dev/null | cut -c1-64); [ -n "$h" ] || h=UNREADABLE
  t=file; [ -L "$f" ] && t="symlink->$(readlink "$f")"; [ -L "$f" ] || [ -f "$f" ] || t=other
  printf '%s %s %s %s\n' "$h" "$(stat -c %u:%g "$f")" "$(stat -c %a "$f")" "$t"
}
auth_paths="/root/.ssh/authorized_keys /etc/pve/priv/authorized_keys"
declare -A before
for f in $auth_paths; do before[$f]=$(sig "$f"); done
ak=/root/.ssh/authorized_keys
retired_re=' ominull-hub-install(-extra)?$'
missing=0; stale=0
for role in "${roles[@]}"; do grep -qxF "${line[$role]}" "$ak" || missing=1; done
grep -Eq "$retired_re" "$ak" && stale=1
if [ "$missing" = 1 ] || [ "$stale" = 1 ]; then
  remove=(-e "$retired_re")
  # The backup and observe lines are replaced only when one is missing or different; otherwise they stay in place.
  if [ "$missing" = 1 ]; then remove+=(-e ' ominull-backup$' -e ' ominull-observe$'); fi
  grep -Ev "${remove[@]}" "$ak" > "$tmp" || true
  if [ "$missing" = 1 ]; then for role in "${roles[@]}"; do printf '%s\n' "${line[$role]}" >> "$tmp"; done; fi
  cat "$tmp" > "$ak"
fi
# The retired hub-install role: its dispatcher, pin and work directory (only these paths).
retired=()
[ "$stale" = 1 ] && retired+=("authorized_keys lines")
for path in /usr/local/sbin/ominull-hub-install /etc/ominull-hub-install /var/lib/ominull-hub-install; do
  if [ -e "$path" ] || [ -L "$path" ]; then rm -rf -- "$path"; retired+=("$path"); fi
done
if [ "${#retired[@]}" -gt 0 ]; then echo "retired the hub-install key: ${retired[*]}"; fi
for f in $auth_paths; do
  after=$(sig "$f")
  [ "$after" = "${before[$f]}" ] || printf 'AUTH\t%s\t%s\t%s\n' "$f" "${before[$f]}" "$after"
done
echo "NODE $(hostname -s)"
echo "ominull forced-command keys installed"
REMOTE
grep -v -e '^AUTH' -e '^NODE ' "$work/pve-install.out"
node="$(awk '$1 == "NODE" {print $2}' "$work/pve-install.out")"
for role in "${ROLES[@]}"; do
  key="$KEYDIR/$role.ed25519"
  if [ -f "$key.new" ]; then as_admin mv -f "$key.new.pub" "$key.pub"; as_admin mv -f "$key.new" "$key"; fi
done
if grep -q '^AUTH' "$work/pve-install.out"; then
  as_admin aico declare --host pve --what keys --hours 1 --reason "OmniNull forced-command keys installed or refreshed" ||
    echo "authorized_keys changed on PVE; declare it: aico declare --host pve --what keys --reason ..." >&2
fi

# Each key reaches only its dispatcher: a shell command is refused, one read-only verb answers.
host="$(as_admin ssh -G "$PVE" | awk '$1 == "hostname" {print $2}')"
check() {
  as_admin ssh -F /dev/null -i "$KEYDIR/$1.ed25519" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes \
    -o "UserKnownHostsFile=$admin_home/.ssh/known_hosts" "root@$host" "${@:2}" < /dev/null
}
answers() { if check "$@" > /dev/null; then echo "$1 key answers: $2"; else echo "the $1 key does not answer $2" >&2; exit 1; fi; }
answers backup guest 00000000000000000000000000000000 install-check "$node"
answers observe package
for role in "${ROLES[@]}"; do
  if check "$role" id 2>/dev/null; then
    echo "the $role key ran a shell command; remove its line from $PVE:/root/.ssh/authorized_keys" >&2; exit 1
  fi
done
echo "every key refuses other commands"
