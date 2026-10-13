#!/bin/sh
# Ominull router telemetry poller.
#
# Runs on an OpenWrt gateway and posts three things the agents cannot see:
#
#   leases  - who holds which address, from dnsmasq. This is the only identity
#             an unagented device ever volunteers.
#   flows   - who is talking to whom, from conntrack. Not NetFlow: conntrack is
#             already there, needs no package, and carries byte counts in both
#             directions, which NetFlow v5 does not.
#   dns     - what names were asked for, when dnsmasq query logging is on. This
#             is what turns an alert reading "104.18.32.7" into one naming a
#             host. Off by default because it costs throughput.
#   clients - per-client cumulative byte counters, where the firmware keeps
#             them (GL.iNet "ubus call gl-clients list").
#
# It only ever reads. Nothing here changes gateway state, and the hub's reply is
# a count, never an instruction - a gateway that has been taken over must not be
# able to ask the hub what to do next.
#
# Install:
#   pipe this over SSH to /usr/bin/ominull-router-poll.sh, chmod +x,
#   write /etc/ominull-router.conf, then add to /etc/crontabs/root:
#     */5 * * * * /usr/bin/ominull-router-poll.sh >/dev/null 2>&1
#
# /etc/ominull-router.conf (chmod 600):
# The file is sourced by the shell, so every value is quoted - an unquoted
# label containing a space runs its second word as a command.
#   HUB_URL="https://192.0.2.58:9443"          # the agent TLS listener
#   TLS_CA="/etc/ominull-router/ca.crt"
#   TLS_CERT="/etc/ominull-router/router.crt"  # from POST /api/v1/router/identity
#   TLS_KEY="/etc/ominull-router/router.key"
#   HUB_KEY=""           # tenant key; only used without TLS_CERT
#   ROUTER_ID="gl-axt1800"
#   LABEL="living room"
#   DNS_LOG="0"
#   DNS_LOG_FILE="/tmp/dnsmasq.log"            # dnsmasq logfacility; empty reads logread
#   LAN_CIDR=""          # optional override, e.g. 192.0.2.0/24
#
# DNS from a log file is read by byte offset. The offset advances only after
# the hub answers 200, so a hub outage delays queries instead of losing them.
# Once everything is delivered and the file passes DNS_TRUNCATE_AT it is
# emptied; if the hub stays away until the file passes DNS_FILE_CAP, the
# backlog is dropped and logged, so tmpfs stays bounded.

# Conntrack emits compressed literals. This is a scope filter, not evidence
# that a destination belongs to this estate. The hub validates both families
# again, including expanded and IPv4-mapped forms from other poller versions.
is_local_destination() {
	case "$1" in
		10.*|192.168.*|127.*|169.254.*|0.*|255.*|22[4-9].*|23[0-9].*) return 0 ;;
		172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
		100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
		::|::1|[fF][cCdD][0-9a-fA-F][0-9a-fA-F]:*|[fF][eE][89aAbB][0-9a-fA-F]:*|[fF][fF][0-9a-fA-F][0-9a-fA-F]:*) return 0 ;;
	esac
	return 1
}

set -u

CONF=${OMINULL_ROUTER_CONF:-/etc/ominull-router.conf}
[ -r "$CONF" ] || { echo "ominull: $CONF is missing" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${HUB_URL:?HUB_URL not set}"
: "${HUB_KEY:=}"
: "${TLS_CA:=}"
: "${TLS_CERT:=}"
: "${TLS_KEY:=}"
[ -n "$HUB_KEY" ] || [ -n "$TLS_CERT" ] || { echo "ominull: set TLS_CERT or HUB_KEY" >&2; exit 1; }
: "${ROUTER_ID:=$(uci -q get system.@system[0].hostname || echo gateway)}"
: "${LABEL:=}"
: "${DNS_LOG:=0}"
: "${LEASEFILE:=/tmp/dhcp.leases}"
: "${MAX_FLOWS:=20000}"
: "${DHCP_CACHE:=/tmp/ominull-dhcp}"
: "${CONNTRACK:=/proc/net/nf_conntrack}"
: "${DNS_LOG_FILE:=}"
: "${DNS_STATE:=/tmp/ominull-router-dns.offset}"
: "${DNS_LINE_STATE:=/tmp/ominull-router-dns.last}"
: "${DNS_BATCH_BYTES:=1500000}"
: "${DNS_TRUNCATE_AT:=1048576}"
: "${DNS_FILE_CAP:=16777216}"
: "${GL_CLIENTS:=1}"
: "${WORK_BASE:=/tmp}"
: "${LOGGER:=logger}"

# The lease file is not authoritative about what is on this network. It keeps
# records from earlier configurations - a router that once served a different
# subnet leaves them behind, and dnsmasq has no reason to remove them. Sending
# those to the hub invents assets on a network that no longer exists, so leases
# are filtered to the gateway's own LAN before anything leaves the box.
ip2int() {
	IFS=. read -r _a _b _c _d <<EOF
$1
EOF
	[ -n "${_d:-}" ] || return 1
	echo $(( (_a << 24) + (_b << 16) + (_c << 8) + _d ))
}

LAN_SELF=$(uci -q get network.lan.ipaddr 2>/dev/null || echo '')
LAN_NET=''
LAN_MASKINT=''
if [ -n "${LAN_CIDR:-}" ]; then
	_base=${LAN_CIDR%%/*}
	_bits=${LAN_CIDR##*/}
	if [ "$_bits" -ge 0 ] 2>/dev/null && [ "$_bits" -le 32 ]; then
		LAN_MASKINT=$(( _bits == 0 ? 0 : (0xFFFFFFFF << (32 - _bits)) & 0xFFFFFFFF ))
		_b=$(ip2int "$_base") && LAN_NET=$(( _b & LAN_MASKINT ))
	fi
else
	_ip=$(uci -q get network.lan.ipaddr || echo '')
	_mask=$(uci -q get network.lan.netmask || echo 255.255.255.0)
	if [ -n "$_ip" ]; then
		_i=$(ip2int "$_ip") && _m=$(ip2int "$_mask") && {
			LAN_MASKINT=$_m
			LAN_NET=$(( _i & _m ))
		}
	fi
fi

# in_lan is deliberately fail-closed only when the subnet is known. If the
# gateway would not tell us what its LAN is, every lease is sent and the hub's
# own validation is the remaining guard - losing all lease visibility would be
# the worse failure.
in_lan() {
	[ -n "$LAN_NET" ] || return 0
	_v=$(ip2int "$1") || return 1
	[ $(( _v & LAN_MASKINT )) -eq "$LAN_NET" ]
}

WORK=$(mktemp -d "$WORK_BASE/ominull-poll.XXXXXX") || exit 1
trap 'rm -f "$WORK/leases.json" "$WORK/flows.json" "$WORK/dns.json" "$WORK/resolutions.json" "$WORK/body.json" "$WORK/reply.json" "$WORK/dns.chunk" "$WORK/clients.json" "$WORK/code" "$WORK/err"; rmdir "$WORK"' EXIT INT TERM

# json_escape keeps a device-chosen hostname from breaking the document. The
# hub bounds these again on arrival; doing it here too means a malformed name
# never even reaches the wire.
json_escape() {
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\x08/\\b/g' -e 's/\x0c/\\f/g' \
	    -e 's/\r/\\r/g' -e 's/\t/\\t/g' -e 's/[[:cntrl:]]//g'
}

# Read only a validated MAC filename, never source client-controlled content.
fingerprint_json() {
 _mac=$(printf '%s' "$1" | tr 'A-F' 'a-f')
 case "$_mac" in
  [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
  *) return ;;
 esac
 [ -f "$DHCP_CACHE/$_mac" ] || return 0
 # Three lines, bounded before shell parsing even if the cache is corrupted.
 _fingerprint=$(head -c 1400 "$DHCP_CACHE/$_mac")
 _observed=$(printf '%s\n' "$_fingerprint" | sed -n '1p')
 _vendor=$(printf '%s\n' "$_fingerprint" | sed -n '2p' | json_escape)
 _options=$(printf '%s\n' "$_fingerprint" | sed -n '3p')
 case "$_observed" in ????-??-??T??:??:??Z) ;; *) return ;; esac
 case "$_observed" in *[!0-9TZ:-]*) return ;; esac
 case "$_options" in *[!0-9,]*) return ;; esac
 printf ',"dhcp":{"observed_at":"%s","vendor_class":"%s","requested_options":"%s"}' "$_observed" "$_vendor" "$_options"
}

# ---- leases ----------------------------------------------------------------
# dnsmasq lease format: <expiry> <mac> <ip> <hostname> <client-id>
# "*" in the hostname column means the client offered no name.
{
	printf '['
	first=1
	if [ -r "$LEASEFILE" ]; then
		while read -r expiry mac ip host _rest; do
			[ -n "${ip:-}" ] || continue
			case "$host" in
				'*'|'-'|'') host='' ;;
			esac
			esc=$(printf '%s' "$host" | json_escape)
			[ $first -eq 1 ] || printf ','
			first=0
			printf '{"mac":"%s","ip":"%s","hostname":"%s","expires_at":"%s"' \
				"$mac" "$ip" "$esc" \
				"$(date -u -d "@$expiry" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 1970-01-01T00:00:00Z)"
			fingerprint_json "$mac"
			printf '}'
		done < "$LEASEFILE"
	fi
	printf ']'
} > "$WORK/leases.json"

# ---- flows -----------------------------------------------------------------
# conntrack reports each tracked conversation with cumulative counters in both
# directions. Only traffic that left the LAN is interesting here, so flows whose
# destination is itself a private address are dropped: the hub is trying to see
# what the estate talks to outside, and LAN chatter would bury it.
{
	printf '['
	first=1
	n=0
	if [ -r "$CONNTRACK" ]; then
		while read -r _f _v proto _pn _to rest; do
			case "$proto" in tcp|udp|icmp) ;; *) continue ;; esac

			src=''; dst=''; dport=''; ob=''; rb=''; op=''; rp=''
			for tok in $rest; do
				case "$tok" in
					src=*) [ -z "$src" ] && src=${tok#src=} ;;
					dst=*) [ -z "$dst" ] && dst=${tok#dst=} ;;
					dport=*) [ -z "$dport" ] && dport=${tok#dport=} ;;
					packets=*) if [ -z "$op" ]; then op=${tok#packets=}; else [ -z "$rp" ] && rp=${tok#packets=}; fi ;;
					bytes=*) if [ -z "$ob" ]; then ob=${tok#bytes=}; else [ -z "$rb" ] && rb=${tok#bytes=}; fi ;;
				esac
			done

			[ -n "$src" ] && [ -n "$dst" ] || continue
			[ -n "$dport" ] || dport=0

			is_local_destination "$dst" && continue

			[ $first -eq 1 ] || printf ','
			first=0
			printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"%s","orig_bytes":%s,"reply_bytes":%s,"orig_packets":%s,"reply_packets":%s}' \
				"$src" "$dst" "$dport" "$proto" "${ob:-0}" "${rb:-0}" "${op:-0}" "${rp:-0}"

			n=$((n + 1))
			[ "$n" -ge "$MAX_FLOWS" ] && break
		done < "$CONNTRACK"
	fi
	printf ']'
} > "$WORK/flows.json"

# ---- dns -------------------------------------------------------------------
# Only when the operator turned query logging on. One awk pass turns dnsmasq's
# "query[A] name from 192.0.2.5" and "reply name is 192.0.2.9" lines into the
# two arrays; anything else is skipped rather than guessed at. Lines carry
# their own time, so a backlog sent after an outage keeps when it happened.
TZ_OFFSET=$(date +%z | sed 's/^\([+-][0-9][0-9]\)\([0-9][0-9]\)$/\1:\2/')
NOW_YEAR=$(date +%Y)
NOW_MONTH=$(date +%m)
parse_dns() {
	awk -v self="$LAN_SELF" -v tz="$TZ_OFFSET" -v year="$NOW_YEAR" -v month="$NOW_MONTH" \
		-v dnsout="$WORK/dns.json" -v resout="$WORK/resolutions.json" '
	function esc(v) { gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v); gsub(/[[:cntrl:]]/, "", v); return v }
	function stamp(   mon, day, tm, yr, m, logread) {
		# logread: "Mon Oct 12 19:55:53 2026 ..."; log file: "Oct 12 19:55:53 ..."
		logread = ($5 ~ /^[0-9][0-9][0-9][0-9]$/)
		if (logread) { mon = $2; day = $3; tm = $4; yr = $5 }
		else { mon = $1; day = $2; tm = $3; yr = year }
		m = index("JanFebMarAprMayJunJulAugSepOctNovDec", mon)
		if (m == 0 || length(mon) != 3 || tm !~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ || day !~ /^[0-9]+$/) return ""
		m = (m + 2) / 3
		# A December line read in January belongs to last year.
		if (!logread && m > month + 0) yr = yr - 1
		return sprintf("%04d-%02d-%02dT%s%s", yr, m, day, tm, tz)
	}
	BEGIN { printf "[" > dnsout; printf "[" > resout; nd = 0; nr = 0 }
	{
		for (i = 1; i <= NF; i++) {
			if ($i ~ /^query\[[A-Z0-9]+\]$/ && $(i + 2) == "from" && i + 3 <= NF) {
				qtype = substr($i, 7, length($i) - 7); name = $(i + 1); client = $(i + 3)
				# A lookup made by the gateway itself arrives as 127.0.0.1.
				# Attribute it to the gateway, so a router phoning somewhere
				# unexpected is visible as the gateway doing it.
				if (client ~ /^127\./ && self != "") client = self
				if (name == "" || client !~ /^[0-9a-fA-F.:]+$/) break
				at = stamp()
				printf "%s{\"client_ip\":\"%s\",\"domain\":\"%s\",\"qtype\":\"%s\"%s}", (nd++ ? "," : ""), client, esc(name), qtype, (at != "" ? ",\"at\":\"" at "\"" : "") > dnsout
				break
			}
			# NXDOMAIN, NODATA and CNAME targets share this position, so only
			# values that look like an address are kept.
			if ($i == "reply" && $(i + 2) == "is" && i + 3 <= NF) {
				name = $(i + 1); addr = $(i + 3)
				if (addr ~ /^[0-9a-fA-F.:]+$/ && addr ~ /[0-9]/ && name != "")
					printf "%s{\"domain\":\"%s\",\"ip\":\"%s\"}", (nr++ ? "," : ""), esc(name), addr > resout
				break
			}
		}
	}
	END { printf "]" > dnsout; printf "]" > resout }'
}

printf '[]' > "$WORK/dns.json"
printf '[]' > "$WORK/resolutions.json"
DNS_COMMIT=''
if [ "$DNS_LOG" = "1" ] && [ -n "$DNS_LOG_FILE" ]; then
	if [ -f "$DNS_LOG_FILE" ]; then
		inode=$(ls -i "$DNS_LOG_FILE" | awk '{print $1}')
		size=$(wc -c < "$DNS_LOG_FILE")
		off=0
		if [ -r "$DNS_STATE" ]; then
			s_inode='' s_off=''
			read -r s_inode s_off < "$DNS_STATE" || true
			# A different inode or a shorter file means it was replaced or
			# truncated, so everything in it is new.
			if [ "$s_inode" = "$inode" ] && [ "${s_off:-x}" -le "$size" ] 2>/dev/null; then
				off=$s_off
			fi
		fi
		if [ "$size" -gt "$DNS_FILE_CAP" ]; then
			$LOGGER -t ominull-router "dns backlog over cap: dropped $((size - off)) unsent bytes"
			: > "$DNS_LOG_FILE"
			size=0
			off=0
		fi
		tail -c +$((off + 1)) "$DNS_LOG_FILE" 2>/dev/null | head -c "$DNS_BATCH_BYTES" > "$WORK/dns.chunk"
		# A line still being written is left for the next poll.
		if [ -s "$WORK/dns.chunk" ] && [ "$(tail -c 1 "$WORK/dns.chunk" | wc -l)" -eq 0 ]; then
			sed -i '$d' "$WORK/dns.chunk"
		fi
		consumed=$(wc -c < "$WORK/dns.chunk")
		parse_dns < "$WORK/dns.chunk"
		DNS_COMMIT="file $inode $((off + consumed))"
	fi
elif [ "$DNS_LOG" = "1" ]; then
	# Legacy: the shared syslog ring. The last line already sent is remembered,
	# and only what follows it is new. If that line is no longer in the buffer
	# the buffer rolled, and everything present is new.
	logread -e dnsmasq 2>/dev/null | grep -E 'query\[| reply ' > "$WORK/dns.chunk"
	if [ -s "$WORK/dns.chunk" ] && [ -r "$DNS_LINE_STATE" ]; then
		last=$(cat "$DNS_LINE_STATE" 2>/dev/null)
		if grep -qxF "$last" "$WORK/dns.chunk"; then
			awk -v l="$last" 'seen{print} $0==l{seen=1}' "$WORK/dns.chunk" > "$WORK/dns.json"
			mv "$WORK/dns.json" "$WORK/dns.chunk"
		fi
	fi
	tail -n 5000 "$WORK/dns.chunk" > "$WORK/dns.json" && mv "$WORK/dns.json" "$WORK/dns.chunk"
	[ -s "$WORK/dns.chunk" ] && DNS_COMMIT="line"
	parse_dns < "$WORK/dns.chunk"
fi

# ---- clients ---------------------------------------------------------------
# Forwarded as the firmware prints it; the hub parses and bounds it. Skipped
# when absent, oversized, or not valid JSON, so it can never spoil the poll.
printf 'null' > "$WORK/clients.json"
if [ "$GL_CLIENTS" = "1" ] && command -v ubus >/dev/null 2>&1; then
	if ubus call gl-clients list > "$WORK/clients.json" 2>/dev/null &&
		[ "$(wc -c < "$WORK/clients.json")" -le 524288 ] &&
		jsonfilter -i "$WORK/clients.json" -e '@.clients' >/dev/null 2>&1; then
		:
	else
		printf 'null' > "$WORK/clients.json"
	fi
fi

# ---- post ------------------------------------------------------------------
{
	printf '{"router_id":"%s","label":"%s","leases":' \
		"$(printf '%s' "$ROUTER_ID" | json_escape)" \
		"$(printf '%s' "$LABEL" | json_escape)"
	cat "$WORK/leases.json"
	printf ',"flows":'
	cat "$WORK/flows.json"
	printf ',"dns":'
	cat "$WORK/dns.json"
	printf ',"resolutions":'
	cat "$WORK/resolutions.json"
	printf ',"gl_clients":'
	cat "$WORK/clients.json"
	printf '}'
} > "$WORK/body.json"

# The key goes down a file descriptor, never onto a command line, because
# /proc/<pid>/cmdline is world readable. With a router certificate there is no
# key at all: the certificate is the credential.
if [ -n "$TLS_CERT" ]; then
	exec 3</dev/null
else
	exec 3<<KEY
header = "X-API-Key: $HUB_KEY"
KEY
fi
set --
[ -n "$TLS_CA" ] && set -- "$@" --cacert "$TLS_CA"
[ -n "$TLS_CERT" ] && set -- "$@" --cert "$TLS_CERT" --key "$TLS_KEY"

curl -sS --max-time 60 -o "$WORK/reply.json" -w '%{http_code}' \
	-K /dev/fd/3 "$@" \
	-H 'Content-Type: application/json' \
	--data-binary @"$WORK/body.json" \
	"$HUB_URL/api/v1/router/telemetry" > "$WORK/code" 2>"$WORK/err"
rc=$?
exec 3<&-

code=$(cat "$WORK/code" 2>/dev/null)
if [ "$rc" -ne 0 ] || [ "$code" != "200" ]; then
	$LOGGER -t ominull-router "poll failed: rc=$rc http=$code $(head -c 200 "$WORK/err" 2>/dev/null)"
	exit 1
fi

# Only now is what was sent known to have arrived, so only now does the DNS
# position move. A failed post leaves it where it was and the next poll resends.
case "$DNS_COMMIT" in
	file\ *)
		set -- $DNS_COMMIT
		inode=$2
		next=$3
		size=$(wc -c < "$DNS_LOG_FILE" 2>/dev/null || echo 0)
		# Empty the file once everything in it has been delivered. dnsmasq
		# appends, so its next line lands at the new start.
		if [ "$next" -ge "$DNS_TRUNCATE_AT" ] && [ "$next" -eq "$size" ]; then
			: > "$DNS_LOG_FILE"
			next=0
		fi
		printf '%s %s\n' "$inode" "$next" > "$DNS_STATE"
		;;
	line)
		tail -n 1 "$WORK/dns.chunk" > "$DNS_LINE_STATE"
		;;
esac

$LOGGER -t ominull-router "poll ok: $(head -c 200 "$WORK/reply.json")"
exit 0
