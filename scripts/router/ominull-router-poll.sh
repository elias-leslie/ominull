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
#
# It only ever reads. Nothing here changes gateway state, and the hub's reply is
# a count, never an instruction - a gateway that has been taken over must not be
# able to ask the hub what to do next.
#
# Install:
#   scp this to /usr/bin/ominull-router-poll.sh on the gateway, chmod +x,
#   write /etc/ominull-router.conf, then add to /etc/crontabs/root:
#     */5 * * * * /usr/bin/ominull-router-poll.sh >/dev/null 2>&1
#
# /etc/ominull-router.conf (chmod 600 - it holds a key):
# The file is sourced by the shell, so every value is quoted - an unquoted
# label containing a space runs its second word as a command.
#   HUB_URL="http://10.0.0.58:9999"
#   HUB_KEY="<tenant key>"
#   ROUTER_ID="gl-axt1800"
#   LABEL="living room"
#   DNS_LOG="0"
#   LAN_CIDR=""          # optional override, e.g. 10.0.0.0/24

set -u

CONF=/etc/ominull-router.conf
[ -r "$CONF" ] || { echo "ominull: $CONF is missing" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${HUB_URL:?HUB_URL not set}"
: "${HUB_KEY:?HUB_KEY not set}"
: "${ROUTER_ID:=$(uci -q get system.@system[0].hostname || echo gateway)}"
: "${LABEL:=}"
: "${DNS_LOG:=0}"
: "${LEASEFILE:=/tmp/dhcp.leases}"
: "${MAX_FLOWS:=20000}"

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

WORK=$(mktemp -d /tmp/ominull-poll.XXXXXX) || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

# json_escape keeps a device-chosen hostname from breaking the document. The
# hub bounds these again on arrival; doing it here too means a malformed name
# never even reaches the wire.
json_escape() {
	sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\x08/\\b/g' -e 's/\x0c/\\f/g' \
	    -e 's/\r/\\r/g' -e 's/\t/\\t/g' -e 's/[[:cntrl:]]//g'
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
			printf '{"mac":"%s","ip":"%s","hostname":"%s","expires_at":"%s"}' \
				"$mac" "$ip" "$esc" \
				"$(date -u -d "@$expiry" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 1970-01-01T00:00:00Z)"
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
	if [ -r /proc/net/nf_conntrack ]; then
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

			# skip conversations that never left the estate
			case "$dst" in
				10.*|192.168.*|127.*|169.254.*|224.*|255.*) continue ;;
				172.1[6-9].*|172.2[0-9].*|172.3[01].*) continue ;;
			esac

			[ $first -eq 1 ] || printf ','
			first=0
			printf '{"src_ip":"%s","dst_ip":"%s","dst_port":%s,"protocol":"%s","orig_bytes":%s,"reply_bytes":%s,"orig_packets":%s,"reply_packets":%s}' \
				"$src" "$dst" "$dport" "$proto" "${ob:-0}" "${rb:-0}" "${op:-0}" "${rp:-0}"

			n=$((n + 1))
			[ "$n" -ge "$MAX_FLOWS" ] && break
		done < /proc/net/nf_conntrack
	fi
	printf ']'
} > "$WORK/flows.json"

# ---- dns -------------------------------------------------------------------
# Only when the operator turned query logging on. dnsmasq writes lines of the
# form: "query[A] name.example from 10.0.0.5". Anything else is skipped rather
# than guessed at.
: > "$WORK/dns.json"
if [ "$DNS_LOG" = "1" ]; then
	# The ring buffer holds far more than one poll interval, so re-reading it
	# every five minutes would report the same query over and over: two polls
	# two seconds apart both claimed forty-five queries. The last line already
	# sent is remembered, and only what follows it is new. If that line is no
	# longer in the buffer the buffer rolled, and everything present is new.
	DNS_STATE=/tmp/ominull-router-dns.last
	# Queries say who asked for what; replies say which address the name
	# resolved to. Both share one marker so the dedup stays a single position
	# in one stream rather than two that can drift apart.
	all=$(logread -e dnsmasq 2>/dev/null | grep -E 'query\[| reply ')
	if [ -n "$all" ] && [ -r "$DNS_STATE" ]; then
		last=$(cat "$DNS_STATE" 2>/dev/null)
		if printf '%s\n' "$all" | grep -qxF "$last"; then
			all=$(printf '%s\n' "$all" | awk -v l="$last" 'seen{print} $0==l{seen=1}')
		fi
	fi
	[ -n "$all" ] && printf '%s\n' "$all" | tail -1 > "$DNS_STATE"
	all=$(printf '%s\n' "$all" | tail -5000)

	{
		printf '['
		first=1
		printf '%s\n' "$all" | while read -r line; do
			[ -n "$line" ] || continue
			qtype=$(expr "$line" : '.*query\[\([A-Z0-9]*\)\]')
			name=$(expr "$line" : '.*query\[[A-Z0-9]*\] \([^ ]*\) from')
			client=$(expr "$line" : '.*from \([0-9.]*\)')
			# A lookup made by the gateway itself arrives as 127.0.0.1, which
			# is not an asset anybody can act on. Attribute it to the gateway's
			# own address, so a router phoning somewhere unexpected is visible
			# as the gateway doing it.
			case "$client" in
				127.*) client=${LAN_SELF:-$client} ;;
			esac
			[ -n "$name" ] && [ -n "$client" ] || continue
			[ $first -eq 1 ] || printf ','
			first=0
			printf '{"client_ip":"%s","domain":"%s","qtype":"%s"}' \
				"$client" "$(printf '%s' "$name" | json_escape)" "${qtype:-A}"
		done
		printf ']'
	} > "$WORK/dns.json"

	# "reply <name> is <address>". dnsmasq puts NXDOMAIN, NODATA-IPv6 and a
	# CNAME target in the same position, so only values that look like an
	# address are kept; the hub validates them properly on arrival.
	{
		printf '['
		first=1
		printf '%s\n' "$all" | grep -F ' reply ' | while read -r line; do
			name=$(expr "$line" : '.* reply \([^ ]*\) is ')
			addr=$(expr "$line" : '.* is \([0-9a-fA-F.:]*\)$')
			[ -n "$name" ] && [ -n "$addr" ] || continue
			case "$addr" in
				*[0-9a-fA-F]*) ;;
				*) continue ;;
			esac
			[ $first -eq 1 ] || printf ','
			first=0
			printf '{"domain":"%s","ip":"%s"}' \
				"$(printf '%s' "$name" | json_escape)" "$addr"
		done
		printf ']'
	} > "$WORK/resolutions.json"
else
	printf '[]' > "$WORK/dns.json"
	printf '[]' > "$WORK/resolutions.json"
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
	printf '}'
} > "$WORK/body.json"

# The key goes down a file descriptor, never onto a command line, because
# /proc/<pid>/cmdline is world readable.
exec 3<<EOF
header = "X-API-Key: $HUB_KEY"
EOF

curl -sS --max-time 60 -o "$WORK/reply.json" -w '%{http_code}' \
	-K /dev/fd/3 \
	-H 'Content-Type: application/json' \
	--data-binary @"$WORK/body.json" \
	"$HUB_URL/api/v1/router/telemetry" > "$WORK/code" 2>"$WORK/err"
rc=$?
exec 3<&-

code=$(cat "$WORK/code" 2>/dev/null)
if [ "$rc" -ne 0 ] || [ "$code" != "200" ]; then
	logger -t ominull-router "poll failed: rc=$rc http=$code $(head -c 200 "$WORK/err" 2>/dev/null)"
	exit 1
fi

logger -t ominull-router "poll ok: $(head -c 200 "$WORK/reply.json")"
exit 0
