#!/bin/sh
# OpenWrt UCI dhcpscript hook. The stock wrapper sources this file before its
# normal hotplug handlers. Stay in a subshell so neither exit nor variables
# change that wrapper. Do not replace /usr/lib/dnsmasq/dhcp-script.sh.
(
	umask 077
	cache=${OMINULL_DHCP_CACHE:-/tmp/ominull-dhcp}
	mac=$(printf '%s' "${2:-}" | tr 'A-F' 'a-f')
	case "$mac" in
		[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
		*) exit 0 ;;
	esac
	case "${1:-}" in
		del) [ ! -d "$cache" ] || rm -f "$cache/$mac"; exit 0 ;;
		add|old) ;;
		*) exit 0 ;;
	esac
	# This format is DHCPv4 only. IPv6 uses DUIDs and different option numbers.
	case "${3:-}" in *:*) exit 0 ;; esac
	vendor=${DNSMASQ_VENDOR_CLASS:-}
	options=${DNSMASQ_REQUESTED_OPTIONS:-}
	# dnsmasq replays leases without the original options on startup/HUP.
	[ -n "$vendor$options" ] || exit 0
	[ ${#vendor} -le 255 ] || vendor=''
	[ ${#options} -le 1019 ] || options=''
	case "$options" in *[!0-9,]*) options='' ;; esac
	[ -n "$vendor$options" ] || exit 0
	mkdir -p "$cache" || exit 1
	# DHCP clients control MACs. Bound files even when identities keep changing.
	if [ ! -f "$cache/$mac" ]; then
		set -- "$cache"/*
		[ "$#" -lt 2000 ] || exit 0
	fi
	tmp=$(mktemp "$cache/.capture.XXXXXX") || exit 1
	trap 'rm -f "$tmp"' EXIT HUP INT TERM
	{
		date -u +%Y-%m-%dT%H:%M:%SZ
		printf '%s' "$vendor" | tr -d '[:cntrl:]'
		printf '\n%s\n' "$options"
	} > "$tmp" && mv "$tmp" "$cache/$mac"
)
