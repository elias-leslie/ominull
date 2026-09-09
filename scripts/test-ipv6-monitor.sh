#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT_DIR/build"
(cd "$ROOT_DIR/hub" && go test -c ./pkg/ipv6guard -o "$ROOT_DIR/build/test-ipv6-monitor")
(cd "$ROOT_DIR/hub" && go test -c ./pkg/scanner -o "$ROOT_DIR/build/test-ipv6-discovery")
sudo -n unshare --net sh -eu -c '
  ip link set lo up
  ip link add om6-in type veth peer name om6-out
  ip link set om6-in up
  ip link set om6-out up
  OMINULL_IPV6_CAPTURE_TEST=1 "$1" -test.run TestIsolatedPacketCapture -test.v
  ip -6 addr add 2001:db8:1::1/64 dev om6-in nodad
  ip -6 neigh replace 2001:db8:1::2 lladdr 02:00:00:00:00:02 dev om6-in nud permanent
  OMINULL_IPV6_CAPTURE_TEST=1 "$2" -test.run TestIsolatedKernelNeighborDiscovery -test.v
' fixture "$ROOT_DIR/build/test-ipv6-monitor" "$ROOT_DIR/build/test-ipv6-discovery"
