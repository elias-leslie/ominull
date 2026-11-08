#!/usr/bin/env bash
# Runs the Linux isolation rig against real iptables, between two throwaway
# network namespaces with no link to the host. Needs root (sudo) and iptables.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p build
gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_linux_isolation_live.c \
    -o build/test_linux_isolation_live -lcurl -lbpf -lutil

A="ominull-rig-a-$$"
B="ominull-rig-b-$$"
cleanup() {
    sudo -n ip netns pids "$B" 2>/dev/null | sudo -n xargs -r kill 2>/dev/null || true
    sudo -n ip netns del "$A" 2>/dev/null || true
    sudo -n ip netns del "$B" 2>/dev/null || true
}
trap cleanup EXIT

sudo -n ip netns add "$A"
sudo -n ip netns add "$B"
sudo -n ip link add rig-a netns "$A" type veth peer name rig-b netns "$B"
sudo -n ip -n "$A" addr add 10.0.0.1/24 dev rig-a
sudo -n ip -n "$B" addr add 10.0.0.2/24 dev rig-b
sudo -n ip -n "$B" addr add 10.0.0.3/24 dev rig-b
sudo -n ip -n "$A" addr add 2001:db8::1/64 dev rig-a nodad
sudo -n ip -n "$B" addr add 2001:db8::2/64 dev rig-b nodad
for ns in "$A" "$B"; do
    sudo -n ip -n "$ns" link set lo up
done
sudo -n ip -n "$A" link set rig-a up
sudo -n ip -n "$B" link set rig-b up

sudo -n ip netns exec "$B" python3 -c '
import select, socket
listeners = []
for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    for port in (9003, 9004):
        s = socket.socket(family)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((address, port))
        s.listen(512)
        listeners.append(s)
while True:
    for s in select.select(listeners, [], [])[0]:
        s.accept()[0].close()
' &
sleep 0.5
sudo -n ip netns exec "$A" build/test_linux_isolation_live 10.0.0.2 2001:db8::2 10.0.0.3
