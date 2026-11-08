#!/usr/bin/env bash
# Runs the isolation firewall against a real path-MTU failure: this namespace, a router
# on no allow list, and a peer behind a smaller link. Throwaway namespaces with no link
# to the host. Needs root (sudo) and iptables.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p build
gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_linux_icmp_errors_live.c \
    -o build/test_linux_icmp_errors_live -lcurl -lbpf -lutil

A="ominull-mtu-a-$$"; R="ominull-mtu-r-$$"; B="ominull-mtu-b-$$"
cleanup() {
    sudo -n ip netns pids "$B" 2>/dev/null | sudo -n xargs -r kill 2>/dev/null || true
    for ns in "$A" "$R" "$B"; do sudo -n ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
for ns in "$A" "$R" "$B"; do
    sudo -n ip netns add "$ns"
    sudo -n ip -n "$ns" link set lo up
done
sudo -n ip link add mtu-a netns "$A" type veth peer name mtu-ra netns "$R"
# Only the router's side is small: at the peer's own size it would advertise a smaller
# segment at connect time and no packet would ever be too big.
sudo -n ip link add mtu-b netns "$B" type veth peer name mtu-rb netns "$R" mtu 1280
sudo -n ip -n "$A" addr add 10.0.1.1/24 dev mtu-a
sudo -n ip -n "$R" addr add 10.0.1.254/24 dev mtu-ra
sudo -n ip -n "$R" addr add 10.0.2.254/24 dev mtu-rb
sudo -n ip -n "$B" addr add 10.0.2.2/24 dev mtu-b
sudo -n ip -n "$A" addr add 2001:db8:1::1/64 dev mtu-a nodad
sudo -n ip -n "$R" addr add 2001:db8:1::fe/64 dev mtu-ra nodad
sudo -n ip -n "$R" addr add 2001:db8:2::fe/64 dev mtu-rb nodad
sudo -n ip -n "$B" addr add 2001:db8:2::2/64 dev mtu-b nodad
sudo -n ip -n "$A" link set mtu-a up
sudo -n ip -n "$R" link set mtu-ra up
sudo -n ip -n "$R" link set mtu-rb up
sudo -n ip -n "$B" link set mtu-b up
sudo -n ip -n "$A" route add default via 10.0.1.254
sudo -n ip -n "$B" route add default via 10.0.2.254
sudo -n ip -n "$A" -6 route add default via 2001:db8:1::fe
sudo -n ip -n "$B" -6 route add default via 2001:db8:2::fe
sudo -n ip netns exec "$R" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

sudo -n ip netns exec "$B" python3 -c '
import select, socket, threading
def serve(c):
    c.settimeout(10)
    try:
        while c.recv(65536):
            pass
        c.sendall(b"k")
    except OSError:
        pass
    c.close()
listeners = []
for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    s = socket.socket(family)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((address, 9005))
    s.listen(16)
    listeners.append(s)
while True:
    for s in select.select(listeners, [], [])[0]:
        threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
' &
sleep 0.5
sudo -n ip netns exec "$A" build/test_linux_icmp_errors_live 10.0.2.2 2001:db8:2::2
