//go:build linux

package ipv6guard

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
)

type linuxCapture struct{ fd int }

func openCapture(name string) (packetReader, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("capture requires an active Ethernet interface")
	}
	const ipv6NetworkOrder = 0xdd86
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, ipv6NetworkOrder)
	if err != nil {
		return nil, fmt.Errorf("IPv6 capture requires CAP_NET_RAW: %w", err)
	}
	fail := func(err error) (packetReader, error) { unix.Close(fd); return nil, err }
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ipv6NetworkOrder, Ifindex: iface.Index}); err != nil {
		return fail(err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fail(err)
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_ALLMULTI}); err != nil {
		return fail(err)
	}
	return &linuxCapture{fd}, nil
}
func (r *linuxCapture) Read(p []byte) (int, error) {
	n, address, err := unix.Recvfrom(r.fd, p, 0)
	if link, ok := address.(*unix.SockaddrLinklayer); ok && link.Pkttype == unix.PACKET_OUTGOING {
		return 0, errNoPacket
	}
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return 0, errNoPacket
	}
	return n, err
}
func (r *linuxCapture) Close() error { return unix.Close(r.fd) }
