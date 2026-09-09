//go:build !linux

package ipv6guard

import "fmt"

func openCapture(string) (packetReader, error) {
	return nil, fmt.Errorf("IPv6 capture is supported by the Linux hub only")
}
