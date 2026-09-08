package storage

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"ominull/hub/pkg/netaddr"
)

// TopologyNetwork is operator-supplied estate membership, not an inferred route.
type TopologyNetwork struct {
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
	Kind  string `json:"kind,omitempty"`
}

// ValidateTopologyNetworks checks and canonicalizes an explicit estate network list.
func ValidateTopologyNetworks(networks []TopologyNetwork) error {
	seen := map[string]bool{}
	for i := range networks {
		if networks[i].Kind != "" && networks[i].Kind != "physical" && networks[i].Kind != "virtual" {
			return fmt.Errorf("network %d has an invalid kind", i+1)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(networks[i].CIDR))
		if err != nil || p.Bits() == 0 || p.Addr().Is4In6() || p.Addr().IsMulticast() || p.Addr().IsLoopback() {
			return fmt.Errorf("network %d requires an explicit unicast IPv4 or IPv6 prefix", i+1)
		}
		networks[i].CIDR = p.Masked().String()
		networks[i].Label = strings.TrimSpace(networks[i].Label)
		if networks[i].Label == "" {
			networks[i].Label = networks[i].CIDR
		}
		if len(networks[i].Label) > 128 || strings.ContainsAny(networks[i].Label, "\r\n\x00") {
			return fmt.Errorf("network %d has an invalid label", i+1)
		}
		if seen[networks[i].CIDR] {
			return fmt.Errorf("duplicate network %s", networks[i].CIDR)
		}
		seen[networks[i].CIDR] = true
	}
	sort.SliceStable(networks, func(i, j int) bool {
		a, _ := netip.ParsePrefix(networks[i].CIDR)
		b, _ := netip.ParsePrefix(networks[j].CIDR)
		return a.Bits() > b.Bits()
	})
	return nil
}

func (s *Store) TopologyNetworks() ([]TopologyNetwork, error) {
	raw, err := s.GetSetting("topology.networks")
	if err != nil {
		return nil, err
	}
	networks := []TopologyNetwork{}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &networks); err != nil {
			return nil, fmt.Errorf("decode estate networks: %w", err)
		}
	}
	if err := ValidateTopologyNetworks(networks); err != nil {
		return nil, err
	}
	return networks, nil
}

func (s *Store) SetTopologyNetworks(networks []TopologyNetwork) error {
	networks = append([]TopologyNetwork{}, networks...)
	if err := ValidateTopologyNetworks(networks); err != nil {
		return err
	}
	raw, err := json.Marshal(networks)
	if err != nil {
		return err
	}
	return s.SetSetting("topology.networks", string(raw))
}

func describeTopologyNetwork(n *TopologyNode, networks []TopologyNetwork) {
	n.AddressScope = netaddr.Scope(n.IP)
	n.EstateMember = n.AssetID != "" || n.Type == "managed"
	a, err := netaddr.Parse(n.IP)
	if err != nil {
		n.NetworkID, n.NetworkLabel = "unknown", "Address unknown"
		return
	}
	for _, network := range networks {
		p, _ := netip.ParsePrefix(network.CIDR)
		if p.Contains(a.WithZone("")) {
			n.EstateMember = true
			n.NetworkID, n.NetworkLabel = network.CIDR, network.Label
			n.NetworkKind = network.Kind
			if n.Type == "cloud" {
				n.Type, n.Group = "unmanaged", "Seen in traffic only"
			}
			return
		}
	}
	if n.AddressScope == "public" {
		if n.EstateMember {
			n.NetworkID, n.NetworkLabel = "estate-unassigned", "Known estate (segment unknown)"
		} else {
			n.NetworkID, n.NetworkLabel = "external", "Internet"
		}
		return
	}
	if a.Is4() && (n.AddressScope == "private" || n.AddressScope == "shared") {
		n.NetworkID = netip.PrefixFrom(a, 24).Masked().String()
		n.NetworkLabel = n.NetworkID + " (address group)"
		return
	}
	family := "IPv6"
	if a.Is4() {
		family = "IPv4"
	}
	n.NetworkID = n.AddressScope + ":" + strings.ToLower(family) + ":" + a.Zone()
	n.NetworkLabel = n.AddressScope + " " + family + " (segment unknown)"
	if a.Zone() != "" {
		n.NetworkLabel += " · " + a.Zone()
	}
}
