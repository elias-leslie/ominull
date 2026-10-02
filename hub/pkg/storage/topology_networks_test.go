package storage

import (
	"fmt"
	"reflect"
	"testing"
)

func TestTopologyClassificationContracts(t *testing.T) {
	networks := []TopologyNetwork{
		{CIDR: "10.0.0.0/8", Label: "Broad", Kind: "physical"},
		{CIDR: "10.1.0.0/16", Label: "Narrow", Kind: "virtual"},
		{CIDR: "2001:db8:1::/48", Label: "IPv6", Kind: "physical"},
		{CIDR: "fe80::/64", Label: "Link", Kind: "physical"},
	}
	if err := ValidateTopologyNetworks(networks); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		node                   TopologyNode
		id, label, kind, scope string
		estate                 bool
		typ, group             string
	}{
		{TopologyNode{IP: "10.1.2.3", Type: "cloud"}, "10.1.0.0/16", "Narrow", "virtual", "private", true, "unmanaged", "Seen in traffic only"},
		{TopologyNode{IP: "::ffff:10.1.2.3"}, "10.1.0.0/16", "Narrow", "virtual", "private", true, "", ""},
		{TopologyNode{IP: "2001:db8:1::8"}, "2001:db8:1::/48", "IPv6", "physical", "public", true, "", ""},
		{TopologyNode{IP: "fe80::8%eth0"}, "fe80::/64", "Link", "physical", "link-local", true, "", ""},
		{TopologyNode{IP: "198.51.100.8", AssetID: "known"}, "estate-unassigned", "Known estate (segment unknown)", "", "public", true, "", ""},
		{TopologyNode{IP: "198.51.100.8", Type: "managed"}, "estate-unassigned", "Known estate (segment unknown)", "", "public", true, "managed", ""},
		{TopologyNode{IP: "198.51.100.8"}, "external", "Internet", "", "public", false, "", ""},
		{TopologyNode{IP: "172.20.1.8"}, "172.20.1.0/24", "172.20.1.0/24 (address group)", "", "private", false, "", ""},
		{TopologyNode{IP: "100.64.1.8"}, "100.64.1.0/24", "100.64.1.0/24 (address group)", "", "shared", false, "", ""},
		{TopologyNode{IP: "fe80:1::8%eth1"}, "link-local:ipv6:eth1", "link-local IPv6 (segment unknown) · eth1", "", "link-local", false, "", ""},
		{TopologyNode{IP: "invalid"}, "unknown", "Address unknown", "", "invalid", false, "", ""},
	} {
		t.Run(tt.node.IP+tt.node.Type+tt.node.AssetID, func(t *testing.T) {
			got := tt.node
			describeTopologyNetwork(&got, prepareTopologyNetworks(networks))
			want := tt.node
			want.NetworkID, want.NetworkLabel, want.NetworkKind = tt.id, tt.label, tt.kind
			want.AddressScope, want.EstateMember = tt.scope, tt.estate
			want.Type, want.Group = tt.typ, tt.group
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("classification:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func BenchmarkTopologyClassification(b *testing.B) {
	for _, count := range []int{1, 8, 64} {
		b.Run(fmt.Sprintf("networks_%d", count), func(b *testing.B) {
			networks := make([]TopologyNetwork, count)
			for i := range networks {
				cidr := fmt.Sprintf("10.%d.0.0/16", i)
				if i%2 != 0 {
					cidr = fmt.Sprintf("2001:db8:%x::/48", i)
				}
				networks[i] = TopologyNetwork{CIDR: cidr, Label: cidr}
			}
			if err := ValidateTopologyNetworks(networks); err != nil {
				b.Fatal(err)
			}
			addresses := []string{"10.0.1.8", "2001:db8:1::8", "10.62.1.8", "2001:db8:3f::8", "198.51.100.8", "fe80::8%eth0"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				prepared := prepareTopologyNetworks(networks)
				for j := 0; j < 1000; j++ {
					node := TopologyNode{IP: addresses[j%len(addresses)]}
					describeTopologyNetwork(&node, prepared)
					if node.NetworkID == "" {
						b.Fatal("missing classification")
					}
				}
			}
		})
	}
}
