package coreelf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

const testVXLANConfig = `{
  "ports": [{"device":"lan0","vni":100}, {"device":"lan1","vni":200}, {"device":"wan0","local_ip":"192.0.2.1"}],
  "groups": [{"vni":100,"multicast_ip":"239.1.1.100","devices":["lan0","wan0"]},
             {"vni":200,"multicast_ip":"239.1.1.200","devices":["lan1","wan0"]}],
  "fdb": [{"vni":100,"mac":"02:00:00:00:00:01","device":"lan0"}]
}`

func TestVXLANConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*VXLANConfig)
	}{
		{"no ports", func(c *VXLANConfig) { c.Ports = nil }},
		{"no groups", func(c *VXLANConfig) { c.Groups = nil }},
		{"zero VNI", func(c *VXLANConfig) { c.Ports[0].VNI = 0 }},
		{"VNI overflow", func(c *VXLANConfig) { c.Groups[0].VNI = 1 << 24 }},
		{"duplicate group", func(c *VXLANConfig) { c.Groups = append(c.Groups, c.Groups[0]) }},
		{"duplicate port", func(c *VXLANConfig) { c.Ports = append(c.Ports, c.Ports[0]) }},
		{"mixed port roles", func(c *VXLANConfig) { c.Ports[0].LocalIP = "192.0.2.1" }},
		{"IPv6 underlay", func(c *VXLANConfig) { c.Ports[2].LocalIP = "2001:db8::1" }},
		{"multicast source", func(c *VXLANConfig) { c.Ports[2].LocalIP = "239.1.1.1" }},
		{"unicast group", func(c *VXLANConfig) { c.Groups[0].MulticastIP = "192.0.2.1" }},
		{"unknown member", func(c *VXLANConfig) { c.Groups[0].Devices = append(c.Groups[0].Devices, "missing") }},
		{"foreign VNI member", func(c *VXLANConfig) { c.Groups[0].Devices = append(c.Groups[0].Devices, "lan1") }},
		{"duplicate member", func(c *VXLANConfig) { c.Groups[0].Devices = append(c.Groups[0].Devices, "lan0") }},
		{"access absent from group", func(c *VXLANConfig) { c.Groups[0].Devices = []string{"wan0"} }},
		{"multicast FDB", func(c *VXLANConfig) { c.FDB[0].MAC = "01:00:5e:01:01:01" }},
		{"non Ethernet FDB", func(c *VXLANConfig) { c.FDB[0].MAC = "02:00:00:00:00:01:00:00" }},
		{"foreign VNI FDB", func(c *VXLANConfig) { c.FDB[0].Device = "lan1" }},
		{"tunnel FDB", func(c *VXLANConfig) { c.FDB[0].Device = "wan0" }},
		{"duplicate FDB", func(c *VXLANConfig) { c.FDB = append(c.FDB, c.FDB[0]) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := DecodeVXLANConfig(strings.NewReader(testVXLANConfig))
			if err != nil {
				t.Fatal(err)
			}
			tt.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid forwarding config accepted")
			}
		})
	}
	for _, input := range []string{`{"typo":true}`, testVXLANConfig + `{}`, testVXLANConfig + ` garbage`} {
		if _, err := DecodeVXLANConfig(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed JSON config: %s", input)
		}
	}
}

func TestVXLANSpec(t *testing.T) {
	spec, err := loadVxlan()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["vxlan_egress"].AttachType != ebpf.AttachXDPDevMap {
		t.Fatal("egress must be a devmap program")
	}
	if spec.Programs["vxlan_rewrite"].AttachType != ebpf.AttachXDPDevMap {
		t.Fatal("dispatchers and handlers must have matching attach types")
	}
	if CPUMAPEnabled && (spec.Programs["vxlan_cpu"].AttachType != ebpf.AttachXDPCPUMap ||
		spec.Programs["vxlan_cpu_forward"].AttachType != ebpf.AttachXDPCPUMap) {
		t.Fatal("CPU dispatchers and handlers must have matching attach types")
	}
	groups := spec.Maps["vni_groups"]
	if groups.Type != ebpf.HashOfMaps || groups.InnerMap.Type != ebpf.DevMapHash || groups.InnerMap.ValueSize != 8 {
		t.Fatalf("unexpected VNI group map: %+v", groups)
	}
	for _, name := range []string{"peer_cache", "header_cache"} {
		if spec.Maps[name].Type != ebpf.LRUCPUHash {
			t.Fatalf("%s must use LRU_PERCPU_HASH", name)
		}
	}
}

func TestVXLANUnicastConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*VXLANConfig)
	}{
		{"mixed modes", func(c *VXLANConfig) { c.Groups[0].MulticastIP = "239.1.1.100" }},
		{"no destination", func(c *VXLANConfig) { c.Groups[0].UnicastPeers = nil }},
		{"access peer", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].Device = "lan0" }},
		{"duplicate peer", func(c *VXLANConfig) {
			c.Groups[0].UnicastPeers = append(c.Groups[0].UnicastPeers, c.Groups[0].UnicastPeers[0])
		}},
		{"unknown peer port", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].Device = "missing" }},
		{"multicast peer IP", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].RemoteIP = "239.1.1.1" }},
		{"IPv6 peer IP", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].RemoteIP = "2001:db8::2" }},
		{"self peer IP", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].RemoteIP = "192.0.2.1" }},
		{"multicast peer MAC", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].RemoteMAC = "01:00:5e:01:01:01" }},
		{"zero peer MAC", func(c *VXLANConfig) { c.Groups[0].UnicastPeers[0].RemoteMAC = "00-00-00-00-00-00" }},
		{"missing tunnel peer", func(c *VXLANConfig) {
			c.Ports = append(c.Ports, VXLANPort{Device: "wan1", LocalIP: "198.51.100.1"})
			c.Groups[0].Devices = append(c.Groups[0].Devices, "wan1")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := DecodeVXLANConfig(strings.NewReader(testVXLANConfig))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Groups[0].MulticastIP = ""
			cfg.Groups[0].UnicastPeers = []VXLANPeer{{Device: "wan0", RemoteIP: "192.0.2.2", RemoteMAC: "02:00:00:00:00:02"}}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			tt.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid unicast replication config accepted")
			}
		})
	}
}
