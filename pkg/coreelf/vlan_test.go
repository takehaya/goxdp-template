package coreelf

import (
	"os"
	"strings"
	"testing"
)

func vlanTestConfig() VXLANConfig {
	return VXLANConfig{
		Ports: []VXLANPort{
			{Device: "trunk0", VLANs: []VXLANVLAN{{VID: 10, VNI: 100}, {VID: 20, VNI: 200}}},
			{Device: "trunk1", VLANs: []VXLANVLAN{{VID: 10, VNI: 100}, {VID: 20, VNI: 200}}},
			{Device: "other", VLANs: []VXLANVLAN{{VID: 10, VNI: 300}}},
			{Device: "wan0", LocalIP: "192.0.2.1"},
		},
		Groups: []VXLANGroup{
			{VNI: 100, MulticastIP: "239.1.1.100", Devices: []string{"trunk0", "trunk1", "wan0"}},
			{VNI: 200, MulticastIP: "239.1.1.200", Devices: []string{"trunk0", "trunk1", "wan0"}},
			{VNI: 300, MulticastIP: "239.1.2.44", Devices: []string{"other"}},
		},
		FDB: []VXLANFDBEntry{
			{VNI: 100, MAC: "02:00:00:00:00:01", Device: "trunk1"},
			{VNI: 200, MAC: "02:00:00:00:00:01", Device: "trunk1"},
		},
	}
}

func TestVLANConfig(t *testing.T) {
	if err := vlanTestConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		edit func(*VXLANConfig)
	}{
		{"fixed VNI and bindings", func(c *VXLANConfig) { c.Ports[0].VNI = 100 }},
		{"tunnel and bindings", func(c *VXLANConfig) { c.Ports[0].LocalIP = "192.0.2.1" }},
		{"empty bindings", func(c *VXLANConfig) { c.Ports[0].VLANs = nil }},
		{"VID zero", func(c *VXLANConfig) { c.Ports[0].VLANs[0].VID = 0 }},
		{"reserved VID", func(c *VXLANConfig) { c.Ports[0].VLANs[0].VID = 4095 }},
		{"VID overflow", func(c *VXLANConfig) { c.Ports[0].VLANs[0].VID = 4096 }},
		{"VNI zero", func(c *VXLANConfig) { c.Ports[0].VLANs[0].VNI = 0 }},
		{"VNI overflow", func(c *VXLANConfig) { c.Ports[0].VLANs[0].VNI = 1 << 24 }},
		{"duplicate VID", func(c *VXLANConfig) { c.Ports[0].VLANs[1].VID = 10 }},
		{"duplicate VNI", func(c *VXLANConfig) { c.Ports[0].VLANs[1].VNI = 100 }},
		{"too many bindings", func(c *VXLANConfig) { c.Ports[0].VLANs = make([]VXLANVLAN, 65) }},
		{"different local VID", func(c *VXLANConfig) { c.Ports[1].VLANs[0].VID = 11 }},
		{"legacy member", func(c *VXLANConfig) {
			c.Ports = append(c.Ports, VXLANPort{Device: "legacy", VNI: 100})
			c.Groups[0].Devices = append(c.Groups[0].Devices, "legacy")
		}},
		{"foreign VID member", func(c *VXLANConfig) { c.Groups[0].Devices = append(c.Groups[0].Devices, "other") }},
		{"binding without group", func(c *VXLANConfig) { c.Ports[0].VLANs = append(c.Ports[0].VLANs, VXLANVLAN{VID: 30, VNI: 400}) }},
		{"binding without membership", func(c *VXLANConfig) { c.Groups[0].Devices = []string{"trunk1", "wan0"} }},
		{"foreign FDB", func(c *VXLANConfig) { c.FDB[0].Device = "other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := vlanTestConfig()
			tt.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid VLAN config accepted")
			}
		})
	}
}

func TestVLANExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/vxlan-vlan.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeVXLANConfig(strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
}
