//go:build integration

package coreelf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket/layers"
)

func TestVLANForwarding(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cpu=%v", backend, redirect), func(t *testing.T) {
				if redirect && !CPUMAPEnabled {
					t.Skip("CPUMAP disabled at build time")
				}
				runVLANForwarding(t, backend, redirect)
			})
		}
	}
}

func runVLANForwarding(t *testing.T, backend string, redirect bool) {
	n := newTCTestNetwork(t, 8)
	names := make([]string, len(n.devices))
	for i, dev := range n.devices {
		names[i] = dev.Name
	}
	cfg := VXLANConfig{Ports: []VXLANPort{
		{Device: names[0], VLANs: []VXLANVLAN{{VID: 10, VNI: 100}, {VID: 20, VNI: 200}}},
		{Device: names[1], VLANs: []VXLANVLAN{{VID: 10, VNI: 100}, {VID: 20, VNI: 200}}},
		{Device: names[2], VLANs: []VXLANVLAN{{VID: 10, VNI: 100}}},
		{Device: names[3], VLANs: []VXLANVLAN{{VID: 20, VNI: 200}}},
		{Device: names[4], VLANs: []VXLANVLAN{{VID: 10, VNI: 300}}},
		{Device: names[5], LocalIP: "192.0.2.5"},
		{Device: names[6], LocalIP: "192.0.2.6"},
		{Device: names[7], VLANs: []VXLANVLAN{{VID: 10, VNI: 300}}},
	}}
	for i, members := range [][]int{{0, 1, 2, 5}, {0, 1, 3, 5, 6}, {4, 7}} {
		group := VXLANGroup{VNI: uint32((i + 1) * 100)}
		for _, index := range members {
			group.Devices = append(group.Devices, names[index])
			if index == 5 || index == 6 {
				group.UnicastPeers = append(group.UnicastPeers, VXLANPeer{Device: names[index], RemoteIP: fmt.Sprintf("192.0.2.%d", 200+index), RemoteMAC: n.peers[index].HardwareAddr.String()})
			}
		}
		if len(group.UnicastPeers) == 0 {
			group.MulticastIP = "239.1.2.44"
		}
		cfg.Groups = append(cfg.Groups, group)
	}
	for i, vni := range []uint32{100, 200} {
		cfg.FDB = append(cfg.FDB, VXLANFDBEntry{VNI: vni, MAC: "02:00:00:00:00:99", Device: names[i+2]})
	}
	var cpus []uint32
	if redirect {
		available, err := SelectCPUs(nil)
		if err != nil {
			t.Fatal(err)
		}
		cpus = available[:1]
	}
	load := ReadVXLANCollection
	if backend == "tc" {
		load = ReadTCVXLANCollection
	}
	v, err := load(cfg, cpus...)
	if err != nil {
		t.Fatalf("load VLAN forwarding: %+v", err)
	}
	t.Cleanup(func() { v.Close() })
	n.attach(t, v.Program(), v.TCProgram(), 0, 1, 2, 3, 4, 5, 6, 7)
	outer := func(frame []byte, output int, vni uint32, ingress bool) []byte {
		packet := vxlanFrame(t, frame)
		copy(packet[:6], n.peers[output].HardwareAddr)
		copy(packet[6:12], n.devices[output].HardwareAddr)
		copy(packet[30:33], net.IP{192, 0, 2})
		packet[29], packet[33] = byte(output), byte(200+output)
		binary.BigEndian.PutUint16(packet[20:22], 0x4000)
		binary.BigEndian.PutUint16(packet[34:36], 0)
		binary.BigEndian.PutUint16(packet[40:42], 0)
		binary.BigEndian.PutUint32(packet[46:50], vni<<8)
		if ingress {
			copy(packet[:6], n.devices[output].HardwareAddr)
			packet[29], packet[33] = byte(200+output), byte(output)
		}
		return fixIPv4Checksum(packet)
	}
	base := tcInnerFrame(t, layers.EthernetTypeIPv4)
	t.Run("unrelated-VXLAN-destination", func(t *testing.T) {
		frame := tcTaggedFrame(base, 0x8100, 10)
		packet := outer(frame, 6, 100, true)
		packet[33] = 99
		fixIPv4Checksum(packet)
		ctx := struct{ Data, DataEnd, DataMeta, Ingress, RxQueue, Egress uint32 }{DataEnd: uint32(len(packet)), Ingress: uint32(n.devices[6].Index)}
		action, err := v.Program().Run(&ebpf.RunOptions{Data: packet, Context: &ctx})
		if err != nil || action != xdpPass {
			t.Fatalf("unrelated destination: action %d, error %v, want XDP_PASS", action, err)
		}
	})
	for i, vid := range []uint16{10, 20} {
		vni := uint32((i + 1) * 100)
		for _, kind := range []string{"broadcast", "unknown-unicast", "multicast-ipv4", "multicast-ipv6"} {
			t.Run(fmt.Sprintf("vid-%d/%s", vid, kind), func(t *testing.T) {
				frame := tcInnerFrame(t, layers.EthernetTypeARP)
				switch kind {
				case "unknown-unicast":
					frame = bytes.Clone(base)
					copy(frame[:6], net.HardwareAddr{2, 0, 0, 0, 0, 88})
				case "multicast-ipv4":
					frame = bytes.Clone(base)
					copy(frame[:6], net.HardwareAddr{1, 0, 0x5e, 1, 2, 3})
					copy(frame[30:34], net.IP{239, 1, 2, 3})
					fixIPv4Checksum(frame)
				case "multicast-ipv6":
					frame = tcInnerFrame(t, layers.EthernetTypeIPv6)
					copy(frame[:6], net.HardwareAddr{0x33, 0x33, 0, 0, 0, 42})
					copy(frame[38:54], net.ParseIP("ff02::42").To16())
				}
				frame = tcTaggedFrame(frame, 0x8100, vid|0xb000)
				wants := map[int][]byte{1: frame, i + 2: frame, 5: outer(frame, 5, vni, false)}
				if i == 1 {
					wants[6] = outer(frame, 6, vni, false)
				}
				n.exchange(t, 0, frame, wants)
			})
		}
		t.Run(fmt.Sprintf("vid-%d/FDB", vid), func(t *testing.T) {
			frame := tcTaggedFrame(base, 0x8100, vid)
			copy(frame[:6], net.HardwareAddr{2, 0, 0, 0, 0, 0x99})
			n.exchange(t, 0, frame, map[int][]byte{i + 2: frame})
		})
		t.Run(fmt.Sprintf("vid-%d/decap", vid), func(t *testing.T) {
			frame := tcTaggedFrame(base, 0x8100, vid)
			n.exchange(t, 5, outer(frame, 5, vni, true), map[int][]byte{0: frame, 1: frame, i + 2: frame})
		})
	}
	t.Run("same-VID-other-port-domain", func(t *testing.T) {
		frame := tcTaggedFrame(base, 0x8100, 10)
		n.exchange(t, 4, frame, map[int][]byte{7: frame})
	})
	t.Run("multicast-underlay", func(t *testing.T) {
		var saved vxlanVniConfig
		if err := v.objects.Vnis.Lookup(uint32(100), &saved); err != nil {
			t.Fatal(err)
		}
		group := saved
		group.MulticastIp, _ = ipv4Value("239.1.1.100", true)
		if err := v.objects.Vnis.Put(uint32(100), group); err != nil {
			t.Fatal(err)
		}
		defer v.objects.Vnis.Put(uint32(100), saved)
		frame := tcTaggedFrame(base, 0x8100, 10)
		packet := outer(frame, 5, 100, false)
		copy(packet[:6], net.HardwareAddr{1, 0, 0x5e, 1, 1, 100})
		copy(packet[30:34], net.IP{239, 1, 1, 100})
		fixIPv4Checksum(packet)
		n.exchange(t, 0, frame, map[int][]byte{1: frame, 2: frame, 5: packet})
	})
	t.Run("tagged-access-MTU", func(t *testing.T) {
		ipCommand(t, "link", "set", names[2], "mtu", "1500")
		defer ipCommand(t, "link", "set", names[2], "mtu", "1600")
		for _, size := range []int{1518, 1519} {
			frame := tcTaggedFrame(base, 0x8100, 10)
			frame = append(frame, make([]byte, size-len(frame))...)
			wants := map[int][]byte{1: frame, 5: outer(frame, 5, 100, false)}
			if size == 1518 {
				wants[2] = frame
			}
			n.exchange(t, 0, frame, wants)
		}
	})
	for name, frame := range map[string][]byte{
		"unknown-VID": tcTaggedFrame(base, 0x8100, 30),
		"untagged":    base,
		"priority":    tcTaggedFrame(base, 0x8100, 0xb000),
		"reserved":    tcTaggedFrame(base, 0x8100, 4095),
		"8021ad":      tcTaggedFrame(base, 0x88a8, 10),
		"double-tag":  tcTaggedFrame(tcTaggedFrame(base, 0x8100, 10), 0x8100, 10),
		"truncated":   tcTaggedFrame(base, 0x8100, 10)[:16],
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("local", func(t *testing.T) { n.exchange(t, 0, frame, nil) })
			t.Run("overlay", func(t *testing.T) { n.exchange(t, 5, outer(frame, 5, 100, true), nil) })
		})
	}
	t.Run("overlay-VID-mismatch", func(t *testing.T) {
		frame := tcTaggedFrame(base, 0x8100, 20)
		n.exchange(t, 5, outer(frame, 5, 100, true), nil)
	})
	t.Run("unauthorized-tunnel-VNI", func(t *testing.T) {
		frame := tcTaggedFrame(base, 0x8100, 10)
		n.exchange(t, 6, outer(frame, 6, 100, true), nil)
	})
	t.Run("live-group-subset", func(t *testing.T) {
		if err := v.UpdateMembers(100, []string{names[0], names[2], names[5]}); err != nil {
			t.Fatal(err)
		}
		frame := tcTaggedFrame(base, 0x8100, 10)
		n.exchange(t, 0, frame, map[int][]byte{2: frame, 5: outer(frame, 5, 100, false)})
		if err := v.UpdateMembers(100, []string{names[0], names[4]}); err == nil {
			t.Fatal("accepted a member of another domain")
		}
		if err := v.UpdateMembers(100, []string{names[0], names[6]}); err == nil {
			t.Fatal("accepted a tunnel outside the preconfigured VNI")
		}
	})
}
