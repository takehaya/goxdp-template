//go:build integration

package coreelf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func flowFrame(t *testing.T, ipv6 bool, protocol layers.IPProtocol, source uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0xff, 0xff, 0xff, 0xff, 1}, EthernetType: layers.EthernetTypeIPv4}
	var ip gopacket.NetworkLayer = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: protocol, SrcIP: net.IP{198, 18, 0, 1}, DstIP: net.IP{198, 18, 0, 2}}
	if ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: protocol, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	}
	var transport gopacket.SerializableLayer
	if protocol == layers.IPProtocolTCP {
		tcp := &layers.TCP{SrcPort: layers.TCPPort(source), DstPort: 40001, SYN: true, Seq: 1, Window: 1024}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = tcp
	} else {
		udp := &layers.UDP{SrcPort: layers.UDPPort(source), DstPort: 40001}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		transport = udp
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip.(gopacket.SerializableLayer), transport, gopacket.Payload("flow-affinity payload")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func vxlanFlowHash(t *testing.T, v *VXLAN, ingress int, frame []byte) uint32 {
	t.Helper()
	type context struct{ Data, DataEnd, DataMeta, Ingress, RxQueue, Egress uint32 }
	var out context
	opts := &ebpf.RunOptions{Data: frame, DataOut: make([]byte, len(frame)+128), Context: &context{DataEnd: uint32(len(frame)), Ingress: uint32(ingress)}, ContextOut: &out}
	ret, err := v.Program().Run(opts)
	if err != nil || (ret != xdpRedirect && ret != xdpPass) {
		t.Fatalf("flow ingress: action %d, error %v", ret, err)
	}
	meta := opts.DataOut[out.DataMeta:out.Data]
	if len(meta) != 32 || binary.NativeEndian.Uint64(meta[8:16]) != 0x58445043 || binary.NativeEndian.Uint32(meta[24:28]) != out.DataEnd-out.Data {
		t.Fatalf("invalid flow metadata: %x", meta)
	}
	return binary.NativeEndian.Uint32(meta[28:32])
}

func TestVXLANFlowHash(t *testing.T) {
	n := newTCTestNetwork(t, 3)
	names := []string{n.devices[0].Name, n.devices[1].Name, n.devices[2].Name}
	cfg := VXLANConfig{
		Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], VNI: 200}, {Device: names[2], LocalIP: "192.0.2.1"}},
		Groups: []VXLANGroup{{VNI: 100, MulticastIP: "239.1.1.100", Devices: []string{names[0], names[2]}}, {VNI: 200, MulticastIP: "239.1.1.200", Devices: []string{names[1], names[2]}}},
	}
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) {
			load := ReadVXLANCollection
			if backend == "tc" {
				load = ReadTCVXLANCollection
			}
			v, err := load(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			for _, ipv6 := range []bool{false, true} {
				for _, protocol := range []layers.IPProtocol{layers.IPProtocolUDP, layers.IPProtocolTCP} {
					t.Run(fmt.Sprintf("ipv6=%v/%s", ipv6, protocol), func(t *testing.T) {
						frame := flowFrame(t, ipv6, protocol, 10000)
						hash := vxlanFlowHash(t, v, n.devices[0].Index, frame)
						changed := bytes.Clone(frame)
						changed[len(changed)-1] ^= 1
						changed[6] ^= 2
						if vxlanFlowHash(t, v, n.devices[0].Index, changed) != hash || vxlanFlowHash(t, v, n.devices[0].Index, frame) != hash {
							t.Fatal("payload or MAC changes moved an IP flow")
						}
						if vxlanFlowHash(t, v, n.devices[1].Index, frame) == hash {
							t.Fatal("VNI did not contribute to the flow hash")
						}
						if vxlanFlowHash(t, v, n.devices[2].Index, vxlanFrame(t, frame)) != hash {
							t.Fatal("access and decapsulated copies of the same flow differ")
						}
						hashes := map[uint32]bool{}
						for port := uint16(10000); port < 10064; port++ {
							hashes[vxlanFlowHash(t, v, n.devices[0].Index, flowFrame(t, ipv6, protocol, port))] = true
						}
						if len(hashes) < 32 {
							t.Fatalf("64 transport flows produced only %d hashes", len(hashes))
						}
						tagged := tcTaggedFrame(tcTaggedFrame(frame, 0x8100, 100), 0x88a8, 200)
						priority := bytes.Clone(tagged)
						priority[14] |= 0xb0
						if vxlanFlowHash(t, v, n.devices[0].Index, tagged) != vxlanFlowHash(t, v, n.devices[0].Index, priority) {
							t.Fatal("VLAN priority changed flow affinity")
						}
					})
				}
			}
			first := flowFrame(t, false, layers.IPProtocolUDP, 10000)
			binary.BigEndian.PutUint16(first[20:22], 0x2000)
			later := bytes.Clone(first)
			binary.BigEndian.PutUint16(later[20:22], 1)
			later[34], later[35] = 0xff, 0xff
			if vxlanFlowHash(t, v, n.devices[0].Index, first) != vxlanFlowHash(t, v, n.devices[0].Index, later) {
				t.Fatal("IPv4 fragments were assigned different hashes")
			}
			for length := 14; length < 42; length++ {
				vxlanFlowHash(t, v, n.devices[0].Index, first[:length])
			}
		})
	}
}

func TestVXLANCPUFlowDistribution(t *testing.T) {
	if !CPUMAPEnabled {
		t.Skip("CPUMAP disabled at build time")
	}
	available, err := SelectCPUs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(available) < 2 {
		t.Skip("requires at least two available CPUs")
	}
	cpus := []uint32{available[0], available[len(available)/2]}
	if len(available) > 2 {
		cpus = append(cpus, available[len(available)-1])
	}
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) {
			n := newTCTestNetwork(t, 3)
			names := []string{n.devices[0].Name, n.devices[1].Name, n.devices[2].Name}
			cfg := VXLANConfig{
				Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], LocalIP: "192.0.2.1"}, {Device: names[2], LocalIP: "198.51.100.1"}},
				Groups: []VXLANGroup{{VNI: 100, Devices: names, UnicastPeers: []VXLANPeer{{Device: names[1], RemoteIP: "192.0.2.2", RemoteMAC: n.peers[1].HardwareAddr.String()}, {Device: names[2], RemoteIP: "198.51.100.2", RemoteMAC: n.peers[2].HardwareAddr.String()}}}},
			}
			load := ReadVXLANCollection
			if backend == "tc" {
				load = ReadTCVXLANCollection
			}
			v, err := load(cfg, cpus...)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			n.attach(t, v.Program(), v.TCProgram(), 0, 1, 2)
			want := make([]uint64, ebpf.MustPossibleCPU())
			for port := uint16(10000); port < 10016; port++ {
				frame := flowFrame(t, false, layers.IPProtocolUDP, port)
				hash := vxlanFlowHash(t, v, n.devices[0].Index, frame)
				want[cpus[hash%uint32(len(cpus))]] += 2
				outputs := map[int][]byte{}
				for i := 1; i <= 2; i++ {
					outputs[i] = tcExpectedOuter(t, n, i, frame)
					binary.BigEndian.PutUint16(outputs[i][34:36], 49152|uint16(hash&0x3fff))
				}
				for repeat := 0; repeat < 2; repeat++ {
					n.exchange(t, 0, frame, outputs)
				}
			}
			stats := make([]vxlanPipelineCounters, ebpf.MustPossibleCPU())
			if err := v.objects.PipelineStats.Lookup(uint32(0), &stats); err != nil {
				t.Fatal(err)
			}
			for cpu, value := range stats {
				if value.CpuPackets != want[cpu] || value.HeaderPreparations != want[cpu] {
					t.Fatalf("CPU %d: got packets/preparations %d/%d, want %d", cpu, value.CpuPackets, value.HeaderPreparations, want[cpu])
				}
			}
			for _, cpu := range cpus {
				if want[cpu] == 0 {
					t.Fatalf("flows did not exercise CPU %d", cpu)
				}
			}
		})
	}
}
