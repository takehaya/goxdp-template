//go:build linux && scenario

package scenarios

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
)

func vlanFrame(frame []byte, protocol, tag uint16) []byte {
	result := make([]byte, len(frame)+4)
	copy(result, frame[:12])
	binary.BigEndian.PutUint16(result[12:14], protocol)
	binary.BigEndian.PutUint16(result[14:16], tag)
	copy(result[16:], frame[12:])
	return result
}

func TestVLANBUM(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cpu=%v", backend, redirect), func(t *testing.T) {
				if redirect && !coreelf.CPUMAPEnabled {
					t.Skip("CPUMAP disabled at build time")
				}
				runVLANBUM(t, backend, redirect)
			})
		}
	}
}

func runVLANBUM(t *testing.T, backend string, redirect bool) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vlan_peer_pass", Type: ebpf.XDP, License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	prefix := fmt.Sprintf("gxvl-%d-", os.Getpid())
	nodes := []string{prefix + "a", prefix + "b"}
	for _, ns := range nodes {
		newNamespace(t, ns)
	}
	bindings := []coreelf.VXLANVLAN{{VID: 10, VNI: 100}, {VID: 20, VNI: 200}}
	configs := make([]coreelf.VXLANConfig, 2)
	var hosts []endpoint
	var captures []capture
	for i, spec := range []struct {
		name  string
		node  int
		vlans []coreelf.VXLANVLAN
	}{
		{"source", 0, bindings},
		{"local10", 0, bindings[:1]},
		{"local20", 0, bindings[1:]},
		{"other", 0, []coreelf.VXLANVLAN{{VID: 10, VNI: 300}}},
		{"remote", 1, bindings},
	} {
		host := endpoint{name: spec.name, namespace: prefix + spec.name, port: fmt.Sprintf("p%d", i), mac: net.HardwareAddr{2, 0, 0, 0, 3, byte(i + 1)}}
		newNamespace(t, host.namespace)
		connectHost(t, nodes[spec.node], &host, pass)
		hosts = append(hosts, host)
		captures = append(captures, capture{name: host.name, fd: host.fd})
		configs[spec.node].Ports = append(configs[spec.node].Ports, coreelf.VXLANPort{Device: host.port, VLANs: spec.vlans})
	}
	command(t, "ip", "-n", nodes[0], "link", "add", "wan0", "type", "veth", "peer", "name", "wan0", "netns", nodes[1])
	peerMACs := make([]string, 2)
	for i, ns := range nodes {
		command(t, "ip", "-n", ns, "link", "set", "wan0", "mtu", "1600")
		command(t, "ip", "-n", ns, "link", "set", "wan0", "up")
		configs[i].Ports = append(configs[i].Ports, coreelf.VXLANPort{Device: "wan0", LocalIP: fmt.Sprintf("192.0.2.%d", i+1)})
		inNamespace(t, ns, func() {
			iface, err := net.InterfaceByName("wan0")
			if err != nil {
				t.Fatal(err)
			}
			peerMACs[i] = iface.HardwareAddr.String()
		})
	}
	for i := range configs {
		for _, binding := range bindings {
			group := coreelf.VXLANGroup{VNI: binding.VNI, Devices: []string{"wan0"}, UnicastPeers: []coreelf.VXLANPeer{{Device: "wan0", RemoteIP: fmt.Sprintf("192.0.2.%d", 2-i), RemoteMAC: peerMACs[1-i]}}}
			for _, p := range configs[i].Ports {
				for _, vlan := range p.VLANs {
					if vlan.VNI == binding.VNI {
						group.Devices = append(group.Devices, p.Device)
					}
				}
			}
			configs[i].Groups = append(configs[i].Groups, group)
		}
	}
	configs[0].Groups = append(configs[0].Groups, coreelf.VXLANGroup{VNI: 300, Devices: []string{"p3"}, MulticastIP: "239.1.2.44"})
	for i, vni := range []uint32{100, 200} {
		configs[0].FDB = append(configs[0].FDB, coreelf.VXLANFDBEntry{VNI: vni, MAC: "02:00:00:00:00:99", Device: hosts[i+1].port})
	}
	binaryPath, err := filepath.Abs(*goxdpBinary)
	if err != nil {
		t.Fatal(err)
	}
	var stops []func()
	for i, cfg := range configs {
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "vlan.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--mode", "vxlan", "--backend", backend, "--config", path}
		if redirect {
			cpus, err := coreelf.SelectCPUs(nil)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--cpu-redirect", "--cpu", fmt.Sprint(cpus[0]))
		}
		var ports []endpoint
		for _, p := range cfg.Ports {
			args = append(args, "--device", p.Device)
			ports = append(ports, endpoint{port: p.Device})
		}
		stops = append(stops, startForwarder(t, nodes[i], binaryPath, args))
		assertBackend(t, nodes[i], ports, backend, true)
	}
	run := func(t *testing.T, sender int, vid uint16, kind string, known bool, receivers ...string) {
		t.Helper()
		marker := []byte("goxdp/vlan/" + t.Name())
		frame := makeFrame(t, hosts[sender].mac, kind, marker)
		if known {
			copy(frame[:6], net.HardwareAddr{2, 0, 0, 0, 0, 0x99})
		}
		if vid != 0 {
			frame = vlanFrame(frame, 0x8100, vid|0xb000)
		}
		wants := make([]int, len(captures))
		for i, c := range captures {
			for _, name := range receivers {
				if c.name == name {
					wants[i] = 1
				}
			}
		}
		checkFrames(t, hosts[sender], [][]byte{frame}, marker, captures, wants)
	}
	for _, vid := range []uint16{10, 20} {
		local := fmt.Sprintf("local%d", vid)
		for _, kind := range []string{"broadcast_arp", "unknown_unicast_ipv4", "multicast_ipv4", "multicast_ipv6"} {
			t.Run(fmt.Sprintf("vid-%d/%s", vid, kind), func(t *testing.T) { run(t, 0, vid, kind, false, local, "remote") })
		}
		t.Run(fmt.Sprintf("vid-%d/FDB", vid), func(t *testing.T) { run(t, 0, vid, "unknown_unicast_ipv4", true, local) })
		t.Run(fmt.Sprintf("vid-%d/reverse", vid), func(t *testing.T) { run(t, 4, vid, "broadcast_arp", false, "source", local) })
	}
	t.Run("unknown-VID", func(t *testing.T) { run(t, 0, 30, "broadcast_arp", false) })
	t.Run("untagged", func(t *testing.T) { run(t, 0, 0, "broadcast_arp", false) })
	t.Run("same-VID-other-domain", func(t *testing.T) { run(t, 3, 10, "broadcast_arp", false) })
	t.Run("live-group-subset", func(t *testing.T) {
		var index uint32
		inNamespace(t, nodes[0], func() {
			iface, err := net.InterfaceByName("p1")
			if err != nil {
				t.Fatal(err)
			}
			index = uint32(iface.Index)
		})
		id := xdpID(t, nodes[0], "p0")
		if backend == "tc" {
			removeTCGroupMember(t, tcProgramID(t, nodes[0], "p0"), 100, index)
		} else {
			removeGroupMember(t, ebpf.ProgramID(id), 100, index)
		}
		run(t, 0, 10, "broadcast_arp", false, "remote")
		if xdpID(t, nodes[0], "p0") != id {
			t.Fatal("XDP reattached during group update")
		}
	})
	for i, stop := range stops {
		stop()
		var ports []endpoint
		for _, p := range configs[i].Ports {
			ports = append(ports, endpoint{port: p.Device})
		}
		assertBackend(t, nodes[i], ports, backend, false)
	}
}
