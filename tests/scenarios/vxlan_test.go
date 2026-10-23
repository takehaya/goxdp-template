//go:build linux && scenario

package scenarios

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
)

// Three VTEPs use two direct underlay links. No Linux VXLAN device or bridge is
// involved: XDP decapsulates, while the selected backend encapsulates copies.
func TestVXLANBUM(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) {
			for _, redirect := range []bool{false, true} {
				t.Run(fmt.Sprintf("cpu-redirect=%v", redirect), func(t *testing.T) {
					if redirect && !coreelf.CPUMAPEnabled {
						t.Skip("CPUMAP disabled at build time")
					}
					t.Run("multicast-underlay", func(t *testing.T) { runVXLANBUM(t, false, redirect, backend) })
					t.Run("unicast-underlay", func(t *testing.T) { runVXLANBUM(t, true, redirect, backend) })
				})
			}
		})
	}
}

func runVXLANBUM(t *testing.T, unicast, redirect bool, backend string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	binaryPath, err := filepath.Abs(*goxdpBinary)
	if err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vxlan_peer_pass", Type: ebpf.XDP, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	prefix := fmt.Sprintf("gxvx-%d-", os.Getpid())
	var nodes []string
	for _, name := range []string{"a", "b", "c"} {
		ns := prefix + name
		newNamespace(t, ns)
		nodes = append(nodes, ns)
	}
	configs := make([]coreelf.VXLANConfig, 3)
	peers := make([][]coreelf.VXLANPeer, 3)
	var hosts []endpoint
	var captures []capture
	for node, ns := range nodes {
		for tenant, vni := range []uint32{100, 200} {
			host := endpoint{name: fmt.Sprintf("%c-%d", 'a'+node, vni), port: fmt.Sprintf("p%d", tenant),
				mac: net.HardwareAddr{2, 0, 0, 0, byte(node + 1), byte(tenant + 1)}}
			host.namespace = prefix + host.name
			newNamespace(t, host.namespace)
			connectHost(t, ns, &host, pass)
			hosts = append(hosts, host)
			captures = append(captures, capture{name: host.name, fd: host.fd})
			configs[node].Ports = append(configs[node].Ports, coreelf.VXLANPort{Device: host.port, VNI: vni})
		}
	}
	// A second local access port lets one flood contain both local inner
	// frames and remote encapsulated frames, and provides a known-unicast FDB.
	local := endpoint{name: "a-local", namespace: prefix + "a-local", port: "p4", mac: net.HardwareAddr{2, 0, 0, 0, 1, 3}}
	newNamespace(t, local.namespace)
	connectHost(t, nodes[0], &local, pass)
	hosts = append(hosts, local)
	captures = append(captures, capture{name: local.name, fd: local.fd})
	configs[0].Ports = append(configs[0].Ports, coreelf.VXLANPort{Device: "p4", VNI: 100})
	for i, peer := range nodes[1:] {
		port := fmt.Sprintf("p%d", i+2)
		command(t, "ip", "-n", nodes[0], "link", "add", port, "type", "veth", "peer", "name", "p2", "netns", peer)
		command(t, "ip", "-n", nodes[0], "link", "set", port, "mtu", "1600")
		command(t, "ip", "-n", peer, "link", "set", "p2", "mtu", "1600")
		command(t, "ip", "-n", nodes[0], "link", "set", port, "up")
		command(t, "ip", "-n", peer, "link", "set", "p2", "up")
		configs[0].Ports = append(configs[0].Ports, coreelf.VXLANPort{Device: port, LocalIP: fmt.Sprintf("192.0.%d.1", i+2)})
		configs[i+1].Ports = append(configs[i+1].Ports, coreelf.VXLANPort{Device: "p2", LocalIP: fmt.Sprintf("192.0.%d.2", i+2)})
		inNamespace(t, peer, func() {
			iface, err := net.InterfaceByName("p2")
			if err != nil {
				t.Fatal(err)
			}
			peers[0] = append(peers[0], coreelf.VXLANPeer{Device: port, RemoteIP: fmt.Sprintf("192.0.%d.2", i+2), RemoteMAC: iface.HardwareAddr.String()})
		})
		inNamespace(t, nodes[0], func() {
			iface, err := net.InterfaceByName(port)
			if err != nil {
				t.Fatal(err)
			}
			peers[i+1] = append(peers[i+1], coreelf.VXLANPeer{Device: "p2", RemoteIP: fmt.Sprintf("192.0.%d.1", i+2), RemoteMAC: iface.HardwareAddr.String()})
		})
	}
	for i := range configs {
		for _, vni := range []uint32{100, 200} {
			group := coreelf.VXLANGroup{VNI: vni, MulticastIP: fmt.Sprintf("239.1.1.%d", vni)}
			if unicast {
				group.MulticastIP = ""
				group.UnicastPeers = peers[i]
			}
			for _, port := range configs[i].Ports {
				if port.LocalIP != "" || port.VNI == vni {
					group.Devices = append(group.Devices, port.Device)
				}
			}
			configs[i].Groups = append(configs[i].Groups, group)
		}
	}
	configs[0].FDB = []coreelf.VXLANFDBEntry{{VNI: 100, MAC: local.mac.String(), Device: "p4"}}

	var stops []func()
	for i, cfg := range configs {
		// TC-bound ingress is visible to packet sockets before the classifier.
		// Local UDP socket delivery is checked separately for both backends.
		if backend == "xdp" {
			inNamespace(t, nodes[i], func() {
				for _, port := range cfg.Ports {
					iface, err := net.InterfaceByName(port.Device)
					if err != nil {
						t.Fatal(err)
					}
					captures = append(captures, capture{name: fmt.Sprintf("stack-%d-%s", i, port.Device), fd: packetSocket(t, iface.Index)})
				}
			})
		}
		path := filepath.Join(t.TempDir(), "vxlan.json")
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--mode", "vxlan", "--config", path, "--backend", backend}
		if redirect {
			cpus, err := coreelf.SelectCPUs(nil)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--cpu-redirect")
			// Exercise an explicit CPU selection through the production CLI.
			for _, cpu := range cpus[:min(2, len(cpus))] {
				args = append(args, "--cpu", fmt.Sprint(cpu))
			}
		}
		var ports []endpoint
		for _, port := range cfg.Ports {
			args = append(args, "--device", port.Device)
			ports = append(ports, endpoint{port: port.Device})
		}
		stops = append(stops, startForwarder(t, nodes[i], binaryPath, args))
		assertBackend(t, nodes[i], ports, backend, true)
	}

	run := func(t *testing.T, sender endpoint, kind string, destination net.HardwareAddr, size int, receivers ...string) {
		t.Helper()
		marker := []byte("goxdp/vxlan/" + t.Name())
		frame := makeFrame(t, sender.mac, kind, marker)
		if destination != nil {
			copy(frame[:6], destination)
		}
		if size > len(frame) {
			frame = append(frame, make([]byte, size-len(frame))...)
		}
		wants := make([]int, len(captures))
		for i, c := range captures {
			for _, name := range receivers {
				if c.name == name {
					wants[i] = 1
				}
			}
		}
		checkFrames(t, sender, [][]byte{frame}, marker, captures, wants)
	}
	for tenant, vni := range []uint32{100, 200} {
		t.Run(fmt.Sprintf("vni-%d", vni), func(t *testing.T) {
			for _, kind := range []string{"broadcast_arp", "unknown_unicast_ipv4", "multicast_ipv4", "multicast_ipv6"} {
				t.Run(kind, func(t *testing.T) {
					receivers := []string{fmt.Sprintf("b-%d", vni), fmt.Sprintf("c-%d", vni)}
					if vni == 100 {
						receivers = append(receivers, "a-local")
					}
					run(t, hosts[tenant], kind, nil, 0, receivers...)
				})
			}
		})
	}
	t.Run("access-mtu", func(t *testing.T) { run(t, hosts[0], "unknown_unicast_ipv4", nil, 1514, "b-100", "c-100", "a-local") })
	t.Run("known-local-unicast", func(t *testing.T) { run(t, hosts[0], "unknown_unicast_ipv4", local.mac, 0, "a-local") })
	t.Run("split-horizon", func(t *testing.T) { run(t, hosts[2], "broadcast_arp", nil, 0, "a-100", "a-local") })
	t.Run("live-group-update", func(t *testing.T) {
		var index uint32
		inNamespace(t, nodes[0], func() {
			iface, err := net.InterfaceByName("p3")
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
		run(t, hosts[0], "broadcast_arp", nil, 0, "b-100", "a-local")
		if got := xdpID(t, nodes[0], "p0"); got != id {
			t.Fatal("XDP was reattached while updating the group")
		}
	})
	for i, stop := range stops {
		stop()
		var ports []endpoint
		for _, port := range configs[i].Ports {
			ports = append(ports, endpoint{port: port.Device})
		}
		assertBackend(t, nodes[i], ports, backend, false)
		for _, port := range configs[i].Ports {
			if xdpID(t, nodes[i], port.Device) != 0 {
				t.Errorf("%s/%s remained attached after SIGINT", nodes[i], port.Device)
			}
		}
	}
}

func removeTCGroupMember(t *testing.T, programID ebpf.ProgramID, vni, ifindex uint32) {
	t.Helper()
	prog, err := ebpf.NewProgramFromID(programID)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := info.MapIDs()
	if !ok {
		t.Fatal("TC program map IDs unavailable")
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		mapInfo, err := m.Info()
		if err != nil {
			m.Close()
			t.Fatal(err)
		}
		if mapInfo.Name != "tc_groups" {
			m.Close()
			continue
		}
		defer m.Close()
		var group struct {
			Count     uint32
			Ifindices [64]uint32
		}
		if err := m.Lookup(vni, &group); err != nil {
			t.Fatal(err)
		}
		var next struct {
			Count     uint32
			Ifindices [64]uint32
		}
		for _, index := range group.Ifindices[:group.Count] {
			if index != ifindex {
				next.Ifindices[next.Count] = index
				next.Count++
			}
		}
		if err := m.Put(vni, next); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("TC group map not found")
}

func connectHost(t *testing.T, node string, host *endpoint, pass *ebpf.Program) {
	t.Helper()
	command(t, "ip", "-n", node, "link", "add", host.port, "type", "veth", "peer", "name", "eth0", "netns", host.namespace)
	command(t, "ip", "-n", node, "link", "set", host.port, "up")
	command(t, "ip", "-n", host.namespace, "link", "set", "eth0", "address", host.mac.String(), "up")
	inNamespace(t, host.namespace, func() {
		iface, err := net.InterfaceByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		host.ifindex = iface.Index
		attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: iface.Index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attached.Close() })
		host.fd = packetSocket(t, iface.Index)
	})
}

func removeGroupMember(t *testing.T, programID ebpf.ProgramID, vni, ifindex uint32) {
	t.Helper()
	prog, err := ebpf.NewProgramFromID(programID)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := info.MapIDs()
	if !ok {
		t.Fatal("program map IDs are unavailable")
	}
	for _, id := range ids {
		outer, err := ebpf.NewMapFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		if outer.Type() != ebpf.HashOfMaps {
			outer.Close()
			continue
		}
		defer outer.Close()
		var members *ebpf.Map
		if err := outer.Lookup(vni, &members); err != nil {
			t.Fatal(err)
		}
		defer members.Close()
		// Devmap membership itself is mutable from userspace; changing it
		// immediately changes the destinations of subsequent BUM packets.
		if err := members.Delete(ifindex); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("VNI group map not found")
}
