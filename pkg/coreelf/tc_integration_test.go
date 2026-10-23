//go:build integration

package coreelf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type tcTestNetwork struct {
	devices, peers []*net.Interface
	sockets        []int
}

func newTCTestNetwork(t *testing.T, count int) *tcTestNetwork {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tc_peer_pass", Type: ebpf.XDP, License: "MIT", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	n := &tcTestNetwork{}
	for i := 0; i < count; i++ {
		name, peer := fmt.Sprintf("tc%da%d", os.Getpid(), i), fmt.Sprintf("tc%db%d", os.Getpid(), i)
		ipCommand(t, "link", "add", name, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { ipCommand(t, "link", "del", name) })
		for _, device := range []string{name, peer} {
			if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+device+"/disable_ipv6", []byte("1"), 0644); err != nil {
				t.Fatal(err)
			}
			ipCommand(t, "link", "set", device, "mtu", "1600")
			ipCommand(t, "link", "set", device, "up")
		}
		dev, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		other, err := net.InterfaceByName(peer)
		if err != nil {
			t.Fatal(err)
		}
		attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: other.Index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attached.Close() })
		protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(protocol))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
			t.Fatal(err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: other.Index, Protocol: protocol}); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{Ifindex: int32(other.Index), Type: unix.PACKET_MR_PROMISC}); err != nil {
			t.Fatal(err)
		}
		n.devices = append(n.devices, dev)
		n.peers = append(n.peers, other)
		n.sockets = append(n.sockets, fd)
	}
	return n
}

func (n *tcTestNetwork) attach(t *testing.T, xdp, tc *ebpf.Program, ports ...int) {
	t.Helper()
	for _, port := range ports {
		if tc != nil {
			attached, err := link.AttachTCX(link.TCXOptions{Program: tc, Interface: n.devices[port].Index, Attach: ebpf.AttachTCXIngress})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { attached.Close() })
		}
		ingress, err := link.AttachXDP(link.XDPOptions{Program: xdp, Interface: n.devices[port].Index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ingress.Close() })
	}
}

func (n *tcTestNetwork) exchange(t *testing.T, sender int, frame []byte, wants map[int][]byte) {
	t.Helper()
	if err := unix.Sendto(n.sockets[sender], frame, 0, &unix.SockaddrLinklayer{Ifindex: n.peers[sender].Index}); err != nil {
		t.Fatal(err)
	}
	counts := make([]int, len(n.sockets))
	var sourcePort uint16
	polls := make([]unix.PollFd, len(n.sockets))
	for i, fd := range n.sockets {
		polls[i] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_, err := pollPackets(polls, max(1, int(time.Until(deadline).Milliseconds())))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for i, poll := range polls {
			if poll.Revents&unix.POLLIN == 0 {
				continue
			}
			for {
				control := make([]byte, unix.CmsgSpace(20))
				size, controlSize, _, from, err := unix.Recvmsg(int(poll.Fd), buf, control, 0)
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if from.(*unix.SockaddrLinklayer).Pkttype == unix.PACKET_OUTGOING {
					continue
				}
				received := buf[:size]
				messages, err := unix.ParseSocketControlMessage(control[:controlSize])
				if err != nil {
					t.Fatal(err)
				}
				for _, message := range messages {
					if message.Header.Level == unix.SOL_PACKET && message.Header.Type == unix.PACKET_AUXDATA && len(message.Data) >= 20 {
						status := binary.NativeEndian.Uint32(message.Data)
						if status&unix.TP_STATUS_VLAN_VALID != 0 {
							tag := binary.NativeEndian.Uint16(message.Data[16:18])
							protocol := uint16(0x8100)
							if status&unix.TP_STATUS_VLAN_TPID_VALID != 0 {
								protocol = binary.NativeEndian.Uint16(message.Data[18:20])
							}
							received = tcTaggedFrame(received, protocol, tag)
						}
					}
				}
				want := wants[i]
				if len(want) >= 50 && binary.BigEndian.Uint16(want[36:38]) == 4789 && binary.BigEndian.Uint16(want[34:36]) == 0 && len(received) >= 50 {
					// A zero fixture port accepts flow entropy while checking replicas agree.
					port := binary.BigEndian.Uint16(received[34:36])
					if port < 49152 || (sourcePort != 0 && port != sourcePort) {
						t.Errorf("peer %d: unexpected VXLAN source port %d (previous %d)", i, port, sourcePort)
					}
					sourcePort = port
					want = bytes.Clone(want)
					binary.BigEndian.PutUint16(want[34:36], port)
				}
				if !bytes.Equal(received, want) {
					t.Errorf("peer %d: received %x, want %x", i, received, wants[i])
				}
				counts[i]++
			}
		}
	}
	for i, count := range counts {
		want := 0
		if wants[i] != nil {
			want = 1
		}
		if count != want {
			t.Errorf("peer %d received %d copies, want %d", i, count, want)
		}
	}
}

func tcInnerFrame(t *testing.T, kind layers.EthernetType) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: kind}
	var body gopacket.SerializableLayer
	switch kind {
	case layers.EthernetTypeARP:
		body = &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: ethernet.SrcMAC, SourceProtAddress: []byte{192, 0, 2, 10}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 0, 2, 20}}
	case layers.EthernetTypeIPv4:
		body = &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: 253, SrcIP: net.IP{192, 0, 2, 10}, DstIP: net.IP{192, 0, 2, 20}}
	case layers.EthernetTypeIPv6:
		body = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: 253, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	default:
		t.Fatal("unsupported test EtherType")
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, body, gopacket.Payload("TC clone copy-on-write payload")); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tcTaggedFrame(frame []byte, protocol, tag uint16) []byte {
	tagged := make([]byte, len(frame)+4)
	copy(tagged, frame[:12])
	binary.BigEndian.PutUint16(tagged[12:14], protocol)
	binary.BigEndian.PutUint16(tagged[14:16], tag)
	copy(tagged[16:], frame[12:])
	return tagged
}

func tcExpectedOuter(t *testing.T, n *tcTestNetwork, output int, inner []byte) []byte {
	t.Helper()
	frame := vxlanFrame(t, inner)
	copy(frame[:6], n.peers[output].HardwareAddr)
	copy(frame[6:12], n.devices[output].HardwareAddr)
	addresses := [][]byte{{192, 0, 2}, {198, 51, 100}}
	copy(frame[26:29], addresses[output-1])
	frame[29] = 1
	copy(frame[30:33], addresses[output-1])
	frame[33] = 2
	binary.BigEndian.PutUint16(frame[20:22], 0x4000)
	binary.BigEndian.PutUint16(frame[34:36], 0)
	frame[40], frame[41] = 0, 0
	return fixIPv4Checksum(frame)
}

func TestTCVXLANWireCopies(t *testing.T) {
	n := newTCTestNetwork(t, 4)
	names := []string{}
	for _, dev := range n.devices {
		names = append(names, dev.Name)
	}
	cfg := VXLANConfig{
		Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], LocalIP: "192.0.2.1"}, {Device: names[2], LocalIP: "198.51.100.1"}, {Device: names[3], VNI: 100}},
		Groups: []VXLANGroup{{VNI: 100, Devices: names, UnicastPeers: []VXLANPeer{{Device: names[1], RemoteIP: "192.0.2.2", RemoteMAC: n.peers[1].HardwareAddr.String()}, {Device: names[2], RemoteIP: "198.51.100.2", RemoteMAC: n.peers[2].HardwareAddr.String()}}}},
	}
	v, err := ReadTCVXLANCollection(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	n.attach(t, v.Program(), v.TCProgram(), 0, 1, 2, 3)
	for _, kind := range []layers.EthernetType{layers.EthernetTypeARP, layers.EthernetTypeIPv4, layers.EthernetTypeIPv6} {
		t.Run(kind.String(), func(t *testing.T) {
			inner := tcInnerFrame(t, kind)
			n.exchange(t, 0, inner, map[int][]byte{1: tcExpectedOuter(t, n, 1, inner), 2: tcExpectedOuter(t, n, 2, inner), 3: inner})
		})
	}
	for _, protocol := range []uint16{0x8100, 0x88a8} {
		t.Run(fmt.Sprintf("VLAN-%04x", protocol), func(t *testing.T) {
			inner := tcTaggedFrame(tcInnerFrame(t, layers.EthernetTypeIPv4), protocol, 0xb064)
			n.exchange(t, 0, inner, map[int][]byte{1: tcExpectedOuter(t, n, 1, inner), 2: tcExpectedOuter(t, n, 2, inner), 3: inner})
		})
	}
	inner := tcInnerFrame(t, layers.EthernetTypeIPv4)
	for _, invalid := range []int{1, 2} {
		t.Run(fmt.Sprintf("oversized-output-%d", invalid), func(t *testing.T) {
			key := uint32(n.devices[invalid].Index)
			var saved vxlanPortConfig
			if err := v.objects.Ports.Lookup(key, &saved); err != nil {
				t.Fatal(err)
			}
			port := saved
			port.Mtu = 68
			if err := v.objects.Ports.Update(key, port, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			defer v.objects.Ports.Update(key, saved, ebpf.UpdateAny)
			valid := 3 - invalid
			n.exchange(t, 0, inner, map[int][]byte{valid: tcExpectedOuter(t, n, valid, inner), 3: inner})
		})
		t.Run(fmt.Sprintf("missing-peer-%d", invalid), func(t *testing.T) {
			key := vxlanPeerKey{Vni: 100, Ifindex: uint32(n.devices[invalid].Index)}
			var saved vxlanPeerConfig
			if err := v.objects.Peers.Lookup(key, &saved); err != nil {
				t.Fatal(err)
			}
			if err := v.objects.Peers.Delete(key); err != nil {
				t.Fatal(err)
			}
			defer v.objects.Peers.Update(key, saved, ebpf.UpdateAny)
			if err := v.objects.PeerCache.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatal(err)
			}
			valid := 3 - invalid
			n.exchange(t, 0, inner, map[int][]byte{valid: tcExpectedOuter(t, n, valid, inner), 3: inner})
		})
	}
	t.Run("split-horizon", func(t *testing.T) {
		outer := vxlanFrame(t, inner)
		copy(outer[:6], n.devices[1].HardwareAddr)
		copy(outer[30:34], net.IP{192, 0, 2, 1})
		outer[40], outer[41] = 0, 0
		fixIPv4Checksum(outer)
		n.exchange(t, 1, outer, map[int][]byte{0: inner, 3: inner})
	})
	t.Run("known-local-and-removed-member", func(t *testing.T) {
		known := bytes.Clone(inner)
		copy(known[:6], n.peers[3].HardwareAddr)
		key := vxlanFdbKey{Vni: 100}
		copy(key.Mac[:], known[:6])
		if err := v.objects.Fdb.Update(key, uint32(n.devices[3].Index), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		defer v.objects.Fdb.Delete(key)
		n.exchange(t, 0, known, map[int][]byte{3: known})
		if err := v.UpdateMembers(100, names[:3]); err != nil {
			t.Fatal(err)
		}
		defer v.UpdateMembers(100, names)
		n.exchange(t, 0, known, nil)
	})
	t.Run("unrelated-underlay-continues-TCX-chain", func(t *testing.T) {
		count, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer count.Close()
		tail, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "tc_next_count", Type: ebpf.SchedCLS, License: "MIT", Instructions: asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.LoadMapPtr(asm.R1, count.FD()), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "done"), asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord), asm.Mov.Imm(asm.R0, 2).WithSymbol("done"), asm.Return(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer tail.Close()
		attached, err := link.AttachTCX(link.TCXOptions{Program: tail, Interface: n.devices[1].Index, Attach: ebpf.AttachTCXIngress, Anchor: link.Tail()})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		outer := vxlanFrame(t, inner)
		copy(outer[:6], n.devices[1].HardwareAddr)
		binary.BigEndian.PutUint16(outer[36:38], 12345)
		outer[40], outer[41] = 0, 0
		n.exchange(t, 1, outer, nil)
		var got uint64
		if err := count.Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		if got != 1 {
			t.Fatalf("later TCX program saw %d packets, want 1", got)
		}
	})
}

func TestTCBroadcastWireCopies(t *testing.T) {
	n := newTCTestNetwork(t, 3)
	indices := []uint32{}
	for _, dev := range n.devices {
		indices = append(indices, uint32(dev.Index))
	}
	v, err := ReadTCBroadcastCollection(indices)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	n.attach(t, v.XdpBroadcast, v.TcBroadcast, 0)
	for _, kind := range []layers.EthernetType{layers.EthernetTypeARP, layers.EthernetTypeIPv4, layers.EthernetTypeIPv6} {
		t.Run(kind.String(), func(t *testing.T) {
			frame := tcInnerFrame(t, kind)
			n.exchange(t, 0, frame, map[int][]byte{1: frame, 2: frame})
		})
	}
	for _, protocol := range []uint16{0x8100, 0x88a8} {
		t.Run(fmt.Sprintf("VLAN-%04x", protocol), func(t *testing.T) {
			frame := tcTaggedFrame(tcInnerFrame(t, layers.EthernetTypeARP), protocol, 0xb064)
			n.exchange(t, 0, frame, map[int][]byte{1: frame, 2: frame})
		})
	}
	ret, _, err := v.TcBroadcast.Test(tcInnerFrame(t, layers.EthernetTypeIPv4))
	if err != nil || ret != ^uint32(0) {
		t.Fatalf("missing metadata: action %d, error %v; want TCX_NEXT", ret, err)
	}
}

func TestBroadcastEgressMTU(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		for _, undersized := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/output-%d", backend, undersized), func(t *testing.T) {
				n := newTCTestNetwork(t, 3)
				indices := []uint32{uint32(n.devices[0].Index), uint32(n.devices[1].Index), uint32(n.devices[2].Index)}
				if backend == "tc" {
					v, err := ReadTCBroadcastCollection(indices)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { v.Close() })
					n.attach(t, v.XdpBroadcast, v.TcBroadcast, 0)
				} else {
					v, err := ReadBroadcastCollection(indices)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { v.Close() })
					attached, err := link.AttachXDP(link.XDPOptions{Program: v.XdpBroadcast, Interface: n.devices[0].Index, Flags: link.XDPDriverMode})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { attached.Close() })
				}
				ipCommand(t, "link", "set", n.devices[undersized].Name, "mtu", "68")
				for _, size := range []int{86, 87, 128} {
					t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
						frame := tcInnerFrame(t, layers.EthernetTypeIPv4)
						frame = append(frame, make([]byte, size-len(frame))...)
						wants := map[int][]byte{3 - undersized: frame}
						if size == 86 { // devmap allows MTU + Ethernet header + 4 VLAN bytes.
							wants[undersized] = frame
						}
						n.exchange(t, 0, frame, wants)
					})
				}
			})
		}
	}
}

func TestVXLANAccessMTU(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) {
			n := newTCTestNetwork(t, 3)
			names := []string{n.devices[0].Name, n.devices[1].Name, n.devices[2].Name}
			ipCommand(t, "link", "set", names[1], "mtu", "1400")
			cfg := VXLANConfig{
				Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], VNI: 100}, {Device: names[2], VNI: 100}},
				Groups: []VXLANGroup{{VNI: 100, Devices: names, MulticastIP: "239.1.1.100"}},
			}
			load := ReadVXLANCollection
			if backend == "tc" {
				load = ReadTCVXLANCollection
			}
			v, err := load(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			n.attach(t, v.Program(), v.TCProgram(), 0)
			for _, mtu := range []int{1400, 1500} {
				ipCommand(t, "link", "set", names[1], "mtu", fmt.Sprint(mtu))
				for _, protocol := range []uint16{0, 0x8100, 0x88a8} {
					for _, overhead := range []int{14, 18, 19} {
						t.Run(fmt.Sprintf("mtu-%d/proto-%04x/bytes-%d", mtu, protocol, mtu+overhead), func(t *testing.T) {
							frame := tcInnerFrame(t, layers.EthernetTypeIPv4)
							if protocol != 0 {
								frame = tcTaggedFrame(frame, protocol, 10)
							}
							frame = append(frame, make([]byte, mtu+overhead-len(frame))...)
							wants := map[int][]byte{2: frame}
							// Devmap allows MTU + Ethernet header + four VLAN bytes.
							if overhead <= 18 {
								wants[1] = frame
							}
							n.exchange(t, 0, frame, wants)
						})
					}
				}
			}
		})
	}
}

func TestTCVXLANLiveEgressMTU(t *testing.T) {
	for _, undersized := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("output-%d", undersized), func(t *testing.T) {
			n := newTCTestNetwork(t, 4)
			names := []string{n.devices[0].Name, n.devices[1].Name, n.devices[2].Name, n.devices[3].Name}
			cfg := VXLANConfig{
				Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], LocalIP: "192.0.2.1"}, {Device: names[2], LocalIP: "198.51.100.1"}, {Device: names[3], VNI: 100}},
				Groups: []VXLANGroup{{VNI: 100, Devices: names, UnicastPeers: []VXLANPeer{{Device: names[1], RemoteIP: "192.0.2.2", RemoteMAC: n.peers[1].HardwareAddr.String()}, {Device: names[2], RemoteIP: "198.51.100.2", RemoteMAC: n.peers[2].HardwareAddr.String()}}}},
			}
			v, err := ReadTCVXLANCollection(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			n.attach(t, v.Program(), v.TCProgram(), 0)
			ipCommand(t, "link", "set", n.devices[undersized].Name, "mtu", "68")
			inner := tcInnerFrame(t, layers.EthernetTypeIPv4)
			inner = append(inner, make([]byte, 128-len(inner))...)
			wants := map[int][]byte{1: tcExpectedOuter(t, n, 1, inner), 2: tcExpectedOuter(t, n, 2, inner), 3: inner}
			delete(wants, undersized)
			n.exchange(t, 0, inner, wants)
		})
	}
}
