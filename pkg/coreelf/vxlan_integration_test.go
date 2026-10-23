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

func TestVXLANIngress(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var names []string
	for i := 0; i < 3; i++ {
		name, peer := fmt.Sprintf("vx%da%d", os.Getpid(), i), fmt.Sprintf("vx%db%d", os.Getpid(), i)
		ipCommand(t, "link", "add", name, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { ipCommand(t, "link", "del", name) })
		ipCommand(t, "link", "set", name, "up")
		ipCommand(t, "link", "set", peer, "up")
		names = append(names, name)
	}
	cfg := VXLANConfig{
		Ports: []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], VNI: 200}, {Device: names[2], LocalIP: "192.0.2.1"}},
		Groups: []VXLANGroup{
			{VNI: 100, MulticastIP: "239.1.1.100", Devices: []string{names[0], names[2]}},
			{VNI: 200, MulticastIP: "239.1.1.200", Devices: []string{names[1], names[2]}},
		},
	}
	v, err := ReadVXLANCollection(cfg)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%v\n%+v", err, verr)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	iface, err := net.InterfaceByName(names[0])
	if err != nil {
		t.Fatal(err)
	}
	ret, err := v.Program().Run(&ebpf.RunOptions{Data: make([]byte, 64),
		Context: &struct{ Data, DataEnd, DataMeta, Ingress, RxQueue, Egress uint32 }{DataEnd: 64, Ingress: uint32(iface.Index)}})
	if err != nil {
		t.Fatal(err)
	}
	if ret != xdpRedirect {
		t.Fatalf("access frame: got %d, want XDP_REDIRECT", ret)
	}
	if err := v.UpdateMembers(100, []string{names[0]}); err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateMembers(100, []string{names[1]}); err == nil {
		t.Fatal("accepted a member of another VNI")
	}
	if err := v.UpdateMembers(100, []string{names[0], names[2]}); err != nil {
		t.Fatal(err)
	}
	tunnel, err := net.InterfaceByName(names[2])
	if err != nil {
		t.Fatal(err)
	}
	inner := generateOutput(t)
	t.Run("shared-header-and-command", func(t *testing.T) {
		type context struct{ Data, DataEnd, DataMeta, Ingress, RxQueue, Egress uint32 }
		var out context
		opts := &ebpf.RunOptions{Data: inner, DataOut: make([]byte, len(inner)+128),
			Context: &context{DataEnd: uint32(len(inner)), Ingress: uint32(iface.Index)}, ContextOut: &out}
		ret, err := v.Program().Run(opts)
		if err != nil || ret != xdpRedirect {
			t.Fatalf("prepare shared header: action %d, error %v", ret, err)
		}
		frame := opts.DataOut[out.Data:out.DataEnd]
		if !bytes.Equal(frame, inner) {
			t.Fatalf("replication must keep data at the inner frame: %x", frame)
		}
		meta := opts.DataOut[out.DataMeta:out.Data]
		if len(meta) != 32 || binary.NativeEndian.Uint64(meta[:8]) != 1 ||
			binary.NativeEndian.Uint64(meta[8:16]) != 0x58445043 ||
			binary.NativeEndian.Uint32(meta[16:20]) != 100 ||
			binary.NativeEndian.Uint32(meta[20:24]) != 2 {
			t.Fatalf("unexpected command ABI: %x", meta)
		}
		innerLen := binary.NativeEndian.Uint32(meta[24:28])
		if innerLen != uint32(len(inner)) {
			t.Fatalf("unexpected inner length in command: %d", innerLen)
		}
		key := uint64(100)<<32 | uint64(innerLen)
		values := make([]vxlanCachedHeader, ebpf.MustPossibleCPU())
		if err := v.objects.HeaderCache.Lookup(key, &values); err != nil {
			t.Fatal(err)
		}
		var header []byte
		for _, value := range values {
			if value.Valid != 0 {
				header = value.Bytes[:]
				break
			}
		}
		if len(header) != 50 {
			t.Fatal("forwarding did not populate its per-CPU header cache")
		}
		if binary.BigEndian.Uint16(header[12:14]) != 0x0800 || header[14] != 0x45 ||
			!bytes.Equal(header[26:34], make([]byte, 8)) ||
			int(binary.BigEndian.Uint16(header[16:18])) != len(inner)+36 ||
			binary.BigEndian.Uint16(header[36:38]) != 4789 ||
			binary.BigEndian.Uint32(header[46:50]) != 100<<8 {
			t.Fatalf("invalid prepared outer header: %x", header)
		}

	})
	valid := vxlanFrame(t, inner)
	for _, tt := range []struct {
		name string
		edit func([]byte) []byte
		want uint32
	}{
		{"multicast decap", func(b []byte) []byte { return b }, xdpRedirect},
		{"outer padding", func(b []byte) []byte { return append(b, make([]byte, 16)...) }, xdpRedirect},
		{"local unicast decap", func(b []byte) []byte { copy(b[30:34], []byte{192, 0, 2, 1}); return fixIPv4Checksum(b) }, xdpRedirect},
		{"bad IPv4 checksum", func(b []byte) []byte { b[24] ^= 1; return b }, xdpDrop},
		{"IPv4 options", func(b []byte) []byte { return addIPv4Options(b, 4) }, xdpRedirect},
		{"maximum IPv4 options", func(b []byte) []byte { return addIPv4Options(b, 40) }, xdpRedirect},
		{"bad options checksum", func(b []byte) []byte { b = addIPv4Options(b, 40); b[73] ^= 1; return b }, xdpDrop},
		{"unknown VNI", func(b []byte) []byte { b[48] = 101; return b }, xdpDrop},
		{"missing I flag", func(b []byte) []byte { b[42] = 0; return b }, xdpDrop},
		{"truncated VXLAN", func(b []byte) []byte { return b[:49] }, xdpDrop},
		{"wrong UDP length", func(b []byte) []byte { binary.BigEndian.PutUint16(b[38:40], 8); return b }, xdpDrop},
		{"wrong IP version", func(b []byte) []byte { b[14] = 0x65; return b }, xdpDrop},
		{"fragmented underlay", func(b []byte) []byte { b[20] = 0x20; return b }, xdpPass},
		{"unrelated UDP", func(b []byte) []byte { binary.BigEndian.PutUint16(b[36:38], 53); return b }, xdpPass},
		{"foreign multicast group", func(b []byte) []byte { b[33] = 201; return b }, xdpPass},
	} {
		t.Run(tt.name, func(t *testing.T) {
			frame := tt.edit(bytes.Clone(valid))
			type context struct{ Data, DataEnd, DataMeta, Ingress, RxQueue, Egress uint32 }
			var out context
			opts := &ebpf.RunOptions{Data: frame, DataOut: make([]byte, len(frame)+128),
				Context: &context{DataEnd: uint32(len(frame)), Ingress: uint32(tunnel.Index)}, ContextOut: &out}
			ret, err := v.Program().Run(opts)
			if err != nil {
				t.Fatal(err)
			}
			if ret != tt.want {
				t.Fatalf("got %d, want %d", ret, tt.want)
			}
			if ret == xdpRedirect && !bytes.Equal(opts.DataOut[out.Data:out.DataEnd], inner) {
				t.Fatalf("decap changed inner frame: %x", opts.DataOut)
			}
			if ret == xdpPass && !bytes.Equal(opts.DataOut[out.Data:out.DataEnd], frame) {
				t.Fatal("unrelated traffic was modified")
			}
		})
	}
}

func fixIPv4Checksum(frame []byte) []byte {
	ip := frame[14 : 14+int(frame[14]&15)*4]
	ip[10], ip[11] = 0, 0
	var sum uint32
	for i := 0; i < len(ip); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	return frame
}

func addIPv4Options(frame []byte, length int) []byte {
	frame = append(append(append([]byte(nil), frame[:34]...), bytes.Repeat([]byte{1}, length)...), frame[34:]...)
	frame[14] += byte(length / 4)
	binary.BigEndian.PutUint16(frame[16:18], uint16(len(frame)-14))
	return fixIPv4Checksum(frame)
}

func vxlanFrame(t *testing.T, inner []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 0, 2, 2}, DstIP: net.IP{239, 1, 1, 100}}
	udp := &layers.UDP{SrcPort: 49152, DstPort: 4789}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{1, 0, 0x5e, 1, 1, 100}, EthernetType: layers.EthernetTypeIPv4},
		ip, udp, &layers.VXLAN{ValidIDFlag: true, VNI: 100}, gopacket.Payload(inner)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVXLANEncap(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("cpu-redirect=%v", redirect), func(t *testing.T) {
			t.Run("multicast", func(t *testing.T) { testVXLANEncap(t, false, redirect) })
			t.Run("unicast-percpu-lru", func(t *testing.T) { testVXLANEncap(t, true, redirect) })
		})
	}
}

func testVXLANEncap(t *testing.T, unicast, redirect bool) {
	if redirect && !CPUMAPEnabled {
		t.Skip("CPUMAP disabled at build time")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vxlan_test_pass", Type: ebpf.XDP, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	var names []string
	var devices, peers []*net.Interface
	var sockets []int
	for i := 0; i < 4; i++ {
		name, peer := fmt.Sprintf("ve%da%d", os.Getpid(), i), fmt.Sprintf("ve%db%d", os.Getpid(), i)
		ipCommand(t, "link", "add", name, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { ipCommand(t, "link", "del", name) })
		// Keep host-generated IPv6 discovery out of raw tunnel captures.
		for _, iface := range []string{name, peer} {
			if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+iface+"/disable_ipv6", []byte("1"), 0644); err != nil {
				t.Fatal(err)
			}
			if i == 1 || i == 2 {
				ipCommand(t, "link", "set", iface, "mtu", "1600")
			}
		}
		ipCommand(t, "link", "set", name, "up")
		ipCommand(t, "link", "set", peer, "up")
		dev, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		peerDev, err := net.InterfaceByName(peer)
		if err != nil {
			t.Fatal(err)
		}
		attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: peerDev.Index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attached.Close() })
		protocol := binary.NativeEndian.Uint16([]byte{0x08, 0x00})
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(protocol))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: peerDev.Index, Protocol: protocol}); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
			&unix.PacketMreq{Ifindex: int32(peerDev.Index), Type: unix.PACKET_MR_PROMISC}); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		devices, peers = append(devices, dev), append(peers, peerDev)
		sockets = append(sockets, fd)
	}
	cfg := VXLANConfig{
		Ports:  []VXLANPort{{Device: names[0], VNI: 100}, {Device: names[1], LocalIP: "192.0.2.1"}, {Device: names[2], LocalIP: "198.51.100.1"}, {Device: names[3], VNI: 100}},
		Groups: []VXLANGroup{{VNI: 100, MulticastIP: "239.1.1.100", Devices: names}},
	}
	destinations := [][]byte{{239, 1, 1, 100}, {239, 1, 1, 100}}
	if unicast {
		cfg.Groups[0].MulticastIP = ""
		destinations = [][]byte{{192, 0, 2, 2}, {198, 51, 100, 2}}
		for i, remote := range destinations {
			cfg.Groups[0].UnicastPeers = append(cfg.Groups[0].UnicastPeers, VXLANPeer{
				Device: names[i+1], RemoteIP: net.IP(remote).String(), RemoteMAC: peers[i+1].HardwareAddr.String(),
			})
		}
	}
	var cpus []uint32
	if redirect {
		available, err := SelectCPUs(nil)
		if err != nil {
			t.Fatal(err)
		}
		// A nonzero CPU also checks that CPU IDs are not treated as slots.
		cpus = available[len(available)-1:]
	}
	v, err := ReadVXLANCollection(cfg, cpus...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	attached, err := link.AttachXDP(link.XDPOptions{Program: v.Program(), Interface: devices[0].Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { attached.Close() })
	inner := generateOutput(t)
	var sent uint64
	sendAndCheck := func(t *testing.T) {
		t.Helper()
		captured := make([][]byte, 2)
		if err := unix.Sendto(sockets[0], inner, 0, &unix.SockaddrLinklayer{Ifindex: peers[0].Index, Protocol: binary.NativeEndian.Uint16([]byte{8, 0})}); err != nil {
			t.Fatal(err)
		}
		sent++
		for i, source := range [][]byte{{192, 0, 2, 1}, {198, 51, 100, 1}} {
			fd := sockets[i+1]
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := pollPackets(poll, 1000); err != nil || n != 1 {
				t.Fatalf("tunnel %d did not receive an encapsulated frame: %v", i, err)
			}
			buf := make([]byte, 2048)
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				t.Fatal(err)
			}
			frame := buf[:n]
			if len(frame) != len(inner)+50 || !bytes.Equal(frame[50:], inner) {
				t.Fatalf("tunnel %d: wrong encapsulated frame: %x", i, frame)
			}
			captured[i] = bytes.Clone(frame)
			wantMAC := net.HardwareAddr{1, 0, 0x5e, 1, 1, 100}
			if unicast {
				wantMAC = peers[i+1].HardwareAddr
			}
			if !bytes.Equal(frame[:6], wantMAC) || !bytes.Equal(frame[6:12], devices[i+1].HardwareAddr) || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
				t.Fatalf("tunnel %d: wrong outer Ethernet header: %x", i, frame[:14])
			}
			if frame[14] != 0x45 || frame[22] != 64 || frame[23] != 17 || !bytes.Equal(frame[26:30], source) || !bytes.Equal(frame[30:34], destinations[i]) || int(binary.BigEndian.Uint16(frame[16:18])) != len(frame)-14 {
				t.Fatalf("tunnel %d: wrong outer IPv4 header: %x", i, frame[14:34])
			}
			var sum uint32
			for offset := 14; offset < 34; offset += 2 {
				sum += uint32(binary.BigEndian.Uint16(frame[offset : offset+2]))
			}
			for sum > 0xffff {
				sum = (sum & 0xffff) + (sum >> 16)
			}
			if sum != 0xffff {
				t.Fatalf("tunnel %d: invalid IPv4 checksum", i)
			}
			if binary.BigEndian.Uint16(frame[34:36]) < 49152 || binary.BigEndian.Uint16(frame[36:38]) != 4789 || int(binary.BigEndian.Uint16(frame[38:40])) != len(frame)-34 || binary.BigEndian.Uint16(frame[40:42]) != 0 || binary.BigEndian.Uint32(frame[42:46]) != 0x08000000 || binary.BigEndian.Uint32(frame[46:50]) != 100<<8 {
				t.Fatalf("tunnel %d: wrong UDP/VXLAN headers: %x", i, frame[34:50])
			}
		}
		if unicast && (bytes.Equal(captured[0][30:34], captured[1][30:34]) || !bytes.Equal(captured[0][50:], captured[1][50:])) {
			t.Fatal("unicast replicas must have different outer destinations and identical inner frames")
		}
		if !bytes.Equal(captured[0][34:36], captured[1][34:36]) {
			t.Fatal("replicas of one flow must use the same outer UDP source port")
		}
		poll := []unix.PollFd{{Fd: int32(sockets[3]), Events: unix.POLLIN}}
		if n, err := pollPackets(poll, 1000); err != nil || n != 1 {
			t.Fatalf("local access did not receive its inner frame: %v", err)
		}
		buf := make([]byte, 2048)
		n, _, err := unix.Recvfrom(sockets[3], buf, 0)
		if err != nil || !bytes.Equal(buf[:n], inner) {
			t.Fatalf("local access: changed inner frame or receive error: %v", err)
		}
		stats := make([]vxlanPipelineCounters, ebpf.MustPossibleCPU())
		if err := v.objects.PipelineStats.Lookup(uint32(0), &stats); err != nil {
			t.Fatal(err)
		}
		var preparations, cpuPackets uint64
		for cpu, value := range stats {
			preparations += value.HeaderPreparations
			cpuPackets += value.CpuPackets
			if redirect && value.CpuPackets != 0 && uint32(cpu) != cpus[0] {
				t.Fatalf("forwarding ran on CPU %d, want CPU %d", cpu, cpus[0])
			}
		}
		if preparations != sent {
			t.Fatalf("prepared %d headers for %d input frames; expected once before replication", preparations, sent)
		}
		if (redirect && cpuPackets != sent) || (!redirect && cpuPackets != 0) {
			t.Fatalf("unexpected CPUMAP packet count: %d (sent %d, redirect %v)", cpuPackets, sent, redirect)
		}
	}
	sendAndCheck(t)
	t.Run("access-mtu", func(t *testing.T) {
		saved := inner
		defer func() { inner = saved }()
		inner = append(bytes.Clone(inner), bytes.Repeat([]byte{0xa5}, 1514-len(inner))...)
		sendAndCheck(t)
	})
	for _, mode := range []string{"missing", "empty-cpu", "wrong-length"} {
		t.Run("header-cache-"+mode, func(t *testing.T) {
			// Invalidate the template after replication, so egress must rebuild it.
			instructions := asm.Instructions{
				asm.Mov.Reg(asm.R6, asm.R1),
				asm.LoadMem(asm.R2, asm.R6, 8, asm.Word), // data_meta
				asm.Mov.Reg(asm.R3, asm.R2),
				asm.Add.Imm(asm.R3, 32),
				asm.LoadMem(asm.R4, asm.R6, 0, asm.Word), // data
				asm.JGT.Reg(asm.R3, asm.R4, "drop"),
				asm.LoadMem(asm.R7, asm.R2, 16, asm.Word), // args.vxlan.vni
				asm.LSh.Imm(asm.R7, 32),
				asm.LoadMem(asm.R8, asm.R2, 24, asm.Word), // args.vxlan.inner_len
				asm.Or.Reg(asm.R7, asm.R8),
				asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord),
			}
			if mode == "wrong-length" {
				instructions = append(instructions,
					asm.LoadMapPtr(asm.R1, v.objects.HeaderCache.FD()),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -8),
					asm.FnMapLookupElem.Call(),
					asm.JEq.Imm(asm.R0, 0, "drop"),
					// cached_header.bytes + Ethernet + IPv4.tot_len
					asm.StoreImm(asm.R0, 2+14+2, 0, asm.Half),
				)
			} else {
				instructions = append(instructions,
					asm.LoadMapPtr(asm.R1, v.objects.HeaderCache.FD()),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -8),
					asm.FnMapDeleteElem.Call(),
				)
			}
			if mode == "empty-cpu" {
				instructions = append(instructions, asm.Mov.Imm(asm.R0, 0))
				for offset := int16(-64); offset < -8; offset += 8 {
					instructions = append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
				}
				instructions = append(instructions,
					asm.LoadMapPtr(asm.R1, v.objects.HeaderCache.FD()),
					asm.Mov.Reg(asm.R2, asm.RFP),
					asm.Add.Imm(asm.R2, -8),
					asm.Mov.Reg(asm.R3, asm.RFP),
					asm.Add.Imm(asm.R3, -64),
					asm.Mov.Imm(asm.R4, 0),
					asm.FnMapUpdateElem.Call(),
					asm.JNE.Imm(asm.R0, 0, "drop"),
				)
			}
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.LoadMapPtr(asm.R2, v.objects.DevmapPrograms.FD()),
				asm.Mov.Imm(asm.R3, 1),
				asm.FnTailCall.Call(),
				asm.Mov.Imm(asm.R0, int32(xdpDrop)).WithSymbol("drop"),
				asm.Return(),
			)
			invalidate, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Name: "invalidate_hdr", Type: ebpf.XDP, AttachType: ebpf.AttachXDPDevMap,
				License: "MIT", Instructions: instructions,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer invalidate.Close()
			var members *ebpf.Map
			if err := v.objects.VniGroups.Lookup(uint32(100), &members); err != nil {
				t.Fatal(err)
			}
			defer members.Close()
			defer func() {
				if err := v.UpdateMembers(100, names); err != nil {
					t.Error(err)
				}
			}()
			for _, dev := range devices[1:3] {
				index := uint32(dev.Index)
				if err := members.Update(index, [2]uint32{index, uint32(invalidate.FD())}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			sendAndCheck(t)
		})
	}
	if unicast {
		revision := uint32(1)
		checkCache := func(t *testing.T) {
			t.Helper()
			for i := 1; i < 3; i++ {
				values := make([]vxlanCachedPeer, ebpf.MustPossibleCPU())
				key := vxlanPeerKey{Vni: 100, Ifindex: uint32(devices[i].Index)}
				if err := v.objects.PeerCache.Lookup(key, &values); err != nil {
					t.Fatal(err)
				}
				expectedIP := binary.NativeEndian.Uint32(destinations[i-1])
				populated := false
				for _, value := range values {
					if value.Revision == revision {
						populated = true
						if value.Peer.RemoteIp != expectedIP {
							t.Fatal("per-CPU cache contains a stale destination")
						}
					}
				}
				if !populated {
					t.Fatal("egress did not fill a per-CPU cache value")
				}
			}
		}
		checkCache(t)
		t.Run("refill-missing-cache", func(t *testing.T) {
			for _, dev := range devices[1:3] {
				if err := v.objects.PeerCache.Delete(vxlanPeerKey{Vni: 100, Ifindex: uint32(dev.Index)}); err != nil {
					t.Fatal(err)
				}
			}
			sendAndCheck(t)
			checkCache(t)
		})
		t.Run("uninitialized-cpu-values", func(t *testing.T) {
			for _, dev := range devices[1:3] {
				// An existing shared key does not mean this CPU has a value.
				zero := make([]vxlanCachedPeer, ebpf.MustPossibleCPU())
				if err := v.objects.PeerCache.Update(vxlanPeerKey{Vni: 100, Ifindex: uint32(dev.Index)}, zero, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
			}
			sendAndCheck(t)
			checkCache(t)
		})
		t.Run("update-peer-invalidates-cache", func(t *testing.T) {
			destinations[0] = []byte{192, 0, 2, 99}
			if err := v.UpdatePeer(100, VXLANPeer{Device: names[1], RemoteIP: "192.0.2.99", RemoteMAC: peers[1].HardwareAddr.String()}); err != nil {
				t.Fatal(err)
			}
			revision++
			sendAndCheck(t)
			checkCache(t)
		})
	}
	assertSuppressed := func(t *testing.T) {
		t.Helper()
		if err := unix.Sendto(sockets[0], inner, 0, &unix.SockaddrLinklayer{Ifindex: peers[0].Index}); err != nil {
			t.Fatal(err)
		}
		poll := []unix.PollFd{{Fd: int32(sockets[1]), Events: unix.POLLIN}, {Fd: int32(sockets[2]), Events: unix.POLLIN}}
		if n, err := pollPackets(poll, 100); err != nil || n != 0 {
			t.Fatalf("missing handler must drop copies: %d events, %v", n, err)
		}
	}
	t.Run("missing-devmap-handler", func(t *testing.T) {
		if err := v.objects.DevmapPrograms.Delete(uint32(1)); err != nil {
			t.Fatal(err)
		}
		defer v.objects.DevmapPrograms.Update(uint32(1), uint32(v.objects.VxlanRewrite.FD()), ebpf.UpdateAny)
		assertSuppressed(t)
	})
	if redirect {
		t.Run("missing-cpu-handler", func(t *testing.T) {
			programs, handler := v.objects.cpuHandler()
			if err := programs.Delete(uint32(0)); err != nil {
				t.Fatal(err)
			}
			defer programs.Update(uint32(0), uint32(handler.FD()), ebpf.UpdateAny)
			assertSuppressed(t)
		})
	}
	// Reducing the configured egress MTU must suppress an oversized VXLAN copy.
	var port vxlanPortConfig
	if err := v.objects.Ports.Lookup(uint32(devices[1].Index), &port); err != nil {
		t.Fatal(err)
	}
	port.Mtu = 68
	if err := v.objects.Ports.Update(uint32(devices[1].Index), port, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(sockets[0], inner, 0, &unix.SockaddrLinklayer{Ifindex: peers[0].Index}); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(sockets[1]), Events: unix.POLLIN}}
	if n, err := pollPackets(poll, int((100 * time.Millisecond).Milliseconds())); err != nil || n != 0 {
		t.Fatalf("oversized packet was not suppressed: n=%d err=%v", n, err)
	}
}
