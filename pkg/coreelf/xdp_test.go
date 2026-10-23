//go:build integration

package coreelf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	xdpDrop     = 1
	xdpPass     = 2
	xdpTX       = 3
	xdpRedirect = 4
)

var payload = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func generateInput(t *testing.T, vni uint32) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolUDP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1212,
		SrcIP: net.IP{192, 168, 10, 1}, DstIP: net.IP{192, 168, 10, 5},
	}
	udp := &layers.UDP{SrcPort: 4789, DstPort: 4789}
	udp.SetNetworkLayerForChecksum(iph)
	vxlan := &layers.VXLAN{VNI: vni}
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		iph, udp, vxlan,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x01}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x02}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
		},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func generateOutput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x11}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x12}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
		},
		gopacket.Payload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func byteArrayToUint8Array(arr [6]byte) [6]uint8 {
	var uArr [6]uint8
	copy(uArr[:], arr[:])
	return uArr
}

func TestXDPProg(t *testing.T) {
	t.Parallel()

	objs, err := loadbpfProg(t)
	if err != nil {
		t.Fatalf("load bpf prog: %v", err)
	}
	defer objs.Close()
	setIPv4FibLookupMock(t, objs)

	ret, got, err := objs.XdpProg.Test(generateInput(t, 0x123456))
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_TX
	if ret != xdpTX {
		t.Errorf("got %d want %d", ret, xdpTX)
	}

	// check output
	want := generateOutput(t)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch (-want +got):\n%s", diff)
	}
}

func TestCPUDispatch(t *testing.T) {
	if !CPUMAPEnabled {
		t.Skip("CPUMAP disabled at build time")
	}
	t.Parallel()

	objs, err := loadbpfProg(t)
	if err != nil {
		t.Fatalf("load bpf prog: %v", err)
	}
	defer objs.Close()
	setIPv4FibLookupMock(t, objs)

	vni1, vni2 := uint32(0x123456), uint32(0x123457)
	for _, v := range []uint32{vni1, vni2} {
		addStatsKey(t, objs, v)
	}

	runAndExpect(t, objs, vni1, 1)
	runAndExpect(t, objs, vni1, 2)
	runAndExpect(t, objs, vni2, 1)
	runAndExpect(t, objs, vni2, 2)
	runAndExpect(t, objs, vni1, 3)
}

func TestCPUDispatchSelected(t *testing.T) {
	if !CPUMAPEnabled {
		t.Skip("CPUMAP disabled at build time")
	}
	cpus, err := SelectCPUs(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the actual CPU ID distinct from slot zero whenever possible.
	selected := cpus[len(cpus)-1]
	objs, err := ReadCollection(ebpf.MustPossibleCPU(), selected)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()
	setIPv4FibLookupMock(t, objs)
	const vni = uint32(0x123456)
	addStatsKey(t, objs, vni)
	runAndExpect(t, objs, vni, 1)
	_, _, cores := gotPktStats(t, vni, objs)
	if len(cores) != 1 || cores[0] != selected {
		t.Fatalf("CPU redirect ran on %v, want CPU %d", cores, selected)
	}
}

func TestFIBForwarding(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	name, peer := fmt.Sprintf("ff%da", os.Getpid()), fmt.Sprintf("ff%db", os.Getpid())
	ipCommand(t, "link", "add", name, "type", "veth", "peer", "name", peer)
	t.Cleanup(func() { ipCommand(t, "link", "del", name) })
	for _, dev := range []string{name, peer} {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+dev+"/disable_ipv6", []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
		ipCommand(t, "link", "set", dev, "up")
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "fib_peer_pass", Type: ebpf.XDP, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	iface, err := net.InterfaceByName(peer)
	if err != nil {
		t.Fatal(err)
	}
	attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: iface.Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { attached.Close() })
	device, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	protocol := binary.NativeEndian.Uint16([]byte{8, 0})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: protocol}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
		&unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_PROMISC}); err != nil {
		t.Fatal(err)
	}
	cpus, err := SelectCPUs(nil)
	if err != nil {
		t.Fatal(err)
	}
	var targets []uint32
	if CPUMAPEnabled {
		targets = cpus[len(cpus)-1:]
	}
	objs, err := ReadCollection(ebpf.MustPossibleCPU(), targets...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { objs.Close() })
	setIPv4FibLookupMock(t, objs)
	for _, tt := range []struct {
		name string
		prog *ebpf.Program
	}{{"direct", objs.XdpProg}, {"cpumap", objs.CPUProgram()}} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prog == nil {
				t.Skip("CPUMAP disabled at build time")
			}
			attached, err := link.AttachXDP(link.XDPOptions{Program: tt.prog, Interface: device.Index, Flags: link.XDPDriverMode})
			if err != nil {
				t.Fatal(err)
			}
			defer attached.Close()
			frame := generateInput(t, 100)
			if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: protocol}); err != nil {
				t.Fatal(err)
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := pollPackets(poll, 1000); err != nil || n != 1 {
				t.Fatalf("FIB handler did not transmit a frame: %v", err)
			}
			buf := make([]byte, 2048)
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], generateOutput(t)) {
				t.Fatalf("FIB output differs from expected decapped/rewritten frame: %x", buf[:n])
			}
		})
	}
}

func setIPv4FibLookupMock(t *testing.T, objs *xdpObjects) {
	t.Helper()

	err := UpdateIPv4FibLookUpMockMap(
		objs,
		IPv4FibLookUpMockKey{
			IPv4Src: netip.AddrFrom4([4]byte{192, 168, 100, 200}),
			IPv4Dst: netip.AddrFrom4([4]byte{192, 168, 30, 1}),
			Ifindex: 1,
		},
		&xdpFibLookupMockResult{
			Status: unix.BPF_FIB_LKUP_RET_SUCCESS,
			Params: xdpBpfFibLookupMock{
				Dmac: byteArrayToUint8Array([6]byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x11}),
				Smac: byteArrayToUint8Array([6]byte{0x00, 0x00, 0x5e, 0x00, 0x11, 0x12}),
			},
		},
	)
	if err != nil {
		t.Fatalf("update mock map: %v", err)
	}
}

func addStatsKey(t *testing.T, objs *xdpObjects, vni uint32) {
	t.Helper()
	zero := make([]xdpStatsMapValue, ebpf.MustPossibleCPU())
	if err := objs.StatsMap.Update(vni, zero, ebpf.UpdateAny); err != nil {
		t.Fatalf("stats init vni %d: %v", vni, err)
	}
}

func runAndExpect(t *testing.T, objs *xdpObjects, vni uint32, wantPkts uint64) {
	t.Helper()

	if err := runToBpfTestLiveFrame(t, objs, generateInput(t, vni)); err != nil {
		t.Fatalf("run frame vni %d: %v", vni, err)
	}
	time.Sleep(10 * time.Millisecond)

	gotPkts, _, cores := gotPktStats(t, vni, objs)
	if gotPkts != wantPkts {
		t.Fatalf("vni %d: packets got %d want %d", vni, gotPkts, wantPkts)
	}
	if len(cores) != 1 {
		t.Fatalf("vni %d: expected single core entry, got %d", vni, len(cores))
	}
}

func loadbpfProg(t *testing.T) (*xdpObjects, error) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs, err := ReadCollection(ebpf.MustPossibleCPU())
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("%v\n%+v", err, verr)
		} else {
			t.Fatal(err)
		}
	}
	return objs, nil
}

func runToBpfTestLiveFrame(t *testing.T, objs *xdpObjects, data []byte) error {
	t.Helper()
	runopts := &ebpf.RunOptions{
		Data:   data,
		Repeat: 1,
		Flags:  unix.BPF_F_TEST_XDP_LIVE_FRAMES,
	}
	_, err := objs.CPUProgram().Run(runopts)
	if err != nil {
		return fmt.Errorf("run xdp prog: %w", err)
	}

	return nil
}

func gotPktStats(t *testing.T, vni uint32, objs *xdpObjects) (rxPkts, rxBytes uint64, corenum []uint32) {
	t.Helper()
	possibleCpus := ebpf.MustPossibleCPU()

	gotStats := make([]xdpStatsMapValue, possibleCpus)
	if err := objs.StatsMap.Lookup(vni, &gotStats); err != nil {
		t.Fatal(err)
	}
	gotRxPkts := uint64(0)
	gotRxBytes := uint64(0)
	corenum = make([]uint32, 0, possibleCpus)
	for i := 0; i < possibleCpus; i++ {
		if gotStats[i].RxPackets == 0 && gotStats[i].RxBytes == 0 {
			continue
		}
		corenum = append(corenum, uint32(i))
		gotRxPkts += gotStats[i].RxPackets
		gotRxBytes += gotStats[i].RxBytes
	}
	return gotRxPkts, gotRxBytes, corenum
}

func assertEqual[T comparable](t *testing.T, msg string, want, got T) {
	t.Helper()
	if want != got {
		t.Error(msg, ":", got, "!=", want)
	}
}
