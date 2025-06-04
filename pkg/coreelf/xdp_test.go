package coreelf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
	"golang.org/x/sys/unix"
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
	if ret != xdptool.XDP_TX {
		t.Errorf("got %d want %d", ret, xdptool.XDP_TX)
	}

	// check output
	want := generateOutput(t)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("output mismatch (-want +got):\n%s", diff)
	}
}

func TestCPUDispatch(t *testing.T) {
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
			Status: xdptool.BPF_FIB_LKUP_RET_SUCCESS,
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
			t.Fatalf("%+v\n", verr)
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
	_, err := objs.CpuDispatch.Run(runopts)
	if err != nil {
		return fmt.Errorf("run xdp prog: %w", err)
	}

	return nil
}

func gotPktStats(t *testing.T, vni uint32, objs *xdpObjects) (rxPkts, rxBytes uint64, corenum []uint8) {
	t.Helper()
	possibleCpus := ebpf.MustPossibleCPU()

	gotStats := make([]xdpStatsMapValue, possibleCpus)
	if err := objs.StatsMap.Lookup(vni, &gotStats); err != nil {
		t.Fatal(err)
	}
	gotRxPkts := uint64(0)
	gotRxBytes := uint64(0)
	corenum = make([]uint8, 0, possibleCpus)
	for i := 0; i < possibleCpus; i++ {
		if gotStats[i].RxPackets == 0 && gotStats[i].RxBytes == 0 {
			continue
		}
		corenum = append(corenum, uint8(i))
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
