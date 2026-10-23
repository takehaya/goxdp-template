//go:build linux && scenario

package scenarios

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

var goxdpBinary = flag.String("goxdp-binary", "../../bin/goxdp", "path to the production goxdp binary")

type endpoint struct {
	name      string
	namespace string
	port      string
	mac       net.HardwareAddr
	ifindex   int
	fd        int
}

type capture struct {
	name string
	fd   int
}

// TestBUM runs the production CLI in its own namespace. The three group members
// take turns sending, while the fourth endpoint remains outside the devmap.
func TestBUM(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) { runBUM(t, backend) })
	}
}

func runBUM(t *testing.T, backend string) {
	if os.Geteuid() != 0 {
		t.Fatal("run with make test-scenario (requires root and network namespace support)")
	}
	binaryPath, err := filepath.Abs(*goxdpBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Fatalf("build the production binary with make first: %v", err)
	}
	for _, tool := range []string{"ip", "tc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "scenario_pass",
		Type:         ebpf.XDP,
		License:      "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })

	prefix := fmt.Sprintf("gxbum-%d-", os.Getpid())
	dut := prefix + "dut"
	newNamespace(t, dut)
	var endpoints []endpoint
	var captures []capture
	for i, name := range []string{"leaf-a", "leaf-b", "leaf-c", "outside"} {
		ep := endpoint{
			name:      name,
			namespace: prefix + name,
			port:      fmt.Sprintf("p%d", i),
			mac:       net.HardwareAddr{0x02, 0, 0, 0, 0x02, byte(i + 1)},
		}
		newNamespace(t, ep.namespace)
		command(t, "ip", "-n", dut, "link", "add", ep.port, "type", "veth", "peer", "name", "eth0", "netns", ep.namespace)
		command(t, "ip", "-n", dut, "link", "set", ep.port, "address", fmt.Sprintf("02:00:00:00:01:%02x", i+1), "up")
		command(t, "ip", "-n", ep.namespace, "link", "set", "eth0", "address", ep.mac.String(), "up")
		inNamespace(t, ep.namespace, func() {
			iface, err := net.InterfaceByName("eth0")
			if err != nil {
				t.Fatal(err)
			}
			ep.ifindex = iface.Index
			// veth XDP transmit needs an XDP program on the receiving peer.
			attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: iface.Index, Flags: link.XDPDriverMode})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { attached.Close() })
			ep.fd = packetSocket(t, iface.Index)
		})
		endpoints = append(endpoints, ep)
		captures = append(captures, capture{name: name, fd: ep.fd})
	}
	// These sockets also check that redirected frames do not reach the DUT's
	// local network stack on any ingress port.
	if backend == "xdp" {
		inNamespace(t, dut, func() {
			for _, ep := range endpoints[:3] {
				iface, err := net.InterfaceByName(ep.port)
				if err != nil {
					t.Fatal(err)
				}
				captures = append(captures, capture{name: "dut/" + ep.port, fd: packetSocket(t, iface.Index)})
			}
		})
	}

	args := []string{"--mode", "broadcast", "--backend", backend}
	for _, ep := range endpoints[:3] {
		args = append(args, "--device", ep.port, "--egress", ep.port)
	}
	stop := startForwarder(t, dut, binaryPath, args)
	assertBackend(t, dut, endpoints[:3], backend, true)
	assertBackend(t, dut, endpoints[3:], backend, false)
	for sender, ep := range endpoints[:3] {
		t.Run(ep.name, func(t *testing.T) {
			for _, kind := range []string{"broadcast_arp", "unknown_unicast_ipv4", "multicast_ipv4", "multicast_ipv6"} {
				t.Run(kind, func(t *testing.T) {
					checkFlood(t, ep, sender, kind, captures)
				})
			}
		})
	}
	stop()
	assertBackend(t, dut, endpoints, backend, false)
	for _, ep := range endpoints[:3] {
		if got := xdpID(t, dut, ep.port); got != 0 {
			t.Errorf("%s still has XDP program %d after shutdown", ep.port, got)
		}
	}
}

func checkFlood(t *testing.T, sender endpoint, senderIndex int, kind string, captures []capture) {
	t.Helper()
	const burst = 4
	marker := []byte("goxdp/bum/" + t.Name() + "/")
	frames := make([][]byte, burst)
	for seq := range frames {
		frames[seq] = makeFrame(t, sender.mac, kind, append(bytes.Clone(marker), byte('0'+seq)))
	}
	wants := make([]int, len(captures))
	for i := 0; i < 3; i++ {
		if i != senderIndex {
			wants[i] = 1
		}
	}
	checkFrames(t, sender, frames, marker, captures, wants)
}

func checkFrames(t *testing.T, sender endpoint, frames [][]byte, marker []byte, captures []capture, wants []int) {
	t.Helper()
	for _, frame := range frames {
		if err := unix.Sendto(sender.fd, frame, 0, &unix.SockaddrLinklayer{
			Ifindex:  sender.ifindex,
			Protocol: binary.NativeEndian.Uint16(frame[12:14]),
		}); err != nil {
			t.Fatal(err)
		}
	}

	counts := make([][]int, len(captures))
	polls := make([]unix.PollFd, len(captures))
	for i, c := range captures {
		counts[i] = make([]int, len(frames))
		polls[i] = unix.PollFd{Fd: int32(c.fd), Events: unix.POLLIN}
	}
	// Keep observing after delivery to detect extra copies and any traffic on
	// the ingress, excluded endpoint, or DUT stack.
	deadline := time.Now().Add(time.Second)
	buf := make([]byte, 2048)
	control := make([]byte, unix.CmsgSpace(20))
	for time.Now().Before(deadline) {
		_, err := unix.Poll(polls, max(1, int(time.Until(deadline).Milliseconds())))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range polls {
			if p.Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				t.Fatalf("%s: packet socket error %#x", captures[i].name, p.Revents)
			}
			if p.Revents&unix.POLLIN == 0 {
				continue
			}
			for {
				n, controlSize, _, from, err := unix.Recvmsg(int(p.Fd), buf, control, 0)
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if from.(*unix.SockaddrLinklayer).Pkttype == unix.PACKET_OUTGOING || !bytes.Contains(buf[:n], marker) {
					continue
				}
				received := buf[:n]
				messages, err := unix.ParseSocketControlMessage(control[:controlSize])
				if err != nil {
					t.Fatal(err)
				}
				for _, message := range messages {
					if message.Header.Level == unix.SOL_PACKET && message.Header.Type == unix.PACKET_AUXDATA && len(message.Data) >= 20 {
						status := binary.NativeEndian.Uint32(message.Data)
						if status&unix.TP_STATUS_VLAN_VALID != 0 {
							protocol := uint16(0x8100)
							if status&unix.TP_STATUS_VLAN_TPID_VALID != 0 {
								protocol = binary.NativeEndian.Uint16(message.Data[18:20])
							}
							received = vlanFrame(received, protocol, binary.NativeEndian.Uint16(message.Data[16:18]))
						}
					}
				}
				seq := -1
				for j, frame := range frames {
					if bytes.Equal(received, frame) {
						seq = j
						break
					}
				}
				if seq < 0 {
					t.Fatalf("%s received a modified frame: %x", captures[i].name, received)
				}
				counts[i][seq]++
			}
		}
	}
	for i, c := range captures {
		want := wants[i]
		for seq, count := range counts[i] {
			if count != want {
				t.Errorf("%s packet %d: got %d copies, want %d", c.name, seq, count, want)
			}
		}
		t.Logf("%s received copies per packet: %v", c.name, counts[i])
	}
}

func makeFrame(t *testing.T, src net.HardwareAddr, kind string, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: src}
	var packet []gopacket.SerializableLayer
	if kind == "broadcast_arp" {
		eth.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		eth.EthernetType = layers.EthernetTypeARP
		packet = []gopacket.SerializableLayer{eth, &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   src,
			SourceProtAddress: []byte{192, 0, 2, 1},
			DstHwAddress:      make([]byte, 6),
			DstProtAddress:    []byte{192, 0, 2, 254},
		}}
	} else {
		udp := &layers.UDP{SrcPort: 40000, DstPort: 40001}
		if kind == "multicast_ipv6" {
			eth.DstMAC = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x42}
			eth.EthernetType = layers.EthernetTypeIPv6
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64,
				SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("ff02::42")}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			packet = []gopacket.SerializableLayer{eth, ip, udp}
		} else {
			// This destination is not assigned to any endpoint or DUT port.
			eth.DstMAC = net.HardwareAddr{0x02, 0xff, 0xff, 0xff, 0xff, 0x01}
			eth.EthernetType = layers.EthernetTypeIPv4
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 99}}
			if kind == "multicast_ipv4" {
				eth.DstMAC = net.HardwareAddr{0x01, 0, 0x5e, 0x01, 0x02, 0x03}
				ip.DstIP = net.IP{239, 1, 2, 3}
			}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			packet = []gopacket.SerializableLayer{eth, ip, udp}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	packet = append(packet, gopacket.Payload(payload))
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func command(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	return out
}

func newNamespace(t *testing.T, name string) {
	t.Helper()
	command(t, "ip", "netns", "add", name)
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", name).CombinedOutput(); err != nil {
			t.Errorf("delete namespace %s: %v: %s", name, err, out)
		}
	})
}

// Sockets and BPF links retain their network namespace after the calling thread
// returns to its original namespace, so capture can poll all endpoints at once.
func inNamespace(t *testing.T, name string, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer original.Close()
	target, err := os.Open("/run/netns/" + name)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); err != nil {
			// Keep this thread locked so the runtime discards it on Goexit.
			t.Fatalf("restore original network namespace: %v", err)
		}
		runtime.UnlockOSThread()
	}()
	fn()
}

func packetSocket(t *testing.T, ifindex int) int {
	t.Helper()
	protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifindex, Protocol: protocol}); err != nil {
		t.Fatal(err)
	}
	// Unknown unicast addresses must reach the packet socket as OTHERHOST.
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
		&unix.PacketMreq{Ifindex: int32(ifindex), Type: unix.PACKET_MR_PROMISC}); err != nil {
		t.Fatal(err)
	}
	return fd
}

func startForwarder(t *testing.T, namespace, binaryPath string, args []string) func() {
	t.Helper()
	var devices []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--device" {
			devices = append(devices, args[i+1])
		}
	}
	if len(devices) == 0 {
		t.Fatal("scenario forwarder requires explicit --device flags")
	}
	logPath := filepath.Join(t.TempDir(), "goxdp.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd := exec.Command("ip", append([]string{"netns", "exec", namespace, binaryPath}, args...)...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				out, _ := os.ReadFile(logPath)
				t.Errorf("goxdp exited: %v\n%s", err, out)
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("goxdp did not stop after SIGINT")
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			stopped = true
			out, _ := os.ReadFile(logPath)
			t.Fatalf("goxdp exited before attaching: %v\n%s", err, out)
		default:
		}
		attached := true
		for _, device := range devices {
			attached = attached && xdpID(t, namespace, device) != 0
		}
		if attached {
			return stop
		}
		time.Sleep(20 * time.Millisecond)
	}
	out, _ := os.ReadFile(logPath)
	t.Fatalf("goxdp attachment timed out\n%s", out)
	return nil
}

func xdpID(t *testing.T, namespace, port string) int {
	t.Helper()
	const xdpAttachedDriver = 1 // XDP_ATTACHED_DRV from linux/if_link.h
	var links []struct {
		XDP struct {
			Mode int `json:"mode"`
			Prog struct {
				ID int `json:"id"`
			} `json:"prog"`
		} `json:"xdp"`
	}
	if err := json.Unmarshal(command(t, "ip", "-n", namespace, "-j", "-d", "link", "show", "dev", port), &links); err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("expected one interface for %s/%s", namespace, port)
	}
	if links[0].XDP.Prog.ID != 0 && links[0].XDP.Mode != xdpAttachedDriver {
		t.Fatalf("%s/%s is not using native XDP", namespace, port)
	}
	return links[0].XDP.Prog.ID
}

func assertNoTC(t *testing.T, namespace string, endpoints []endpoint) {
	t.Helper()
	for _, ep := range endpoints {
		for _, direction := range []string{"ingress", "egress"} {
			var filters []json.RawMessage
			out := command(t, "ip", "netns", "exec", namespace, "tc", "-j", "filter", "show", "dev", ep.port, direction)
			if err := json.Unmarshal(out, &filters); err != nil {
				t.Fatal(err)
			}
			if len(filters) != 0 {
				t.Fatalf("unexpected TC filters on %s/%s %s: %s", namespace, ep.port, direction, out)
			}
		}
	}
}

func assertBackend(t *testing.T, namespace string, endpoints []endpoint, backend string, active bool) {
	t.Helper()
	assertNoTC(t, namespace, endpoints)
	inNamespace(t, namespace, func() {
		for _, ep := range endpoints {
			iface, err := net.InterfaceByName(ep.port)
			if err != nil {
				t.Fatal(err)
			}
			for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
				result, err := link.QueryPrograms(link.QueryOptions{Target: iface.Index, Attach: attach})
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if backend == "tc" && active && attach == ebpf.AttachTCXIngress {
					want = 1
				}
				if len(result.Programs) != want {
					t.Fatalf("%s/%s attach %v: got %d TCX programs, want %d", namespace, ep.port, attach, len(result.Programs), want)
				}
			}
		}
	})
}

func tcProgramID(t *testing.T, namespace, device string) ebpf.ProgramID {
	t.Helper()
	var id ebpf.ProgramID
	inNamespace(t, namespace, func() {
		iface, err := net.InterfaceByName(device)
		if err != nil {
			t.Fatal(err)
		}
		result, err := link.QueryPrograms(link.QueryOptions{Target: iface.Index, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Programs) != 1 {
			t.Fatalf("expected one TCX program on %s/%s", namespace, device)
		}
		id = result.Programs[0].ID
	})
	return id
}
