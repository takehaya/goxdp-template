//go:build integration

package coreelf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This test sends a real Ethernet frame through native XDP on veth pairs.
// Program.Test alone would return XDP_REDIRECT without executing the fan-out.
// make test-integration runs it inside an isolated network namespace.
func TestBroadcastFanout(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "test_xdp_pass",
		Type:         ebpf.XDP,
		License:      "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, int32(xdpPass)), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })

	var devices, peers []*net.Interface
	var sockets []int
	var ifindices []uint32
	for i := 0; i < 3; i++ {
		name, peer := fmt.Sprintf("gx%da%d", os.Getpid(), i), fmt.Sprintf("gx%db%d", os.Getpid(), i)
		ipCommand(t, "link", "add", name, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { ipCommand(t, "link", "del", name) })
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
		// veth XDP transmit requires an XDP program on the receiving peer.
		attached, err := link.AttachXDP(link.XDPOptions{Program: pass, Interface: peerDev.Index, Flags: link.XDPDriverMode})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attached.Close() })
		devices = append(devices, dev)
		peers = append(peers, peerDev)
		ifindices = append(ifindices, uint32(dev.Index))
		sockets = append(sockets, packetSocket(t, peerDev.Index))
	}

	// Deliberately include ingress in the devmap to test EXCLUDE_INGRESS.
	objs, err := ReadBroadcastCollection(ifindices)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { objs.Close() })
	attached, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpBroadcast, Interface: devices[0].Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { attached.Close() })

	frame := make([]byte, 64)
	copy(frame[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], peers[0].HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], 0x88b5) // local experimental EtherType
	copy(frame[14:], []byte("XDP devmap broadcast without TC"))
	if err := unix.Sendto(sockets[0], frame, 0, &unix.SockaddrLinklayer{Ifindex: peers[0].Index}); err != nil {
		t.Fatal(err)
	}

	counts := make([]int, len(sockets))
	polls := make([]unix.PollFd, len(sockets))
	for i, fd := range sockets {
		polls[i] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	}
	deadline := time.Now().Add(time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		_, err := pollPackets(polls, max(1, int(time.Until(deadline).Milliseconds())))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range polls {
			if p.Revents&unix.POLLIN == 0 {
				continue
			}
			for {
				n, from, err := unix.Recvfrom(int(p.Fd), buf, 0)
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if from.(*unix.SockaddrLinklayer).Pkttype == unix.PACKET_OUTGOING {
					continue
				}
				if !bytes.Equal(buf[:n], frame) {
					t.Fatalf("peer %d: frame changed: %x", i, buf[:n])
				}
				counts[i]++
			}
		}
	}
	for i, want := range []int{0, 1, 1} {
		if counts[i] != want {
			t.Errorf("peer %d received %d copies, want %d", i, counts[i], want)
		}
	}
}

func ipCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
}

func packetSocket(t *testing.T, ifindex int) int {
	t.Helper()
	protocol := binary.NativeEndian.Uint16([]byte{0x88, 0xb5})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: ifindex, Protocol: protocol}); err != nil {
		t.Fatal(err)
	}
	return fd
}
