//go:build linux && scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/goxdp-template/pkg/coreelf"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
	"golang.org/x/sys/unix"
)

func TestLocalDelivery(t *testing.T) {
	for _, backend := range []string{"xdp", "tc"} {
		t.Run(backend, func(t *testing.T) {
			for _, mode := range []string{"broadcast", "vxlan", "vxlan-cpu"} {
				t.Run(mode, func(t *testing.T) { runLocalDelivery(t, mode, backend) })
			}
		})
	}
}

func runLocalDelivery(t *testing.T, mode, backend string) {
	if mode == "vxlan-cpu" && !coreelf.CPUMAPEnabled {
		t.Skip("CPUMAP disabled at build time")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	binaryPath, err := filepath.Abs(*goxdpBinary)
	if err != nil {
		t.Fatal(err)
	}
	pass, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "local_peer_pass", Type: ebpf.XDP, License: "MIT",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pass.Close() })
	prefix := fmt.Sprintf("gxlocal-%d-", os.Getpid())
	dut, remote := prefix+"dut", prefix+"remote"
	sender := endpoint{name: "sender", namespace: prefix + "sender", port: "p0", mac: net.HardwareAddr{2, 0, 0, 0, 0, 1}}
	// Match the unknown-unicast destination produced by makeFrame.
	receiver := endpoint{name: "receiver", namespace: prefix + "receiver", port: "p0", mac: net.HardwareAddr{2, 0xff, 0xff, 0xff, 0xff, 1}}
	for _, namespace := range []string{dut, remote, sender.namespace, receiver.namespace} {
		newNamespace(t, namespace)
	}
	connectHost(t, dut, &sender, pass)
	connectHost(t, remote, &receiver, pass)
	command(t, "ip", "-n", dut, "link", "add", "p1", "type", "veth", "peer", "name", "p1", "netns", remote)
	for _, namespace := range []string{dut, remote} {
		command(t, "ip", "-n", namespace, "link", "set", "p1", "mtu", "1600", "up")
	}
	command(t, "ip", "-n", dut, "link", "add", "local_tx", "type", "veth", "peer", "name", "local_rx")
	for _, device := range []string{"local_tx", "local_rx"} {
		command(t, "ip", "-n", dut, "link", "set", device, "up")
	}
	command(t, "ip", "-n", dut, "link", "set", "local_rx", "address", "02:00:00:00:00:09")
	command(t, "ip", "-n", dut, "addr", "add", "192.0.2.99/24", "dev", "local_rx")
	command(t, "ip", "-n", receiver.namespace, "addr", "add", "192.0.2.99/24", "dev", "eth0")
	var localFD, remoteFD int
	inNamespace(t, dut, func() { localFD = udpReceiver(t) })
	inNamespace(t, receiver.namespace, func() { remoteFD = udpReceiver(t) })

	var remoteMAC, dutMAC string
	inNamespace(t, dut, func() { iface, _ := net.InterfaceByName("p1"); dutMAC = iface.HardwareAddr.String() })
	inNamespace(t, remote, func() { iface, _ := net.InterfaceByName("p1"); remoteMAC = iface.HardwareAddr.String() })
	args := make([][]string, 2)
	for i, ports := range [][]string{{"p0", "p1", "local_tx"}, {"p0", "p1"}} {
		if mode == "broadcast" {
			args[i] = []string{"--mode", "broadcast"}
			for _, device := range ports {
				args[i] = append(args[i], "--egress", device)
			}
		} else {
			localIP, peerIP, peerMAC := "198.51.100.1", "198.51.100.2", remoteMAC
			if i == 1 {
				localIP, peerIP, peerMAC = peerIP, localIP, dutMAC
			}
			cfg := coreelf.VXLANConfig{Groups: []coreelf.VXLANGroup{{VNI: 100, Devices: ports,
				UnicastPeers: []coreelf.VXLANPeer{{Device: "p1", RemoteIP: peerIP, RemoteMAC: peerMAC}}}}}
			for _, device := range ports {
				port := coreelf.VXLANPort{Device: device, VNI: 100}
				if device == "p1" {
					port.VNI, port.LocalIP = 0, localIP
				}
				cfg.Ports = append(cfg.Ports, port)
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "vxlan.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			args[i] = []string{"--mode", "vxlan", "--config", path}
			if mode == "vxlan-cpu" {
				args[i] = append(args[i], "--cpu-redirect")
			}
		}
		args[i] = append(args[i], "--backend", backend)
		for _, device := range ports {
			args[i] = append(args[i], "--device", device)
		}
	}
	stopRemote := startForwarder(t, remote, binaryPath, args[1])
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			dutArgs := append([]string(nil), args[0]...)
			if enabled {
				dutArgs = append(dutArgs, "--local-delivery", "local_rx")
			}
			stop := startForwarder(t, dut, binaryPath, dutArgs)
			if got := xdpID(t, dut, "local_rx"); (got != 0) != enabled {
				t.Fatalf("local receiver attachment=%d, enabled=%v", got, enabled)
			}
			checkUDPReplication(t, sender, localFD, remoteFD, enabled)
			assertBackend(t, dut, []endpoint{{port: "p0"}, {port: "p1"}, {port: "local_tx"}}, backend, true)
			assertBackend(t, dut, []endpoint{{port: "local_rx"}}, backend, enabled)
			stop()
			assertBackend(t, dut, []endpoint{{port: "p0"}, {port: "p1"}, {port: "local_tx"}, {port: "local_rx"}}, backend, false)
			for _, device := range []string{"p0", "p1", "local_tx", "local_rx"} {
				if xdpID(t, dut, device) != 0 {
					t.Fatalf("%s remained attached after SIGINT", device)
				}
			}
		})
	}
	stopRemote()
	// A failed ingress attachment must also release the local receiver link.
	inNamespace(t, dut, func() {
		attached, err := xdptool.Attach(pass, "p0")
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
		id := xdpID(t, dut, "p0")
		failedArgs := append([]string{"netns", "exec", dut, binaryPath}, args[0]...)
		failedArgs = append(failedArgs, "--local-delivery", "local_rx")
		if out, err := exec.Command("ip", failedArgs...).CombinedOutput(); err == nil {
			t.Fatalf("expected attachment conflict: %s", out)
		}
		assertBackend(t, dut, []endpoint{{port: "p0"}, {port: "p1"}, {port: "local_tx"}, {port: "local_rx"}}, backend, false)
		if xdpID(t, dut, "local_rx") != 0 || xdpID(t, dut, "p0") != id {
			t.Fatal("failed attachment leaked a receiver or changed the existing program")
		}
	})
}

func udpReceiver(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 40001, Addr: [4]byte{192, 0, 2, 99}}); err != nil {
		t.Fatal(err)
	}
	return fd
}

func checkUDPReplication(t *testing.T, sender endpoint, localFD, remoteFD int, enabled bool) {
	t.Helper()
	const burst = 4
	want := make(map[string]bool)
	for i := 0; i < burst; i++ {
		payload := []byte(fmt.Sprintf("%s/%d", t.Name(), i))
		want[string(payload)] = true
		frame := makeFrame(t, sender.mac, "unknown_unicast_ipv4", payload)
		if err := unix.Sendto(sender.fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: sender.ifindex}); err != nil {
			t.Fatal(err)
		}
	}
	polls := []unix.PollFd{{Fd: int32(localFD), Events: unix.POLLIN}, {Fd: int32(remoteFD), Events: unix.POLLIN}}
	counts := []map[string]int{{}, {}}
	deadline := time.Now().Add(time.Second)
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if _, err := unix.Poll(polls, max(1, int(time.Until(deadline).Milliseconds()))); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			t.Fatal(err)
		}
		for i, poll := range polls {
			if poll.Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				t.Fatalf("UDP receiver %d: poll error %#x", i, poll.Revents)
			}
			for poll.Revents&unix.POLLIN != 0 {
				n, _, err := unix.Recvfrom(int(poll.Fd), buffer, 0)
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(buffer[:n], []byte(t.Name())) || !want[string(buffer[:n])] {
					t.Fatalf("UDP receiver %d: unexpected payload %q", i, buffer[:n])
				}
				counts[i][string(buffer[:n])]++
			}
		}
	}
	for payload := range want {
		localWant := 0
		if enabled {
			localWant = 1
		}
		if counts[0][payload] != localWant || counts[1][payload] != 1 {
			t.Errorf("%q: local=%d (want %d), remote=%d (want 1)", payload, counts[0][payload], localWant, counts[1][payload])
		}
	}
}
