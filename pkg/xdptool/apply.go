package xdptool

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func LoadElf(filepath string) (*ebpf.Collection, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return nil, err
	}
	return ebpf.NewCollection(spec)
}

// Attach returns an owned link. Close it to detach only this program, including
// when a later attachment fails. Native XDP is required for devmap fan-out.
func Attach(prog *ebpf.Program, device string) (link.Link, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("find device %s: %w", device, err)
	}
	attached, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return nil, fmt.Errorf("attach XDP to %s: %w", device, err)
	}
	return attached, nil
}

// AttachTC returns an owned TCX ingress link without creating or replacing a qdisc.
func AttachTC(prog *ebpf.Program, device string) (link.Link, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("find device %s: %w", device, err)
	}
	attached, err := link.AttachTCX(link.TCXOptions{
		Program: prog, Interface: iface.Index, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		return nil, fmt.Errorf("attach TCX ingress to %s: %w", device, err)
	}
	return attached, nil
}
