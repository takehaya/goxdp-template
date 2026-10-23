package coreelf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

//go:generate go tool bpf2go -target bpf local ../../src/xdp_local.c -- -O2 -g -Wall -Werror
//go:generate go tool bpf2go -target bpf tcLocal ../../src/tc_local.c -- -O2 -g -Wall -Werror

// ReadLocalDeliveryCollection prepares an ingress program for a local veth
// receiver. Register its sending peer as a devmap member separately.
func ReadLocalDeliveryCollection(mac net.HardwareAddr) (*localObjects, error) {
	spec, err := localDeliverySpec(mac, false)
	if err != nil {
		return nil, err
	}
	objects := &localObjects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return nil, err
	}
	return objects, nil
}

// ReadTCLocalDeliveryCollection also repairs the packet type retained by the
// skb-based veth receive path after the local XDP destination-MAC rewrite.
func ReadTCLocalDeliveryCollection(mac net.HardwareAddr) (*tcLocalObjects, error) {
	spec, err := localDeliverySpec(mac, true)
	if err != nil {
		return nil, err
	}
	objects := &tcLocalObjects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return nil, err
	}
	return objects, nil
}

func localDeliverySpec(mac net.HardwareAddr, tc bool) (*ebpf.CollectionSpec, error) {
	if len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return nil, fmt.Errorf("local delivery requires a unicast Ethernet MAC: %s", mac)
	}
	spec, err := loadLocal()
	if tc {
		spec, err = loadTcLocal()
	}
	if err != nil {
		return nil, err
	}
	var address [6]byte
	copy(address[:], mac)
	if err := spec.Variables["local_mac"].Set(address); err != nil {
		return nil, err
	}
	return spec, nil
}
