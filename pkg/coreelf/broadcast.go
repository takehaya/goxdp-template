package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

//go:generate go tool bpf2go -target bpf broadcast ../../src/xdp_broadcast.c -- -O2 -g -Wall -Werror

// ReadBroadcastCollection loads the standalone XDP fan-out example and fills
// its devmap before the caller attaches the program to an ingress interface.
// Closing the returned objects releases the program and map.
func ReadBroadcastCollection(ifindices []uint32) (*broadcastObjects, error) {
	spec, err := loadBroadcast()
	if err != nil {
		return nil, fmt.Errorf("load broadcast spec: %w", err)
	}
	if err := validateEgress(ifindices, spec.Maps["tx_ports"].MaxEntries); err != nil {
		return nil, err
	}

	objs := &broadcastObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, fmt.Errorf("load broadcast objects: %w", err)
	}
	for slot, ifindex := range ifindices {
		if err := objs.TxPorts.Update(uint32(slot), ifindex, ebpf.UpdateAny); err != nil {
			objs.Close()
			return nil, fmt.Errorf("set egress ifindex %d: %w", ifindex, err)
		}
	}
	return objs, nil
}

func validateEgress(ifindices []uint32, maxEntries uint32) error {
	if len(ifindices) == 0 || uint64(len(ifindices)) > uint64(maxEntries) {
		return fmt.Errorf("broadcast requires 1 to %d egress interfaces", maxEntries)
	}
	seen := make(map[uint32]bool, len(ifindices))
	for _, ifindex := range ifindices {
		if ifindex == 0 {
			return fmt.Errorf("egress interface index must be positive")
		}
		if seen[ifindex] {
			return fmt.Errorf("duplicate egress ifindex %d", ifindex)
		}
		seen[ifindex] = true
	}
	return nil
}
