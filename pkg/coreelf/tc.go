package coreelf

import (
	"fmt"
	"net"
)

//go:generate go tool bpf2go -target bpf tcBroadcast ../../src/tc_broadcast.c -- -O2 -g -Wall -Werror
//go:generate go tool bpf2go -target bpf -tags !nocpumap tcVxlan ../../src/tc_vxlan.c -- -O2 -g -Wall -Werror -UNO_CPUMAP
//go:generate go tool bpf2go -target bpf -tags nocpumap -output-stem tcvxlan_direct tcVxlan ../../src/tc_vxlan.c -- -O2 -g -Wall -Werror -DNO_CPUMAP

// ReadTCBroadcastCollection prepares XDP ingress and TC cloning for the same
// Ethernet replication group as ReadBroadcastCollection.
func ReadTCBroadcastCollection(ifindices []uint32) (*tcBroadcastObjects, error) {
	spec, err := loadTcBroadcast()
	if err != nil {
		return nil, fmt.Errorf("load TC broadcast spec: %w", err)
	}
	if err := validateEgress(ifindices, spec.Maps["tx_ports"].MaxEntries); err != nil {
		return nil, err
	}
	for _, index := range ifindices {
		if _, err := net.InterfaceByIndex(int(index)); err != nil {
			return nil, fmt.Errorf("find TC egress ifindex %d: %w", index, err)
		}
	}
	if err := spec.Variables["egress_count"].Set(uint32(len(ifindices))); err != nil {
		return nil, err
	}
	objects := &tcBroadcastObjects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return nil, fmt.Errorf("load TC broadcast objects: %w", err)
	}
	for slot, index := range ifindices {
		if err := objects.TxPorts.Put(uint32(slot), index); err != nil {
			objects.Close()
			return nil, fmt.Errorf("set TC egress %d: %w", index, err)
		}
	}
	return objects, nil
}
