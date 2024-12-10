package coreelf

import (
	"encoding/binary"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
)

// fiblookup(ipv4) mock implementation
type IPv4FibLookUpMockKey struct {
	IPv4Src netip.Addr
	IPv4Dst netip.Addr
	Ifindex uint32
}

func UpdateIPv4FibLookUpMockMap(objs *xdpObjects, key IPv4FibLookUpMockKey, res *xdpFibLookupMockResult) error {
	wrapkey := xdpBpfFibLookupMock{
		Family:           2, // af_inet
		Ipv4SrcOrIpv6Src: [4]uint32{binary.LittleEndian.Uint32(key.IPv4Src.AsSlice()), 0, 0, 0},
		Ipv4DstOrIpv6Dst: [4]uint32{binary.LittleEndian.Uint32(key.IPv4Dst.AsSlice()), 0, 0, 0},
		Ifindex:          key.Ifindex,
	}
	return updateFibLookUpMockMap(objs, &wrapkey, res)
}

func updateFibLookUpMockMap(objs *xdpObjects, key *xdpBpfFibLookupMock, res *xdpFibLookupMockResult) error {
	possibleCpus, err := xdptool.PossibleCPUs()
	if err != nil {
		return err
	}

	entry := xdptool.CreateEntry(res, possibleCpus)
	return objs.FibLookupMockTable.Update(key, entry, ebpf.UpdateAny)
}
