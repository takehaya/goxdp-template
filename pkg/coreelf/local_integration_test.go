//go:build integration

package coreelf

import (
	"bytes"
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/takehaya/goxdp-template/pkg/xdptool"
)

func TestLocalDelivery(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 9}
	objects, err := ReadLocalDeliveryCollection(mac)
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	for _, destination := range []net.HardwareAddr{
		{2, 0, 0, 0, 0, 1},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{1, 0, 0x5e, 1, 2, 3},
		{0x33, 0x33, 0, 0, 0, 1},
	} {
		frame := bytes.Repeat([]byte{0x42}, 64)
		copy(frame, destination)
		want := bytes.Clone(frame)
		if destination[0]&1 == 0 {
			copy(want, mac)
		}
		verdict, got, err := objects.LocalReceive.Test(frame)
		if err != nil || verdict != uint32(xdptool.XDP_PASS) || !bytes.Equal(got, want) {
			t.Fatalf("destination %s: verdict=%d frame=%x error=%v", destination, verdict, got, err)
		}
	}
}
