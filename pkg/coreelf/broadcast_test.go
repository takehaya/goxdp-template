package coreelf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestBroadcastSpec(t *testing.T) {
	spec, err := loadBroadcast()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 1 || spec.Programs["xdp_broadcast"].Type != ebpf.XDP {
		t.Fatal("broadcast must load independently as one XDP program")
	}
	ports := spec.Maps["tx_ports"]
	if ports.Type != ebpf.DevMap || ports.KeySize != 4 || ports.ValueSize != 4 {
		t.Fatalf("unexpected replication map: %v", ports)
	}
}

func TestValidateEgress(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ifindices []uint32
		max       uint32
		wantErr   bool
	}{
		{"one member", []uint32{2}, 64, false},
		{"full group", []uint32{2, 3}, 2, false},
		{"large interface indices", []uint32{1000, 2000}, 2, false},
		{"empty group", nil, 64, true},
		{"too many members", []uint32{2, 3, 4}, 2, true},
		{"invalid interface", []uint32{0}, 64, true},
		{"duplicate member", []uint32{2, 2}, 64, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateEgress(tt.ifindices, tt.max); (err != nil) != tt.wantErr {
				t.Fatalf("validateEgress() = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}
