//go:build integration

package coreelf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestProductionFIBLoad(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	file := "xdp_bpf.o"
	if !CPUMAPEnabled {
		file = "xdp_direct_bpf.o"
	}
	// Integration bindings use mocked FIB lookup; verify the production ELF too.
	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configureFIBCPUSpec(spec, ebpf.MustPossibleCPU(), nil); err != nil {
		t.Fatal(err)
	}
	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load production FIB: %+v", err)
	}
	t.Cleanup(objects.Close)
	if objects.Maps["fib_lookup_mock_table"] != nil {
		t.Fatal("production FIB loaded a test mock")
	}
}
