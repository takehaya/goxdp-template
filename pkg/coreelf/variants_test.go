package coreelf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestBPFVariants(t *testing.T) {
	for _, tt := range []struct {
		file string
		fib  bool
	}{
		{"xdp_bpf.o", true},
		{"xdp_mock_bpf.o", false},
		{"xdp_direct_bpf.o", true},
		{"xdp_mock_direct_bpf.o", false},
	} {
		t.Run(tt.file, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			fib := false
			for _, ins := range spec.Programs["xdp_prog"].Instructions {
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnFibLookup) {
					fib = true
				}
			}
			if fib != tt.fib {
				t.Fatalf("FIB helper present: %v, want %v", fib, tt.fib)
			}
			if mockMap := spec.Maps["fib_lookup_mock_table"] != nil; mockMap == tt.fib {
				t.Fatalf("mock map present: %v, want %v", mockMap, !tt.fib)
			}
		})
	}
}

func assertCPUMAPSpec(t *testing.T, spec *ebpf.CollectionSpec, enabled bool) {
	t.Helper()
	var cpuMap, cpuProgram bool
	for _, m := range spec.Maps {
		cpuMap = cpuMap || m.Type == ebpf.CPUMap
	}
	for _, p := range spec.Programs {
		cpuProgram = cpuProgram || p.AttachType == ebpf.AttachXDPCPUMap
	}
	if cpuMap != enabled || cpuProgram != enabled || (spec.Variables["cpu_count"] != nil) != enabled {
		t.Fatalf("CPU map/program/constant = %v/%v/%v, want %v", cpuMap, cpuProgram, spec.Variables["cpu_count"] != nil, enabled)
	}
	if !enabled {
		for _, name := range []string{"cpu_map", "cpus_map", "cpu_ids", "cpu_programs", "xdp_prog_array", "xdpcap_cpumap_hook"} {
			if spec.Maps[name] != nil {
				t.Fatalf("CPU-only map %s remains", name)
			}
		}
		if spec.Programs["cpu_dispatch"] != nil {
			t.Fatal("CPU ingress dispatcher remains")
		}
	}
}

func TestCPUMAPVariants(t *testing.T) {
	for _, name := range []string{"xdp", "xdp_mock", "vxlan", "tcvxlan"} {
		for _, enabled := range []bool{false, true} {
			stem := name
			if !enabled {
				stem += "_direct"
			}
			t.Run(stem, func(t *testing.T) {
				spec, err := ebpf.LoadCollectionSpec(stem + "_bpf.o")
				if err != nil {
					t.Fatal(err)
				}
				assertCPUMAPSpec(t, spec, enabled)
			})
		}
	}
}

func TestSelectedCPUMAPVariant(t *testing.T) {
	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){"FIB": loadXdp, "VXLAN": loadVxlan, "TC VXLAN": loadTcVxlan} {
		t.Run(name, func(t *testing.T) {
			spec, err := load()
			if err != nil {
				t.Fatal(err)
			}
			assertCPUMAPSpec(t, spec, CPUMAPEnabled)
		})
	}
}

func TestDisabledCPUMAPRequests(t *testing.T) {
	if CPUMAPEnabled {
		t.Skip("requires nocpumap build")
	}
	if _, err := ReadCollection(1, 0); !errors.Is(err, ErrCPUMAPDisabled) {
		t.Fatalf("FIB CPU request: %v", err)
	}
	for _, load := range []func(VXLANConfig, ...uint32) (*VXLAN, error){ReadVXLANCollection, ReadTCVXLANCollection} {
		if _, err := load(VXLANConfig{}, 0); !errors.Is(err, ErrCPUMAPDisabled) {
			t.Fatalf("VXLAN CPU request: %v", err)
		}
	}
}
