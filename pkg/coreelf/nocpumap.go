//go:build nocpumap

package coreelf

import "github.com/cilium/ebpf"

// CPUMAPEnabled reports whether this build includes CPU redirects.
const CPUMAPEnabled = false

func (objs *xdpObjects) CPUProgram() *ebpf.Program { return nil }

func (objs *vxlanObjects) cpuHandler() (*ebpf.Map, *ebpf.Program) { return nil, nil }

// Public loaders reject explicit CPU targets before reaching these no-op paths.
func configureFIBCPUSpec(spec *ebpf.CollectionSpec, possible int, cpus []uint32) ([]uint32, error) {
	return nil, nil
}

func configureVXLANCPUSpec(spec *ebpf.CollectionSpec, cpus []uint32) error { return nil }
func setFIBCPUMaps(objs *xdpObjects, cpus []uint32) error                  { return nil }
func setVXLANCPUMaps(objs *vxlanObjects, cpus []uint32) error              { return nil }
