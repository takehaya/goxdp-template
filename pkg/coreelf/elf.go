package coreelf

import "fmt"

//go:generate go tool bpf2go -target bpf -tags !integration,!nocpumap xdp ../../src/xdp_prog.c -- -O2 -g -Wall -Werror -UXDP_TEST -UNO_CPUMAP
//go:generate go tool bpf2go -target bpf -tags !integration,nocpumap -output-stem xdp_direct xdp ../../src/xdp_prog.c -- -O2 -g -Wall -Werror -UXDP_TEST -DNO_CPUMAP

func ReadCollection(possibleCpu int, cpus ...uint32) (*xdpObjects, error) {
	if possibleCpu <= 0 {
		return nil, fmt.Errorf("invalid CPU count: %d", possibleCpu)
	}
	if !CPUMAPEnabled && len(cpus) != 0 {
		return nil, ErrCPUMAPDisabled
	}
	objs := &xdpObjects{}
	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("fail to load xdp spec: %w", err)
	}
	cpus, err = configureFIBCPUSpec(spec, possibleCpu, cpus)
	if err != nil {
		return nil, err
	}
	err = spec.LoadAndAssign(objs, nil)
	if err != nil {
		return nil, fmt.Errorf("fail to load and assign xdp objects: %w", err)
	}

	if err := setFIBCPUMaps(objs, cpus); err != nil {
		objs.Close()
		return nil, fmt.Errorf("fail to set CPU maps: %w", err)
	}
	return objs, nil
}
