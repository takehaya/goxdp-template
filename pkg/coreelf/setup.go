//go:build !nocpumap

package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// CPUMAPEnabled reports whether this build includes CPU redirects.
const CPUMAPEnabled = true

func (objs *xdpObjects) CPUProgram() *ebpf.Program { return objs.CpuDispatch }

func (objs *vxlanObjects) cpuHandler() (*ebpf.Map, *ebpf.Program) {
	return objs.CpuPrograms, objs.VxlanCpuForward
}

func configureFIBCPUSpec(spec *ebpf.CollectionSpec, possible int, cpus []uint32) ([]uint32, error) {
	if len(cpus) == 0 {
		for cpu := 0; cpu < possible; cpu++ {
			cpus = append(cpus, uint32(cpu))
		}
	}
	if err := validateCPUIds(possible, cpus); err != nil {
		return nil, err
	}
	spec.Maps["cpus_map"].MaxEntries = uint32(possible)
	spec.Maps["cpu_ids"].MaxEntries = uint32(len(cpus))
	count, ok := spec.Variables["cpu_count"]
	if !ok {
		return nil, fmt.Errorf("constant cpu_count not found in spec")
	}
	if err := count.Set(uint32(len(cpus))); err != nil {
		return nil, fmt.Errorf("fail to set constant cpu_count: %w", err)
	}
	return cpus, nil
}

func configureVXLANCPUSpec(spec *ebpf.CollectionSpec, cpus []uint32) error {
	possible, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	if err := validateCPUIds(possible, cpus); err != nil {
		return err
	}
	spec.Maps["cpu_map"].MaxEntries = uint32(possible)
	spec.Maps["cpu_ids"].MaxEntries = uint32(max(1, len(cpus)))
	return spec.Variables["cpu_count"].Set(uint32(len(cpus)))
}

func validateCPUIds(possible int, cpus []uint32) error {
	seen := make(map[uint32]bool)
	for _, cpu := range cpus {
		if cpu >= uint32(possible) || seen[cpu] {
			return fmt.Errorf("invalid or duplicate CPU %d", cpu)
		}
		seen[cpu] = true
	}
	return nil
}

func setFIBCPUMaps(objs *xdpObjects, cpus []uint32) error {
	if err := setTailCall(objs); err != nil {
		return fmt.Errorf("fail to set tail call: %w", err)
	}
	return setCpusMaps(objs, cpus)
}

func setVXLANCPUMaps(objs *vxlanObjects, cpus []uint32) error {
	programs, handler := objs.cpuHandler()
	if err := programs.Update(uint32(0), uint32(handler.FD()), ebpf.UpdateAny); err != nil {
		return err
	}
	for slot, cpu := range cpus {
		value := [2]uint32{2048, uint32(objs.VxlanCpu.FD())}
		if err := objs.CpuMap.Update(cpu, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure CPU %d: %w", cpu, err)
		}
		if err := objs.CpuIds.Update(uint32(slot), cpu, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func setTailCall(objs *xdpObjects) error {
	proglist := []*ebpf.Program{
		objs.XdpCpumapProg,
	}
	for i := 0; i < len(proglist); i++ {
		err := objs.XdpProgArray.Update(
			uint32(i),
			uint32(proglist[i].FD()),
			ebpf.UpdateAny,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func setCpusMaps(objs *xdpObjects, cpus []uint32) error {
	val := xdpBpfCpumapVal{
		Qsize: 128,
	}
	val.BpfProg.Fd = int32(objs.XdpMainJump.FD())
	for slot, cpu := range cpus {
		err := objs.CpusMap.Update(
			uint32(cpu),
			val,
			ebpf.UpdateAny,
		)
		if err != nil {
			return fmt.Errorf("fail to set CPU dispatch: %w", err)
		}
		if err := objs.CpuIds.Update(uint32(slot), cpu, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}
