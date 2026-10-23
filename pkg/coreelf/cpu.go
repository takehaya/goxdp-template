package coreelf

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

var ErrCPUMAPDisabled = errors.New("CPUMAP support is disabled in this build; rebuild with CPUMAP=1")

// SelectCPUs defaults to the CPUs available to the current process. Explicit
// selections retain their order, which determines flow-to-CPU assignment.
func SelectCPUs(requested []int) ([]uint32, error) {
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		return nil, fmt.Errorf("read CPU affinity: %w", err)
	}
	var cpus []uint32
	if len(requested) == 0 {
		for cpu := 0; cpu < len(allowed)*64; cpu++ {
			if allowed.IsSet(cpu) {
				cpus = append(cpus, uint32(cpu))
			}
		}
	} else {
		seen := make(map[int]bool)
		for _, cpu := range requested {
			if cpu < 0 || cpu >= len(allowed)*64 || !allowed.IsSet(cpu) || seen[cpu] {
				return nil, fmt.Errorf("CPU %d is unavailable or duplicated", cpu)
			}
			seen[cpu] = true
			cpus = append(cpus, uint32(cpu))
		}
	}
	if len(cpus) == 0 {
		return nil, fmt.Errorf("no CPUs available for redirect")
	}
	return cpus, nil
}
