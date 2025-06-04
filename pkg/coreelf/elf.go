package coreelf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpf xdp ../../src/xdp_prog.c -- -I./../../include -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wnull-character -g -c -O2 -D__KERNEL__

func ReadCollection(possibleCpu int) (*xdpObjects, error) {
	objs := &xdpObjects{}
	// TODO: BPF log level remove hardcoding. yaml in config?
	spec, err := loadXdp()
	if err != nil {
		return nil, fmt.Errorf("fail to load xdp spec: %w", err)
	}
	consts := map[string]interface{}{
		"cpu_count": uint32(possibleCpu),
	}
	for name, value := range consts {
		varSpec, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("constant %s not found in spec", name)
		}
		if err := varSpec.Set(value); err != nil {
			return nil, fmt.Errorf("fail to set constant %s: %w", name, err)
		}
	}
	err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1073741823, LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("%+v\n", verr)
		}
		return nil, fmt.Errorf("fail to load and assign xdp objects: %w", err)
	}

	if err := setTailCall(objs); err != nil {
		return nil, fmt.Errorf("fail to set tail call: %w", err)
	}

	if err := setCpusMaps(objs, possibleCpu); err != nil {
		return nil, fmt.Errorf("fail to set CPU maps: %w", err)
	}
	return objs, nil
}
